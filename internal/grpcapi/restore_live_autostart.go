package grpcapi

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// resolveRestoreSpec determines the VMSpec to define a restored VM from,
// in precedence order:
//  1. an operator-supplied spec on the request,
//  2. the spec embedded in the manifest at backup time (vm_spec_json),
//  3. (only with from_existing) the spec of an existing vms record.
//
// If none yields a spec it returns FailedPrecondition — the caller must
// then restore without --auto-start (NBD + overlay only) and define the
// VM by hand. This is the backward-compat path for manifests written
// before metadata capture.
func (s *Server) resolveRestoreSpec(ctx context.Context, req *pb.RestoreLiveRequest, manifest *pbsstore.Manifest) (*pb.VMSpec, error) {
	if req.Spec != nil {
		return req.Spec, nil
	}
	if manifest.VMSpecJSON != "" {
		var spec pb.VMSpec
		if err := json.Unmarshal([]byte(manifest.VMSpecJSON), &spec); err != nil {
			return nil, status.Errorf(codes.Internal, "parse embedded vm spec: %v", err)
		}
		return &spec, nil
	}
	if req.FromExisting {
		if rec, err := corrosion.GetVM(ctx, s.db, req.VmName); err == nil && rec != nil && rec.Spec != "" {
			var spec pb.VMSpec
			if err := json.Unmarshal([]byte(rec.Spec), &spec); err != nil {
				return nil, status.Errorf(codes.Internal, "parse existing vm spec: %v", err)
			}
			return &spec, nil
		}
	}
	return nil, status.Error(codes.FailedPrecondition,
		"manifest has no embedded VM metadata; pass --from-existing to use the VM's existing record (or a spec on the request), or restore without --auto-start")
}

// autoDefineRestoredVM reconstructs and starts a VM from the resolved spec
// with its root disk pointed at the NBD-backed overlay. It returns the name the
// VM was defined under and the root disk's target dev (for blockpull). The
// domain XML never references NBD — the overlay qcow2 carries the nbd:// URI in
// its own header — so the disk survives a later blockpull that makes it
// self-contained.
func (s *Server) autoDefineRestoredVM(
	ctx context.Context,
	req *pb.RestoreLiveRequest,
	repo *pbsstore.Repo,
	manifest *pbsstore.Manifest,
	overlayPath string,
	project string,
	send func(*pb.RestoreLiveProgress) error,
) (string, string, error) {
	if s.virt == nil {
		return "", "", status.Error(codes.FailedPrecondition, "no libvirt backend wired on this daemon")
	}
	spec, err := s.resolveRestoreSpec(ctx, req, manifest)
	if err != nil {
		return "", "", err
	}
	// A caller's spec or a manifest's is untrusted, as a create's is: its
	// stack name and load balancer pass CreateVM's checks, and an LB TLS file
	// outside lb.CertDir needs the admin role, as at CreateVM. Only the
	// --from-existing spec, this cluster's own row, already passed them.
	if req.Spec != nil || manifest.VMSpecJSON != "" {
		if err := validateRestoredLB(ctx, spec); err != nil {
			return "", "", err
		}
	}
	// The spec is a manifest's or a caller's, never a validated create: its
	// disk/NIC tuning is dropped before the gate opens and validated after.
	ioR, rerr := s.restrictRestoredTuning(ctx, spec)
	if rerr != nil {
		return "", "", rerr
	}
	ioG := ioR.grant
	if ioR.stripped {
		_ = send(&pb.RestoreLiveProgress{Status: "the backup's disk/NIC tuning is not applied: " + ioR.why()})
	}
	if len(ioR.invalid) > 0 {
		_ = send(&pb.RestoreLiveProgress{Status: "invalid disk/NIC tuning in the backup's spec is not applied: " + strings.Join(ioR.invalid, "; ")})
	}
	mtuR := s.restrictRestoredNICMTU(ctx, spec)
	if mtuR.stripped {
		_ = send(&pb.RestoreLiveProgress{Status: "the backup's NIC MTUs are not applied: the nic_mtu feature is not open"})
	}
	if len(mtuR.invalid) > 0 {
		_ = send(&pb.RestoreLiveProgress{Status: "invalid NIC MTUs in the backup's spec are not applied: " + strings.Join(mtuR.invalid, "; ")})
	}
	// A limit in the spec — an operator's --spec or one embedded in a backup,
	// possibly from a cluster that has latched — is dropped, never refused,
	// where a create's would be refused (restrictRestoredLimits).
	limDropped := s.restrictRestoredLimits(spec)
	if len(limDropped) > 0 {
		_ = send(&pb.RestoreLiveProgress{Status: "CPU/NIC limits in the spec are not applied: " + strings.Join(limDropped, "; ")})
	}

	originalName := spec.Name
	targetName := req.NewName
	if targetName == "" {
		targetName = originalName
	}
	if targetName == "" {
		targetName = req.VmName
	}
	if !validRestoreName(targetName) {
		return "", "", status.Errorf(codes.InvalidArgument, "invalid restore name %q", targetName)
	}

	// A restore does not claim. It rebuilds the NIC rows straight from the
	// backed-up spec — carrying that spec's addresses verbatim — so restoring
	// onto a NetBox-bound network would boot a guest holding an address the
	// external IPAM either still assigns to the original or never issued at all.
	// Refused before admission, the firmware bundle and DefineDomain, so nothing
	// is reserved and nothing is written.
	if err := s.refuseIfBound(ctx, "restore", specNetworkNames(spec.Network)); err != nil {
		return "", "", err
	}
	// Project isolation: the restored VM lands in the authorized restore project.
	// A caller-supplied --spec names its networks the way a create does, and a
	// spec embedded in the manifest is untrusted backup data (its project field
	// included), so both take create admission — a raw bridge needs root. Only
	// the --from-existing spec, read from this cluster's own vms row, is a copy
	// of a VM in spec.Project and admitted as one. Refused before admission and
	// DefineDomain.
	fromExisting := req.Spec == nil && manifest.VMSpecJSON == ""
	// USB devices and memory hot-add come only from server-side state that
	// passed create's gates: a client --spec and a manifest's embedded spec
	// grant neither (stripped, and said so); the cluster's own row keeps them,
	// re-judged as a create would judge them, on this host.
	passthroughG, err := s.admitRestoredUSBAndHotplug(ctx, spec, targetName, fromExisting)
	if err != nil {
		return "", "", err
	}
	if fromExisting {
		if err := s.admitCopiedNetworks(ctx, "restore", project, spec.Project, specNetworkNames(spec.Network)); err != nil {
			return "", "", err
		}
	} else {
		for _, name := range specNetworkNames(spec.Network) {
			if err := s.admitNetworkAttach(ctx, project, name); err != nil {
				return "", "", err
			}
		}
	}
	if err := s.admitSecurityGroupRefs(ctx, project, nicSecurityGroupNames(spec.Network)); err != nil {
		return "", "", status.Errorf(status.Code(err), "restore: %s", status.Convert(err).Message())
	}
	// This path creates a RUNNING managed VM, so beyond backup.restore the caller
	// must hold vm.create on the target name in the (authorized) restore project.
	if err := s.RequirePerm(ctx, vmRBACPathFor(project, targetName), "vm.create", "operator"); err != nil {
		return "", "", err
	}

	// No create of the name runs on this host while this restore does
	// (beginCreate): they would share the name's domain and paths.
	endFlight, setFlightUUID, ferr := s.beginCreate(targetName)
	if ferr != nil {
		return "", "", ferr
	}
	defer endFlight()
	// Collision guard: never clobber a live VM. The operator passes
	// --name to restore alongside the original.
	if rec, _ := corrosion.GetVM(ctx, s.db, targetName); rec != nil {
		return "", "", status.Errorf(codes.AlreadyExists,
			"vm %q already exists; pass --name to restore alongside it", targetName)
	}
	if s.virt.DomainExists(targetName) {
		return "", "", status.Errorf(codes.AlreadyExists,
			"domain %q already defined; pass --name to restore alongside it", targetName)
	}
	// The restore writes the target name's firmware state and defines its
	// domain: not a name a live firmware move's record holds (spec §6.9).
	if err := s.firmwareMoveNameRefusal("restore", targetName); err != nil {
		return "", "", err
	}

	// Capacity + quota admission. A live-restore reconstructs a full-sized VM from
	// a manifest and BOOTS it, so it consumes exactly what CreateVM of the same
	// spec would — and nothing admitted it. Backup data is the one input an
	// operator can replay at will, which made this the cheapest way to overfill a
	// host or walk a project past its quota while every other create path refused
	// correctly.
	//
	// FULL admission (quota included, unlike a migrate or a start): this is a NEW
	// allocation the project does not yet carry — the row written below is a VM
	// that did not exist a moment ago, even when it restores alongside a still-
	// running original. resourceID names it so a DELEGATED quota holder can tell
	// the admission it granted has landed, instead of guessing from a clock.
	//
	// Placed after the name-collision guard and before materializeFirmwareBundle /
	// DefineDomain, so a refusal costs no disk I/O and defines nothing. The lease
	// is released when this function returns — i.e. after InsertVMWithHardware
	// below, so the provisional reservation is only dropped once the VM's own row
	// accounts for the same capacity.
	lease, aerr := s.admitWithReservation(
		ctx, "RestoreLive", s.hostName, project, "vm:"+targetName,
		int(spec.Cpu), int(spec.MemoryMib), vmSpecQuotaAmount(spec), intentVMResident)
	if aerr != nil {
		return "", "", aerr
	}
	defer lease.release(ctx)

	renamed := targetName != originalName
	if !renamed {
		// The backup's MACs come back as they were; one another NIC took
		// since would put two NICs on one MAC.
		var specMACs []string
		for _, n := range spec.Network {
			specMACs = append(specMACs, n.Mac)
		}
		mac, holder, herr := s.macHolderOtherThan(ctx, specMACs, targetName)
		if herr != nil {
			return "", "", herr
		}
		if holder != "" {
			return "", "", status.Errorf(codes.AlreadyExists,
				"MAC %s of the backup's NIC is now used by %s; restore under another name (`lv backup restore-live --name`), which gives the NICs new MACs", mac, holder)
		}
	}
	spec.Name = targetName
	// Force the restored VM into the authorized restore project — never let it
	// fall through to the default project (InsertVM's "" → _default).
	spec.Project = project

	// PCI passthrough, as CreateVM attaches it: resolved against this host's
	// inventory, owned and vfio-bound under a durable device lease, rendered
	// as hostdevs, and recorded as the VM's intents. A device this host
	// cannot provide refuses the restore, as it would refuse a start; the VM
	// is never started silently without it. --without-devices (operator
	// opt-in) drops them from the spec first, so the row agrees with the
	// domain, and says so. Allocated before the MAC, guard and firmware work,
	// so a refusal leaves none of it behind.
	var devicesDropped string
	if req.WithoutDevices && len(spec.Devices) > 0 {
		devicesDropped = deviceSpecsSummary(spec.Devices)
		spec.Devices = nil
		_ = send(&pb.RestoreLiveProgress{Status: "PCI passthrough devices not attached (--without-devices): " + devicesDropped})
	}
	var pciIntents []corrosion.PCIIntentRecord
	var pciAddrs []string
	// pciHeld: the domain may be running with the devices, so they are not
	// given back. Until it starts, and again once it is provably destroyed, a
	// failed restore releases them at once (owner-scoped, so never another
	// VM's): a device left owned by a VM with no row is free again only at the
	// stranded-ownership sweep.
	pciHeld, pciKept := false, false
	if len(spec.Devices) > 0 {
		addrs, devFinish, devErr := s.allocateDevices(ctx, targetName, spec.Devices, deviceLeaseStageBound)
		if devErr != nil {
			return "", "", status.Errorf(status.Code(devErr),
				"restore %q: the backed-up VM's PCI passthrough devices cannot be attached on host %s: %s (pass --without-devices to start it without them)",
				targetName, s.hostName, status.Convert(devErr).Message())
		}
		pciAddrs = addrs
		defer devFinish()
		defer func() {
			if !pciHeld && !pciKept {
				s.releaseAllocatedDevices(ctx, "restore", targetName, pciAddrs)
			}
		}()
		pciIntents = s.buildPCIIntents(targetName, spec.Devices)
	}

	// Firmware-state travel (G1): a Secure-Boot/vTPM VM's NVRAM + swtpm bind
	// BitLocker. Re-home them onto this host under a FRESH identity (so a
	// restore-alongside can't collide with the still-running original's
	// UUID-keyed swtpm dir) BEFORE defining the domain. Refuse if the host lacks
	// the capability or the backup captured no firmware — booting a fresh-TPM VM
	// would silently brick BitLocker.
	fwVM := spec.SecureBoot || spec.Tpm
	// A restore beside the original under a new name is a second VM, so it
	// gets its own identity, as a clone does (a firmware VM always does,
	// below); so does a spec that names none. A restore to the original's own
	// name keeps it only when the spec is the backup's own or this cluster's
	// row and no live VM holds the uuid: a caller's --spec gets a fresh one,
	// as a create does, so no two live VMs share one.
	if !fwVM && (targetName != originalName || spec.Uuid == "" || req.Spec != nil || s.liveVMHoldsUUID(ctx, spec.Uuid)) {
		spec.Uuid = uuid.NewString()
	}
	// restoreOK gates the deferred firmware rollback below: a firmware VM that
	// fails ANY step after materialization (bridge/XML/define/start/persist) must
	// not strand name-keyed NVRAM + UUID-keyed swtpm that lifecycle code can't
	// reconcile, so we tear it all down unless the restore fully succeeds (G1).
	restoreOK := false
	if fwVM {
		if spec.SecureBoot && !s.firmware.SecureBootAvailable() {
			return "", "", status.Errorf(codes.FailedPrecondition,
				"host %s has no Secure Boot firmware; cannot restore VM %q here", s.hostName, targetName)
		}
		if spec.Tpm {
			if err := s.checkTPMHostSupport(); err != nil {
				return "", "", err
			}
		}
		if len(spec.Disks) > 1 {
			return "", "", status.Errorf(codes.Unimplemented,
				"VM %q is a multi-disk Secure Boot / vTPM VM; only its root disk + firmware are restored, which would boot it missing its data disks — not supported yet", targetName)
		}
		if len(manifest.FirmwareChunks) == 0 {
			return "", "", status.Errorf(codes.FailedPrecondition,
				"backup of Secure Boot / vTPM VM %q captured no firmware state; cannot restore it consistently (re-take the backup on a firmware-aware build)", req.VmName)
		}
		spec.Uuid = uuid.NewString()
		if err := s.materializeFirmwareBundle(repo, manifest, targetName, spec.Uuid); err != nil {
			return "", "", err
		}
		defer func() {
			if restoreOK {
				return
			}
			// Failed partway after materialization: destroy/undefine any domain we
			// defined and wipe the materialized firmware so a retry re-materializes
			// cleanly (and lifecycle never sees orphaned state).
			s.virt.DestroyDomain(targetName)
			_ = s.virt.UndefineDomain(targetName, false)
			s.fw().WipeFirmwareState(targetName, spec.Uuid)
		}()
	}

	// Root disk → the overlay. Rebuild bus/controller from the stored spec (not
	// hardcoded virtio) so an imported scsi/sata guest — e.g. Windows — boots
	// after restore instead of stalling on a missing controller (G1). Multi-disk
	// auto-restore is out of scope: only the root disk is NBD-backed.
	rootBus, rootCtrl := "virtio", ""
	for _, ds := range spec.Disks {
		if ds.Name == "root" {
			if ds.Bus != "" {
				rootBus = ds.Bus
			}
			rootCtrl = ds.ControllerModel
			break
		}
	}
	rootDev := lv.DiskDevName(rootBus, 0)
	diskCfg := []lv.DiskConfig{{Name: "root", Path: overlayPath, Bus: rootBus, ControllerModel: rootCtrl}}
	diskRecords := []corrosion.DiskRecord{{
		VMName: targetName, DiskName: "root", HostName: s.hostName,
		Path: overlayPath, SizeBytes: manifest.TotalSize, StorageType: "local",
		TargetDev: rootDev, Bus: rootBus,
	}}

	// Networks from the spec. On a rename we regenerate MACs so the
	// restored VM can't collide on L2 with the still-running original.
	var netCfg []lv.NetworkConfig
	var ifaceRecords []corrosion.InterfaceRecord
	var nicRecords []corrosion.NICRecord // v42 dual-write alongside ifaceRecords (vm_nics)
	macs := s.newMACAllocator()
	for _, n := range spec.Network {
		if !renamed {
			macs.reserve(n.Mac)
		}
	}
	for i, n := range spec.Network {
		mac := n.Mac
		if renamed || mac == "" {
			var merr error
			if mac, merr = macs.next(ctx); merr != nil {
				return "", "", merr
			}
		}
		// The spec records the NIC's real MAC (as a clone does), so its queues
		// are matched at every later redefine, not lost to the source's MAC.
		n.Mac = mac
		bridge := network.FlatBridgeName(n.Name)
		if err := s.ensureBridge(bridge); err != nil {
			return "", "", status.Errorf(codes.FailedPrecondition,
				"network bridge %q not available on host %s: %v", bridge, s.hostName, err)
		}
		netCfg = append(netCfg, lv.NetworkConfig{Bridge: bridge, Model: n.Model, MAC: mac, RateMBps: n.RateMbSec})
		// The groups go on the legacy row as well as the vm_nics one: a peer on
		// an older build renders this NIC's chain from vm_interfaces alone.
		ifaceRecords = append(ifaceRecords, corrosion.InterfaceRecord{
			VMName: targetName, NetworkName: n.Name, Ordinal: i, MAC: mac, IP: n.Ip,
			SecurityGroups: n.SecurityGroups,
		})
		nicRecords = append(nicRecords, corrosion.NICRecord{
			VMName:         targetName,
			ID:             corrosion.DeterministicNICID(targetName, mac),
			NetworkName:    n.Name,
			Model:          n.Model,
			MAC:            mac,
			Ordinal:        i,
			IP:             n.Ip,
			TapDevice:      "",
			SecurityGroups: encodeSecurityGroups(n.SecurityGroups),
		})
	}

	// Restored under a new name, the VM is a second VM with fresh MACs: its
	// NICs are new and guarded by default, as a clone's are (copyNICGuards).
	var guardRecords []corrosion.NICGuardRecord
	if renamed {
		guardRecords = copyNICGuards(targetName, spec.Uuid, ifaceRecords, func(n string) string { return guardUnenforcedOnNetwork(ctx, s.db, n) })
		if err := s.writeNewNICGuards(ctx, guardRecords); err != nil {
			return "", "", err
		}
	}

	vmCfg := lv.VMConfig{
		Name:        targetName,
		CPU:         int(spec.Cpu),
		CPUMode:     spec.CpuMode,
		CPUModel:    spec.CpuModel,
		MemoryMiB:   int(spec.MemoryMib),
		Machine:     spec.Machine,
		Firmware:    spec.Firmware,
		GuestAgent:  spec.GuestAgent,
		EnableVNC:   !spec.DisableVnc,
		EnableSPICE: spec.EnableSpice,
		Disks:       diskCfg,
		Networks:    netCfg,
		Boot:        spec.Boot,
		// A seed this host holds for the restored VM, as CreateVM attaches it.
		CloudInitISO: s.stampedSeedFor(targetName, spec.Uuid),
		// Memory hot-add, only as admitted above (admitRestoredUSBAndHotplug).
		HotplugBaseMiB: int(spec.MemoryHotplugBaseMib),
		HotplugMaxMiB:  int(spec.MemoryHotplugMaxMib),
		CPULimit:       spec.CpuLimit,
		CPUShares:      int(spec.CpuShares),
	}
	compose.ApplyDiskTuning(vmCfg.Disks, spec)
	compose.ApplyNICTuningByPosition(vmCfg.Networks, spec)
	// Firmware fields (G1): point the domain at the just-materialized NVRAM
	// (name-keyed) + the fresh UUID whose swtpm dir we re-homed the state into.
	if fwVM {
		s.firmware.ApplyTo(&vmCfg, s.dataDir, targetName, spec.SecureBoot, spec.Tpm)
	}
	// The domain carries the VM's identity, firmware or not, as every definer
	// does (a later rebuild knows it for the VM's own by it).
	vmCfg.UUID = spec.Uuid
	for _, addr := range pciAddrs {
		vmCfg.Hostdevs = append(vmCfg.Hostdevs, lv.HostdevConfig{Address: addr})
	}
	s.withNICMTU(&vmCfg)
	domXML, err := lv.GenerateDomainXML(vmCfg)
	if err != nil {
		return "", "", renderStatus("generate domain XML", err)
	}

	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_DEFINING, VmName: targetName,
		TargetPath: overlayPath, Status: "defining domain against overlay",
	})
	// The release gate for the limits this restore carries, immediately before
	// the domain that holds them is defined.
	limitsG, err := s.recordLimitedSpec(ctx, spec)
	if err != nil {
		// A refusing gate drops the limits, not the restore: the domain is
		// generated again without them.
		why := "the vm_limits gate refused: " + status.Convert(err).Message()
		for _, k := range stripLimits(spec) {
			d := k + " (" + why + ")"
			slog.Warn("restored spec: CPU/NIC limit dropped", "vm", targetName, "dropped", d)
			limDropped = append(limDropped, d)
		}
		vmCfg.CPULimit, vmCfg.CPUShares = 0, 0
		for i := range vmCfg.Networks {
			vmCfg.Networks[i].RateMBps = 0
		}
		if domXML, err = lv.GenerateDomainXML(vmCfg); err != nil {
			return "", "", renderStatus("generate domain XML", err)
		}
		limitsG = capabilities.FeatureGrant{}
	}
	s.forgetMoveRecords(ctx, targetName) // the restored domain takes the name
	setFlightUUID(spec.Uuid)
	if err := s.setAsideStaleLibvirtVars(targetName); err != nil {
		return "", "", status.Errorf(codes.Internal, "%v", err)
	}
	if err := s.virt.DefineDomain(domXML); err != nil {
		return "", "", status.Errorf(codes.Internal, "define domain: %v", err)
	}

	// hardware_v2 pre-start (adoption gate + PCI preflight); no-op unless latched, so a
	// fleet with the feature off restores exactly as before. A restore always targets a
	// fresh name (name-collision is refused earlier), and its PCI intents are written
	// with its row after the start (its devices were allocated above, as CreateVM's are),
	// so the preflight finds none and only the adoption gate can fire (refusing an
	// auto-start into a name the operator has flagged blocked). release() runs only if the
	// subsequent StartDomain fails.
	hwSpecJSON, _ := json.Marshal(spec)
	hwRec := &corrosion.VMRecord{
		Name: targetName, HostName: s.hostName, Spec: string(hwSpecJSON),
		CPUActual: int(spec.Cpu), MemActual: int(spec.MemoryMib), Project: project,
	}
	releaseHW, hwErr := s.PrepareHardwareForStart(ctx, hwRec)
	if hwErr != nil {
		_ = s.virt.UndefineDomain(targetName, false)
		return "", "", hwErr
	}
	// Spare root ports last, as in the reconciler's start: a device the
	// pre-start patches in would otherwise land on a spare.
	s.ensureSparePCIeRootPorts(targetName)
	if len(guardRecords) > 0 {
		// The row is written once the domain runs; until then the firewall
		// renders its NICs from here (nic_firewall_arming.go).
		defer s.pendingNICs(targetName, spec.Uuid, ifaceRecords, nil)()
	}
	// Its NICs' VLANs go on its taps before it runs (NICStartGuard), read from
	// here until its row is written.
	defer s.pendingTapVLANsFor(ctx, targetName, spec, ifaceRecords)()
	if err := s.virt.StartDomain(targetName); err != nil {
		releaseHW()
		// Roll back the definition but KEEP the overlay + NBD so the operator can
		// retry define/start against the still-valid source. For a firmware VM the
		// deferred rollback additionally wipes the materialized NVRAM/swtpm.
		_ = s.virt.UndefineDomain(targetName, false)
		return "", "", status.Errorf(codes.Internal, "start domain: %v", err)
	}
	pciHeld = true
	// STARTED is sent further down, once the row is committed and published: a
	// client acts on it, and the fence below can still tear this domain down.

	// FENCE, immediately before the durable write (see allowCommit). Firmware
	// materialisation, define, hardware prepare, and the start off the overlay
	// all sit between admission and here, so the project's quota authority can
	// move mid-restore. The VM is already running, so a refusal must tear it
	// down like a start failure would — a running domain with no cluster row is
	// strictly worse than the retry this costs. The overlay + NBD are kept, as
	// on a start failure, so a retry restores against the still-valid source;
	// for a firmware VM the deferred rollback (restoreOK=false) also wipes the
	// materialized NVRAM/swtpm.
	s.fireCommitFenceHook("RestoreLive")
	if ferr := lease.allowCommit(ctx); ferr != nil {
		if derr := s.virt.DestroyDomain(targetName); derr != nil {
			slog.Error("live-restore: fence refused the commit but the running domain could not be destroyed — manual cleanup needed",
				"vm", targetName, "error", derr)
		} else {
			pciHeld = false // destroyed: its devices go back
		}
		releaseHW()
		_ = s.virt.UndefineDomain(targetName, false)
		return "", "", ferr
	}

	// Persist the VM so lifecycle / migration / UI treat it like any
	// other. Best-effort: the VM is already running.
	//
	// The define above resolved any machine alias against this host's qemu.
	// Persist that concrete value, or a VM restored from a backup taken on a
	// different qemu carries an alias whose meaning changes the next time it
	// moves — the same guest-ABI hazard create/import/promote/clone pin against.
	s.pinMachineFromDomain(spec)
	specJSON, _ := json.Marshal(spec)
	// Inserted "creating": assignOwnerEpochAtCreate publishes it running only
	// once it holds a positive epoch and a marker names it.
	vmRecord := corrosion.VMRecord{
		Name: targetName, HostName: s.hostName, Spec: string(specJSON),
		State: "creating", CPUActual: int(spec.Cpu), MemActual: int(spec.MemoryMib),
		Project: project,
	}
	// PCI intents: exactly the devices allocated above and rendered as the
	// domain's hostdevs, so every reservation names a device the VM holds.
	// adopt=false: best-effort-populate vm_nics, but don't self-certify adoption —
	// the backfill audit confirms/reconciles.
	gs := vmSpecGrants{tuning: ioG, passthrough: passthroughG, limits: limitsG, mtu: mtuR.grant}
	// The restored VM is a new one, with no firewall identity (the insert
	// strips the backup's): what the deleted VM of this name left is read
	// before the row takes its tombstone over.
	tagsLeft := s.firewallTagsLeftNote(ctx, corrosion.TagMemberVM, project, targetName, "")
	if err := s.insertVMWithGrants(ctx, spec, gs, vmRecord, ifaceRecords, diskRecords, nicRecords, pciIntents, false); err != nil {
		if fwVM {
			// A running firmware domain with no DB row is unmanageable — lifecycle
			// code wouldn't know to preserve/wipe its state — so fail hard; the
			// deferred rollback destroys the domain + wipes the firmware. That
			// rollback was registered after the device allocation, so it runs
			// first (defers are LIFO); the release is still decided here, by
			// pciHeld, which clears only once this explicit destroy succeeds,
			// so the devices are released only off a guest that is gone.
			if derr := s.virt.DestroyDomain(targetName); derr == nil {
				pciHeld = false
			}
			return "", "", status.Errorf(codes.Internal, "persist restored firmware VM %q: %v", targetName, err)
		}
		slog.Error("live-restore: failed to write VM to corrosion", "vm", targetName, "error", err)
	} else {
		if tagsLeft != "" {
			_ = send(&pb.RestoreLiveProgress{Status: tagsLeft})
		}
		// Graduates, marks, and only then publishes running; a failure leaves the
		// row "creating" for the reconciler to finish.
		//
		// In the else on purpose: a non-firmware insert failure is NOT fatal on
		// this path, so an unguarded call would act on a row that does not exist.
		s.assignOwnerEpochAtCreate(ctx, targetName, true)
		// The guards apply from the first reconcile that sees the row.
		if len(guardRecords) > 0 {
			s.reconcileLocal(ctx)
		}
	}
	// Only now: the fence has passed and the row is in the cluster, published
	// running unless assignOwnerEpochAtCreate left it "creating" for the
	// reconciler. Sent earlier, a client could read no row at all, or be told
	// a VM had started that the fence then destroyed.
	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_STARTED, VmName: targetName,
		TargetPath: overlayPath, Status: "VM started off overlay",
	})
	restoreOK = true
	pciKept = true
	s.recordVMEvent(ctx, targetName, "vm.created", "ok", "host="+s.hostName+" (live-restore)")
	if devicesDropped != "" {
		s.audit(ctx, "vm.devices_dropped", targetName, "restore: not attached (--without-devices): "+devicesDropped, "degraded")
	}
	s.auditTuningDropped(ctx, ioR, targetName, "restore")
	if len(limDropped) > 0 {
		s.audit(ctx, "vm.release_features_dropped", targetName, "restore: not carried: "+strings.Join(limDropped, "; "), "degraded")
	}
	return targetName, rootDev, nil
}

// driveBlockpull localizes the restored disk by flattening the NBD backing
// chain into the overlay, then returns once the job completes so the
// caller's deferred NBD teardown can run. On a failed/partial pull it
// returns ok=false so the caller keeps the stream open instead of
// bricking a half-pulled disk.
func (s *Server) driveBlockpull(ctx context.Context, vmName, dev string, send func(*pb.RestoreLiveProgress) error) (ok bool) {
	if dev == "" {
		dev = "vda"
	}
	_ = send(&pb.RestoreLiveProgress{
		Phase: pb.RestoreLiveProgress_BLOCKPULL, VmName: vmName,
		Status: "localizing disk via blockpull",
	})
	if err := s.virt.BlockPull(vmName, dev); err != nil {
		_ = send(&pb.RestoreLiveProgress{
			Phase: pb.RestoreLiveProgress_READY, VmName: vmName,
			Status: "blockpull failed (" + err.Error() + ") — keeping NBD up; localize manually then close the stream",
		})
		return false
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
			st, err := s.virt.BlockJobStatus(vmName, dev)
			if err != nil {
				_ = send(&pb.RestoreLiveProgress{
					Phase: pb.RestoreLiveProgress_READY, VmName: vmName,
					Status: "blockpull status error (" + err.Error() + ") — keeping NBD up",
				})
				return false
			}
			if !st.Found || (st.End > 0 && st.Cur >= st.End) {
				_ = send(&pb.RestoreLiveProgress{
					Phase: pb.RestoreLiveProgress_LOCALIZED, VmName: vmName,
					Status: "disk localized — NBD server stopping",
				})
				return true
			}
		}
	}
}

// liveVMHoldsUUID reports whether a live VM row carries uuid as its spec
// uuid. A list that cannot be read answers yes.
func (s *Server) liveVMHoldsUUID(ctx context.Context, u string) bool {
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return true
	}
	for _, v := range vms {
		if v.Spec == "" {
			continue
		}
		var sp struct {
			UUID string `json:"uuid"`
		}
		if json.Unmarshal([]byte(v.Spec), &sp) == nil && sp.UUID == u {
			return true
		}
	}
	return false
}
