package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// vfioHost is this host's vfio binder, which records each device's previous host
// driver in the data directory (vfio.HostDriversFileName) so a release rebinds
// that driver explicitly. With no data directory it keeps no record.
func (s *Server) vfioHost() *vfio.Host {
	if s.dataDir == "" {
		return vfio.HostAt("")
	}
	return vfio.HostAt(filepath.Join(s.dataDir, vfio.HostDriversFileName))
}

// RescanHost triggers a PCI device rescan on the local host and updates the DB.
func (s *Server) RescanHost(ctx context.Context, req *pb.RescanHostRequest) (*pb.RescanHostResponse, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	if req.Name != "" && req.Name != s.hostName {
		client, conn, err := s.peerClient(ctx, req.Name)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", req.Name, err)
		}
		defer conn.Close()
		return client.RescanHost(ctx, req)
	}

	// Get existing devices from DB to calculate diff.
	existing, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list existing devices: %v", err)
	}
	existingMap := make(map[string]bool, len(existing))
	for _, d := range existing {
		existingMap[d.Address] = true
	}

	// Scan the host.
	scan := pci.Scan
	if s.pciScanOverride != nil {
		scan = s.pciScanOverride
	}
	scanned, err := scan()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "PCI scan: %v", err)
	}

	interesting := pci.FilterInteresting(scanned)

	var added, removed int32
	scannedMap := make(map[string]bool, len(interesting))

	for _, d := range interesting {
		scannedMap[d.Address] = true
		if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName:      s.hostName,
			Address:       d.Address,
			VendorID:      d.VendorID,
			DeviceID:      d.DeviceID,
			VendorName:    d.VendorName,
			DeviceName:    d.DeviceName,
			Type:          d.Type,
			IOMMUGroup:    d.IOMMUGroup,
			SRIOVCapable:  d.SRIOVCapable,
			SRIOVVFsTotal: d.SRIOVVFsTotal,
			SRIOVVFsFree:  d.SRIOVVFsFree,
			Driver:        d.Driver,
			NUMANode:      d.NUMANode,
		}); err != nil {
			slog.Warn("failed to upsert PCI device", "address", d.Address, "error", err)
		}
		if !existingMap[d.Address] {
			added++
			s.publish("device.added", s.hostName, d.Address+" "+d.Type)
		}

		// Track individual VFs for SR-IOV capable PFs so that VF pool
		// exhaustion is properly detected (#36).
		if d.SRIOVCapable && d.SRIOVVFsTotal > 0 {
			vfAddrs, err := pci.ListVFs(d.Address)
			if err != nil {
				slog.Debug("rescan: list VFs", "pf", d.Address, "error", err)
				continue
			}
			for _, vfAddr := range vfAddrs {
				scannedMap[vfAddr] = true
				vfDev, scanErr := pci.ScanDevice(vfAddr)
				if scanErr != nil {
					continue
				}
				if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
					HostName:   s.hostName,
					Address:    vfDev.Address,
					VendorID:   vfDev.VendorID,
					DeviceID:   vfDev.DeviceID,
					VendorName: vfDev.VendorName,
					DeviceName: vfDev.DeviceName,
					Type:       vfDev.Type,
					IOMMUGroup: vfDev.IOMMUGroup,
					Driver:     vfDev.Driver,
					NUMANode:   vfDev.NUMANode,
				}); err != nil {
					slog.Debug("rescan: upsert VF", "address", vfAddr, "error", err)
				}
				if !existingMap[vfAddr] {
					added++
				}
			}
		}
	}

	// Mark disappeared devices.
	for _, d := range existing {
		if !scannedMap[d.Address] {
			removed++
			corrosion.SoftDeletePCIDevice(ctx, s.db, s.hostName, d.Address)
			s.publish("device.removed", s.hostName, d.Address+" "+d.Type)
			if d.VMName != "" {
				slog.Error("assigned device disappeared", "address", d.Address, "vm", d.VMName)
				s.publish("device.lost", d.VMName, d.Address+" was assigned to running VM")
			}
		}
	}

	// Reclaim assignments whose VM no longer exists. A device that vanished and
	// came back keeps its vm_name deliberately (a transient scan drop must not
	// let a second VM claim hardware still in use), but nothing else ever clears
	// it once the VM is gone — and ClaimPCIDevice matches only an empty vm_name,
	// so such a device would be unassignable forever (#218). The age guard keeps
	// a not-yet-replicated VM from having its device taken.
	if freed, sErr := corrosion.SweepStrandedPCIOwnership(ctx, s.db, s.hostName,
		corrosion.DefaultPCIOwnershipSweepAge); sErr != nil {
		slog.Warn("rescan: stranded-ownership sweep failed", "error", sErr)
	} else {
		for _, addr := range freed {
			s.publish("device.reclaimed", s.hostName, addr+" freed: owning VM no longer exists")
		}
	}
	// And devices a live VM owns but provably does not hold: what a failed SR-IOV
	// attach on an older build left behind (lab finding L1).
	s.SweepUnattachedPCIOwnership(ctx)

	// Build response.
	devices, _ := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	resp := &pb.RescanHostResponse{
		Added:   added,
		Removed: removed,
		Total:   int32(len(devices)),
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, pciDeviceToProto(d))
	}

	slog.Info("PCI rescan complete", "added", added, "removed", removed, "total", len(devices))
	return resp, nil
}

// ListHostDevices returns PCI devices for a host.
func (s *Server) ListHostDevices(ctx context.Context, req *pb.ListHostDevicesRequest) (*pb.ListHostDevicesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	hostName := req.Name
	if hostName == "" {
		hostName = s.hostName
	}

	devices, err := corrosion.ListPCIDevices(ctx, s.db, hostName, req.TypeFilter)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list devices: %v", err)
	}

	resp := &pb.ListHostDevicesResponse{}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, pciDeviceToProto(d))
	}
	return resp, nil
}

// ResolvedMember is one concrete host device that realizes a PCI passthrough
// request: the resolved BDF plus the intent/member identity used to key its
// vm_pci_realizations row and its `ua-<DeviceID>-<MemberID>` hostdev alias.
// Ordinal orders the members realizing a single request (primary = 0, then its
// IOMMU-group siblings, then subsequent count-N devices).
type ResolvedMember struct {
	DeviceID string
	MemberID string
	Address  string
	Ordinal  int
}

// allocateDevices resolves DeviceSpec requests against host inventory,
// validates IOMMU group conflicts, assigns devices, binds to VFIO-PCI,
// and returns the PCI addresses for hostdev XML.
//
// It is a thin composition of the pure resolve phase (resolveDeviceSpec /
// allocateSRIOVVFs) and the side-effecting acquire phase (acquireDeviceLeases):
// existing callers see identical behavior. It returns the resolved addresses AND
// a finish func: the durable device-lease entry (F1) is written before the vfio
// bind, and the CALLER must defer finish() so the lease is cleared once the VM
// row is finalized (or on the caller's own rollback). A crash before finish()
// runs leaves the entry for startup recovery (RecoverDeviceLeases) to roll back.
//
// stage is the initial durable device-lease stage (see beginDeviceLease): CreateVM passes
// deviceLeaseStageBound; the legacy running-attach passes deviceLeaseStageInProgress.
func (s *Server) allocateDevices(ctx context.Context, vmName string, specs []*pb.DeviceSpec, stage string) ([]string, func(), error) {
	noop := func() {}
	var members []ResolvedMember

	// sriovClaimed = the VFs allocateSRIOVVFs CAS-claimed for THIS request. It only
	// claims unassigned VFs, so none of them belongs to an earlier attach. Every
	// failure from here on must release them: acquireDeviceLeases sees them as
	// self-owned, so its own claim set never includes them (lab finding L1, where
	// each failed SR-IOV attach left one more VF owned by the VM).
	var sriovClaimed []string
	fail := func(err error) ([]string, func(), error) {
		if len(sriovClaimed) > 0 {
			// Nothing is bound yet, so the strict primitive skips every unbind and
			// owner-releases them.
			if rerr := s.unbindAndReleaseOwnership(ctx, vmName, sriovClaimed); rerr != nil {
				slog.Error("sr-iov allocation rollback: release incomplete", "vm", vmName, "vfs", sriovClaimed, "error", rerr)
			}
		}
		return nil, noop, err
	}

	// Cross-spec exclusion set: the addresses already selected by earlier specs in
	// THIS request (primaries + IOMMU-group siblings + claimed SR-IOV VFs). The old
	// fused loop assigned each spec inline, so a later type/vendor spec's
	// GetAvailableDevicesByType saw a SHRINKING pool; resolving deferred assignment
	// to acquire, so every type spec would otherwise re-select the same free
	// device. Threading this set restores the pool-shrinking semantics PURELY — no
	// assignment in the resolve phase, just in-memory exclusion.
	selected := map[string]bool{}
	// A device named by address, or by a mapping, is its own selector's, never
	// another's IOMMU sibling or type pick; type selectors are then satisfied
	// first, and the named devices' siblings are added last (pciSelectorPhase).
	kinds := make([]string, len(specs))
	for i, spec := range specs {
		kind, key := corrosion.ClassifyPCISelector(spec)
		kinds[i] = kind
		switch kind {
		case "address":
			if key != nil {
				selected[*key] = true
			}
		case "mapping":
			if addr, err := corrosion.ResolveMappingAddress(ctx, s.db, spec.Mapping, s.hostName); err == nil && addr != "" {
				selected[addr] = true
			}
		}
	}

	bySpec := make([][]ResolvedMember, len(specs))
	for _, i := range pciSelectorOrder(kinds) {
		spec := specs[i]
		count := int(spec.Count)
		if count == 0 {
			count = 1
		}
		selectorKind, _ := corrosion.ClassifyPCISelector(spec)

		// SR-IOV VF allocation is inherently side-effecting — it CAS-claims free VFs
		// and may create a VF pool on-demand (writing host sysfs) — so it cannot be
		// part of the pure resolver and stays on this path. The claimed VFs flow into
		// acquireDeviceLeases alongside the rest for the durable lease + vfio bind.
		//
		// A resource-mapping spec is a concrete pin, not VF allocation: mapping
		// resolution must precede the SR-IOV branch (as in the original order), so a
		// Sriov+Mapping spec resolves the mapped device rather than allocating a VF.
		if selectorKind == "sriov" {
			vfAddrs, err := s.allocateSRIOVVFs(ctx, vmName, spec, count)
			if err != nil {
				return fail(err)
			}
			for j, a := range vfAddrs {
				bySpec[i] = append(bySpec[i], ResolvedMember{MemberID: fmt.Sprintf("m%d", j), Address: a, Ordinal: j})
				selected[a] = true
				sriovClaimed = append(sriovClaimed, a)
			}
			continue
		}

		specMembers, err := s.resolveDeviceSpec(ctx, vmName, spec, "", selected)
		if err != nil {
			return fail(err)
		}
		// Freeze the resolved concrete BDF back onto a resource-mapping spec so
		// CreateVM's json.Marshal(spec) records the current realization. Mapping
		// remains the authoritative portable selector; Address is only its cached
		// per-host artifact. The pure resolveDeviceSpec never mutates the spec —
		// allocateDevices does.
		if spec.Mapping != "" && len(specMembers) > 0 {
			spec.Address = specMembers[0].Address
		}
		bySpec[i] = specMembers
	}
	for _, m := range bySpec {
		members = append(members, m...)
	}

	// On its own failures acquireDeviceLeases releases sriovClaimed too.
	finish, _, err := s.acquireDeviceLeases(ctx, vmName, members, stage, sriovClaimed)
	if err != nil {
		return nil, noop, err
	}
	addresses := make([]string, 0, len(members))
	for _, m := range members {
		addresses = append(addresses, m.Address)
	}
	return addresses, finish, nil
}

// resolveDeviceSpec is the PURE selection/validation core shared by
// allocateDevices (from a live *pb.DeviceSpec) and resolveDeviceIntents (from a
// stored intent). It resolves ONE non-SR-IOV request to its concrete host
// device(s): a resource mapping to this host's pinned address, an exact address
// or a type/vendor/model match, each expanded to include its IOMMU-group
// siblings and validated against IOMMU-group conflicts. It performs NO
// AssignPCIDevice, NO VF creation and NO vfio bind — nothing that touches host
// hardware or inventory ownership — so it is safe to run while reconciling a
// stopped VM. deviceID (the intent id, "" for the live-spec path) is stamped
// onto every returned member.
//
// exclude is a cross-spec working set of addresses already chosen by earlier
// specs in the same request: type/vendor selection SKIPS any candidate in it, and
// each address this call selects (primary + IOMMU-group siblings) is added to it,
// so a subsequent spec sees the same shrunken pool the old inline-assign loop did.
// It is a caller-owned scratch map (never a *pb.DeviceSpec), so mutating it keeps
// the resolver pure w.r.t. host hardware and inventory ownership.
func (s *Server) resolveDeviceSpec(ctx context.Context, vmName string, spec *pb.DeviceSpec, deviceID string, exclude map[string]bool) ([]ResolvedMember, error) {
	count := int(spec.Count)
	if count == 0 {
		count = 1
	}

	selectorKind, _ := corrosion.ClassifyPCISelector(spec)
	address := ""
	switch selectorKind {
	case "mapping":
		// Resource mapping (#14): resolve a cluster-wide mapping name to the concrete
		// PCI address registered for THIS host, then treat it as an exact pin. This is
		// what lets a passthrough VM land on / migrate to any host that has a device
		// under the same mapping. Mapping outranks a frozen Address artifact, matching
		// ClassifyPCISelector and CanonicalPCISelector. Resolve into a local var —
		// never mutate the input spec.
		addr, err := corrosion.ResolveMappingAddress(ctx, s.db, spec.Mapping, s.hostName)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "resolve resource mapping %q: %v", spec.Mapping, err)
		}
		if addr == "" {
			return nil, status.Errorf(codes.FailedPrecondition,
				"resource mapping %q has no device on host %s", spec.Mapping, s.hostName)
		}
		address = addr
	case "address":
		address = spec.Address
	case "sriov":
		return nil, status.Error(codes.FailedPrecondition,
			"SR-IOV selector must be resolved by the SR-IOV allocator")
	}

	var members []ResolvedMember
	ordinal := 0
	// addPrimary appends primary + its IOMMU-group siblings as ordered members.
	// The conflict check is on the primary only (a sibling shares the group, so a
	// conflicting other-VM owner is already caught by the primary's check). A
	// sibling already in exclude is not added: another selector of this
	// request took it or names it (a GPU and its audio function, each named
	// by address), and each device is passed through once.
	addPrimary := func(primary string) error {
		if err := s.checkIOMMUConflict(ctx, primary, vmName); err != nil {
			return err
		}
		members = append(members, ResolvedMember{DeviceID: deviceID, MemberID: fmt.Sprintf("m%d", ordinal), Address: primary, Ordinal: ordinal})
		ordinal++
		exclude[primary] = true
		groupAddrs, err := s.iommuGroupSiblings(ctx, primary)
		if err != nil {
			return status.Errorf(codes.Unavailable,
				"refusing PCI passthrough of %s: cannot read host %s's PCI inventory (host_pci_devices) "+
					"for its IOMMU-group siblings: %v; retry once the local database is readable",
				primary, s.hostName, err)
		}
		for _, a := range groupAddrs {
			if a != primary && !exclude[a] {
				members = append(members, ResolvedMember{DeviceID: deviceID, MemberID: fmt.Sprintf("m%d", ordinal), Address: a, Ordinal: ordinal})
				ordinal++
				exclude[a] = true
			}
		}
		return nil
	}

	// Exact address pinning (also the resolved-mapping path).
	if address != "" {
		if err := addPrimary(address); err != nil {
			return nil, err
		}
		return members, nil
	}

	// A device that realizes this intent here, and the VM still owns, realizes
	// it again: a restart keeps the device it has, and never takes a second
	// one for an intent the first already satisfies. Only the remainder, if
	// any, is searched for among the free devices.
	matches := func(d corrosion.PCIDeviceRecord) bool {
		return (spec.Type == "" || d.Type == spec.Type) &&
			(spec.Vendor == "" || d.VendorID == spec.Vendor) &&
			(spec.Model == "" || d.DeviceName == spec.Model)
	}
	if deviceID != "" {
		owned, err := s.ownedRealizationsHere(ctx, vmName, deviceID)
		if err != nil {
			return nil, err
		}
		for _, d := range owned {
			if count == 0 {
				break
			}
			if exclude[d.Address] || !matches(d) {
				continue
			}
			if err := addPrimary(d.Address); err != nil {
				return nil, err
			}
			count--
		}
		if count == 0 {
			return members, nil
		}
	}

	// Type/vendor allocation. A vendor-only selector is classified as type-kind
	// even when Type is empty, so it must search the whole unassigned inventory;
	// querying GetAvailableDevicesByType with "" would incorrectly require a
	// literal empty device type. Preserve the narrower indexed query whenever a
	// concrete type is present.
	var available []corrosion.PCIDeviceRecord
	var err error
	if spec.Type == "" {
		available, err = corrosion.GetAvailableDevicesWithTopology(ctx, s.db, s.hostName, "")
	} else {
		available, err = corrosion.GetAvailableDevicesByType(ctx, s.db, s.hostName, spec.Type)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query devices: %v", err)
	}
	// Filter by vendor/model if specified, skipping any device already chosen by an
	// earlier spec in this request (the cross-spec pool-shrinking exclusion).
	var matched []corrosion.PCIDeviceRecord
	for _, d := range available {
		if exclude[d.Address] || !matches(d) {
			continue
		}
		matched = append(matched, d)
	}
	if len(matched) < count {
		return nil, status.Errorf(codes.ResourceExhausted,
			"need %d %s device(s) but only %d available on host %s",
			count, spec.Type, len(matched), s.hostName)
	}
	for i := 0; i < count; i++ {
		if err := addPrimary(matched[i].Address); err != nil {
			return nil, err
		}
	}
	return members, nil
}

// resolveDeviceIntents is the PURE resolver the topology-preserving reconcile
// primitive uses: it maps a VM's stored vm_pci_intent rows to the concrete host
// members they realize, touching no host hardware and no inventory ownership.
// An "address" intent resolves via its exclusive_key BDF; portable "mapping" /
// "type" intents decode their selector_payload (a protojson DeviceSpec) and run
// the shared resolveDeviceSpec selection. SR-IOV intents are NOT resolved here:
// realizing them CAS-claims and may create VFs (side effects), which belongs in
// the acquire phase (allocateSRIOVVFs) — wiring pure SR-IOV candidate selection
// into this resolver is deferred to the start-path task.
func (s *Server) resolveDeviceIntents(ctx context.Context, vmName string, intents []corrosion.PCIIntentRecord) ([]ResolvedMember, error) {
	// Cross-intent exclusion set (see resolveDeviceSpec): a scratch map so two
	// type/vendor intents resolve to distinct devices, exactly as the live-spec
	// path. Local to this call — resolveDeviceIntents stays pure.
	return s.resolveDeviceIntentsExcluding(ctx, vmName, intents, map[string]bool{})
}

// resolveDeviceIntentsExcluding is resolveDeviceIntents with a caller-owned
// exclusion set: each intent takes a device none before it took.
func (s *Server) resolveDeviceIntentsExcluding(ctx context.Context, vmName string, intents []corrosion.PCIIntentRecord, selected map[string]bool) ([]ResolvedMember, error) {
	local, err := s.addressIntentsHere(ctx, vmName, intents, selected)
	if err != nil {
		return nil, err
	}
	return s.resolveIntentsHere(ctx, vmName, intents, selected, local)
}

// addressIntentsHere is the device on this host that realizes each
// concrete-address intent of intents, by intent id, each marked in selected
// (and so is the device each mapping intent names here)
// before any intent is realized: a device the VM names by address is realized
// by its own intent, never as the IOMMU-group sibling of another (a GPU and
// its audio function, each named), and no type selector takes it. An address
// recorded on this host is that device; one recorded on another host (a
// failover) is a device of its kind here (pci_failover.go), none taken twice.
func (s *Server) addressIntentsHere(ctx context.Context, vmName string, intents []corrosion.PCIIntentRecord, selected map[string]bool) (map[string]string, error) {
	local := map[string]string{}
	var moved []corrosion.PCIIntentRecord
	for _, in := range intents {
		if in.SelectorKind == "mapping" {
			// A mapping names this host's device for it: reserved likewise.
			spec := &pb.DeviceSpec{}
			if err := protojson.Unmarshal([]byte(in.SelectorPayload), spec); err != nil {
				return nil, status.Errorf(codes.Internal, "decode selector payload for device %s: %v", in.DeviceID, err)
			}
			addr, err := corrosion.ResolveMappingAddress(ctx, s.db, spec.Mapping, s.hostName)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "resolve resource mapping %q: %v", spec.Mapping, err)
			}
			if addr != "" {
				selected[addr] = true
			}
			continue
		}
		if in.SelectorKind != "address" {
			continue
		}
		if in.HostName != "" && in.HostName != s.hostName {
			moved = append(moved, in)
			continue
		}
		addr := ""
		if in.ExclusiveKey != nil {
			addr = *in.ExclusiveKey
		}
		local[in.DeviceID] = addr
		selected[addr] = true
	}
	for _, in := range moved {
		addr := ""
		if in.ExclusiveKey != nil {
			addr = *in.ExclusiveKey
		}
		here, err := s.addressOnThisHost(ctx, vmName, in.DeviceID, in.HostName, addr, selected)
		if err != nil {
			return nil, err
		}
		local[in.DeviceID] = here
		selected[here] = true
	}
	return local, nil
}

// resolveIntentsHere resolves intents, each concrete address to its device in
// local (addressIntentsHere).
func (s *Server) resolveIntentsHere(ctx context.Context, vmName string, intents []corrosion.PCIIntentRecord, selected map[string]bool, local map[string]string) ([]ResolvedMember, error) {
	kinds := make([]string, len(intents))
	for i, in := range intents {
		kinds[i] = in.SelectorKind
	}
	byIntent := make([][]ResolvedMember, len(intents))
	for _, i := range pciSelectorOrder(kinds) {
		intent := intents[i]
		var members []ResolvedMember
		switch intent.SelectorKind {
		case "sriov":
			return nil, status.Errorf(codes.Unimplemented,
				"SR-IOV intent %s: VF realization is side-effecting and handled by the acquire path, not the pure resolver", intent.DeviceID)
		case "address":
			// The address is a slot on the host it was recorded on. On any
			// other host (a failover) it is realized by a device of its kind
			// here, never by whatever sits at the same address
			// (addressIntentsHere).
			addr, ok := local[intent.DeviceID]
			if !ok {
				return nil, status.Errorf(codes.Internal, "PCI device %s of %s has no address on host %s", intent.DeviceID, vmName, s.hostName)
			}
			specMembers, err := s.resolveDeviceSpec(ctx, vmName, &pb.DeviceSpec{Address: addr}, intent.DeviceID, selected)
			if err != nil {
				return nil, err
			}
			members = append(members, specMembers...)
		default: // "mapping", "type"
			spec := &pb.DeviceSpec{}
			if err := protojson.Unmarshal([]byte(intent.SelectorPayload), spec); err != nil {
				return nil, status.Errorf(codes.Internal, "decode selector payload for device %s: %v", intent.DeviceID, err)
			}
			specMembers, err := s.resolveDeviceSpec(ctx, vmName, spec, intent.DeviceID, selected)
			if err != nil {
				return nil, err
			}
			members = append(members, specMembers...)
		}
		byIntent[i] = members
	}
	var members []ResolvedMember
	for _, m := range byIntent {
		members = append(members, m...)
	}
	return members, nil
}

// pciSelectorOrder is the order a request's selectors, by kind, are realized
// in: SR-IOV and type selectors first, from the devices no address or mapping
// names (those are reserved beforehand), then address and mapping selectors,
// whose IOMMU-group siblings are added last, skipping what a type selector
// took. The order does not depend on the selectors' order in the request.
func pciSelectorOrder(kinds []string) []int {
	var first, last []int
	for i, k := range kinds {
		if k == "address" || k == "mapping" {
			last = append(last, i)
		} else {
			first = append(first, i)
		}
	}
	return append(first, last...)
}

// claimDeviceOwnership is the ONE shared, fail-closed inventory reservation used by
// EVERY PCI producer — CreateVM's allocateDevices, the running attach, AND the
// stopped concrete-address attach. It reads the current owner of each member once
// (no new statement), then per member:
//   - owner == vmName → an idempotent self-claim (e.g. an SR-IOV VF CAS-claimed
//     during selection, or a same-op retry / re-attach): keep it, NOT newly claimed.
//   - owner is a DIFFERENT non-empty VM → FAIL (AlreadyExists), rolling back the
//     members THIS call already claimed.
//   - present and unowned → corrosion.ClaimPCIDevice (CAS: assigns only if active
//     and unassigned); a false return (lost the race) or an error FAILS the same way.
//   - absent / tombstoned from inventory → FAIL CLOSED (FailedPrecondition): there
//     is no claimable ownership row, so we refuse rather than reserve nothing.
//
// It performs NO vfio bind and writes NO durable lease — ownership only, so it is
// safe on the stopped-attach declare path (the bind/lease/realization stay at VM
// start). It returns the addresses it NEWLY claimed and a release closure that
// owner-releases EXACTLY those (owner-scoped, a no-op for a self-owned member, and a
// no-op if another VM has since claimed the address) — the caller invokes release to
// undo the reservation on its own later failure, or uses the claimed list to scope a
// rollback so a self-owned reservation (a device reserved while the VM was off,
// FIX-9b) is never released by a failed operation. On any failure WITHIN the loop it
// rolls the newly-claimed members back itself before returning the error.
func (s *Server) claimDeviceOwnership(ctx context.Context, vmName string, members []ResolvedMember) ([]string, func(), error) {
	noop := func() {}

	// Current owners on this host, read once (no new statement): distinguishes
	// self-owned (idempotent), other-owned (conflict), present+unowned (CAS-claim)
	// and absent (fail closed).
	owners := map[string]string{}
	devs, lerr := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if lerr != nil {
		return nil, noop, status.Errorf(codes.Internal, "read PCI inventory: %v", lerr)
	}
	for _, d := range devs {
		owners[d.Address] = d.VMName
	}

	// claimed = the addresses THIS call took; release owner-releases exactly those
	// (never another VM's device, never a pre-existing self-owned reservation). No
	// vfio unbind — nothing is bound here.
	var claimed []string
	release := func() {
		for _, addr := range claimed {
			if err := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); err != nil {
				slog.Warn("failed to release PCI device in DB", "vm", vmName, "address", addr, "error", err)
			}
		}
	}
	for _, m := range members {
		addr := m.Address
		owner, present := owners[addr]
		switch {
		case owner == vmName:
			// Already ours — idempotent self-claim; not newly claimed, nothing to do.
		case owner != "":
			release()
			return nil, noop, status.Errorf(codes.AlreadyExists,
				"PCI device %s (host %s) is already claimed by VM %q", addr, s.hostName, owner)
		case !present:
			// Absent / tombstoned from inventory: no claimable ownership row exists.
			// Fail CLOSED — a real passthrough device is discovered into host_pci_devices
			// before it can be assigned, so a missing BDF is an error, not a bind-anyway.
			release()
			return nil, noop, status.Errorf(codes.FailedPrecondition,
				"PCI device %s is not in host %s inventory", addr, s.hostName)
		default:
			// Present and unowned → atomic CAS claim.
			ok, cerr := corrosion.ClaimPCIDevice(ctx, s.db, s.hostName, addr, vmName)
			if cerr != nil {
				release()
				return nil, noop, status.Errorf(codes.Internal, "claim PCI device %s: %v", addr, cerr)
			}
			if !ok {
				// Lost the CAS race — another operation claimed it between the read and here.
				release()
				return nil, noop, status.Errorf(codes.AlreadyExists,
					"PCI device %s (host %s) was claimed by another operation", addr, s.hostName)
			}
			claimed = append(claimed, addr)
		}
	}
	return claimed, release, nil
}

// acquireDeviceLeases is the side-effecting counterpart to resolveDeviceIntents for
// the RUNNING / start path: it composes the shared claimDeviceOwnership reservation
// (the exclusive, fail-closed physical-double-bind guard) with the durable
// device-lease entry (F1) written BEFORE the irreversible vfio bind, then binds
// every member to vfio-pci. On a bind failure it rolls back the devices this call
// newly claimed (via the strict unbindAndReleaseOwnership primitive) and clears the
// lease — unless the release could not confirm the unbind, in which case it RETAINS
// the lease so a crash before the VM row is finalized is recovered at startup. It returns the finish func the caller must
// defer to clear the lease once the row is durable, AND the addresses it NEWLY claimed
// (a self-owned member is skipped → NOT in the list), so a caller's OWN post-acquire
// rollback can release exactly the devices this start took and never a pre-existing
// self-owned reserve-while-off reservation (FIX-9b/9c).
//
// stage is the initial durable device-lease stage (see beginDeviceLease): every caller
// passes deviceLeaseStageBound EXCEPT the unjournaled legacy running-attach, which passes
// deviceLeaseStageInProgress so a mid-attach crash is reclaimed, not cleared.
//
// preClaimed is what the caller already CAS-claimed for THIS attempt before calling:
// the SR-IOV VFs allocateSRIOVVFs took. claimDeviceOwnership sees those as self-owned
// and skips them, so without this every failure below left them owned by the VM with
// nothing to reclaim them (lab finding L1). They join the newly-claimed set: every
// failure here releases them, and the returned list includes them. A device from an
// earlier, successful attach is in neither list.
func (s *Server) acquireDeviceLeases(ctx context.Context, vmName string, members []ResolvedMember, stage string, preClaimed []string) (func(), []string, error) {
	noop := func() {}

	// Claim inventory ownership (fail-closed CAS) BEFORE any bind. On failure the
	// claim rolled back its own reservations; the caller's pre-claims are still held
	// and nothing is bound, so the strict primitive just owner-releases them.
	// claimed = the members THIS attempt newly took (a self-owned member is skipped
	// and is NOT in the list), so the bind-failure rollback can release exactly those
	// and never a pre-existing self-owned reservation.
	newlyClaimed, _, cerr := s.claimDeviceOwnership(ctx, vmName, members)
	if cerr != nil {
		if len(preClaimed) > 0 {
			if rerr := s.unbindAndReleaseOwnership(ctx, vmName, preClaimed); rerr != nil {
				slog.Error("device claim failed; pre-claimed device rollback incomplete (owned, not yet bound)", "vm", vmName, "error", rerr)
			}
		}
		return noop, nil, cerr
	}
	claimed := mergeAddrs(preClaimed, newlyClaimed)

	addresses := make([]string, 0, len(members))
	for _, m := range members {
		addresses = append(addresses, m.Address)
	}

	// Durably record the claimed devices (F1 device lease) BEFORE the irreversible
	// vfio bind, so a crash before the VM row is finalized is rolled back at
	// startup. No-op unless the operation_protocol capability is active.
	finish, lerr := s.beginDeviceLease(ctx, vmName, addresses, stage)
	if lerr != nil {
		// Could not durably record the pre-bind crash anchor → we must NOT bind (a crash would
		// leave an owned, vfio-bound device with no recovery record). Release the claims made
		// (nothing is bound yet → the strict primitive skips every unbind and just owner-
		// releases them) and abort BEFORE the bind loop.
		if rerr := s.unbindAndReleaseOwnership(ctx, vmName, claimed); rerr != nil {
			slog.Error("device-lease begin failed; claim rollback incomplete (owned, not yet bound)", "vm", vmName, "error", rerr)
		}
		return noop, nil, status.Errorf(codes.Internal, "record device lease for %q: %v", vmName, lerr)
	}

	for _, addr := range addresses {
		prevDriver, err := s.vfioHost().Bind(addr)
		if err != nil {
			slog.Warn("VFIO bind failed", "address", addr, "error", err)
			// Roll back ONLY the devices THIS call newly claimed, via the strict all-or-
			// nothing primitive (unbind bound members by vfio ground truth, then owner-
			// release). A self-owned reservation (a device reserved while the VM was off,
			// FIX-9b) is NOT in `claimed`, so a failed start-time bind retains it rather than
			// silently dropping the reservation. When nothing is self-owned, `claimed` ==
			// every address.
			if rerr := s.unbindAndReleaseOwnership(ctx, vmName, claimed); rerr != nil {
				// A freshly-claimed member could not be confirmed unbound → leave it owned +
				// bound (recoverable, never unowned + bound) and RETAIN the durable device-
				// lease so RecoverDeviceLeases retries the release; do NOT finish().
				slog.Error("VFIO bind rollback: release incomplete — device lease retained for recovery", "vm", vmName, "error", rerr)
			} else {
				finish() // release converged (or nothing to release) → clear the durable lease
			}
			return noop, nil, status.Errorf(codes.Internal,
				"failed to bind device %s to vfio-pci: %v", addr, err)
		}
		slog.Info("device bound to vfio-pci", "address", addr, "previous_driver", prevDriver)
	}

	return finish, claimed, nil
}

// pciStartPreflight realizes a hardware_v2 VM's reserved PCI intents at start:
// it resolves every intent to concrete host members, acquires the device leases
// (CAS ownership + durable F1 lease + vfio bind), persists vm_pci_realizations
// (member_id + ua-alias + resolved_address — CONTRACT g) and reconciles the aliased
// <hostdev>s into the domain definition — everything that must be true BEFORE
// StartDomain. It fails CLOSED: a vanished/unacquirable device, a realization write
// failure, or a reconcile failure releases whatever was claimed and returns the
// error (the VM does not start).
//
// SR-IOV routing (CONTRACT a): resolveDeviceIntents returns Unimplemented for an
// sriov selector (VF realization is side-effecting), so an sriov intent is routed
// through allocateSRIOVVFs (the CAS-claim / VF-create acquire path); concrete-address,
// mapping and type intents go through the pure resolveDeviceIntents.
//
// On success it clears the durable F1 lease (the realization rows are the durable
// record now) and returns a release func the caller invokes ONLY if the subsequent
// StartDomain fails, so a failed start leaves no VM bound to devices it never used.
func (s *Server) pciStartPreflight(ctx context.Context, vm *corrosion.VMRecord, intents []corrosion.PCIIntentRecord) (release func(), err error) {
	// ── Resolve every intent to concrete members (routing SR-IOV to the allocator) ──
	var members []ResolvedMember
	var claimedSriov []string // VFs allocateSRIOVVFs CAS-claimed (released on a resolve failure)
	// Every device an earlier intent of this start took: two intents of one
	// kind take two devices.
	selected := map[string]bool{}
	local, lerr := s.addressIntentsHere(ctx, vm.Name, intents, selected)
	if lerr != nil {
		return nil, lerr
	}
	resolveFail := func(e error) (func(), error) {
		if len(claimedSriov) > 0 {
			// The VFs were CAS-claimed but never vfio-bound (allocateSRIOVVFs binds nothing),
			// so the strict primitive skips every unbind (IsBoundToVFIO=false) and just owner-
			// releases them — behavior-preserving. A release-write failure is only logged: the
			// resolve already failed and the residual owned VF converges on the next start's
			// self-owned skip.
			if rerr := s.unbindAndReleaseOwnership(ctx, vm.Name, claimedSriov); rerr != nil {
				slog.Warn("sr-iov resolve rollback: release incomplete", "vm", vm.Name, "error", rerr)
			}
		}
		return nil, e
	}
	kinds := make([]string, len(intents))
	for i, in := range intents {
		kinds[i] = in.SelectorKind
	}
	byIntent := make([][]ResolvedMember, len(intents))
	for _, i := range pciSelectorOrder(kinds) {
		in := intents[i]
		if in.SelectorKind == "sriov" {
			spec := &pb.DeviceSpec{}
			if uerr := protojson.Unmarshal([]byte(in.SelectorPayload), spec); uerr != nil {
				return resolveFail(status.Errorf(codes.Internal,
					"decode SR-IOV selector payload for device %s: %v", in.DeviceID, uerr))
			}
			count := int(spec.Count)
			if count == 0 {
				count = 1
			}
			vfAddrs, aerr := s.allocateSRIOVVFs(ctx, vm.Name, spec, count)
			if aerr != nil {
				return resolveFail(aerr)
			}
			for j, a := range vfAddrs {
				byIntent[i] = append(byIntent[i], ResolvedMember{DeviceID: in.DeviceID, MemberID: fmt.Sprintf("m%d", j), Address: a, Ordinal: j})
				claimedSriov = append(claimedSriov, a)
				selected[a] = true
			}
			continue
		}
		// address / mapping / type: the pure resolver.
		specMembers, rerr := s.resolveIntentsHere(ctx, vm.Name, []corrosion.PCIIntentRecord{in}, selected, local)
		if rerr != nil {
			return resolveFail(rerr)
		}
		byIntent[i] = specMembers
	}
	for _, m := range byIntent {
		members = append(members, m...)
	}

	if len(members) == 0 {
		// Intents that resolved to no members (should not happen — an intent yields ≥1
		// member); nothing to acquire, so start proceeds from the existing definition.
		return func() {}, nil
	}

	// ── Acquire leases: CAS ownership + durable F1 lease + vfio bind ──
	// On a failure acquireDeviceLeases self-cleans every device this start claimed,
	// the SR-IOV VFs claimed above included (passed as its preClaimed), and clears
	// the lease, so nothing is left to release here. acquireClaimed = the addresses
	// this start NEWLY claimed (a self-owned reserve-while-off device is skipped → NOT
	// in it), so the post-acquire rollback below can release exactly what it took.
	finish, acquireClaimed, aerr := s.acquireDeviceLeases(ctx, vm.Name, members, deviceLeaseStageBound, claimedSriov)
	if aerr != nil {
		return nil, aerr
	}

	// The devices freshly claimed DURING THIS START: the VFs CAS-claimed in the resolve
	// phase (claimedSriov) ∪ the members acquire newly claimed (acquireClaimed). A
	// pre-existing self-owned reservation is in NEITHER, so scoping the post-acquire
	// rollback to this set releases only what this start took and RETAINS a
	// reserve-while-off reservation across a transient post-bind failure (FIX-9c). Dedupe
	// defensively (a VF claimed in resolve is self-owned at acquire, so acquire skips it —
	// the sets should not overlap, but a double-release is harmless either way).
	freshlyClaimed := make([]string, 0, len(claimedSriov)+len(acquireClaimed))
	seenFresh := map[string]bool{}
	for _, a := range append(append([]string{}, claimedSriov...), acquireClaimed...) {
		if !seenFresh[a] {
			seenFresh[a] = true
			freshlyClaimed = append(freshlyClaimed, a)
		}
	}

	// ── Persist realizations (CONTRACT g), grouped per device ──
	byDevice := map[string][]ResolvedMember{}
	var deviceOrder []string
	for _, m := range members {
		if _, seen := byDevice[m.DeviceID]; !seen {
			deviceOrder = append(deviceOrder, m.DeviceID)
		}
		byDevice[m.DeviceID] = append(byDevice[m.DeviceID], m)
	}
	rollback := func() error {
		// Release ONLY the devices THIS start freshly claimed — never a pre-existing
		// self-owned reserve-while-off reservation (FIX-9c). A retained self-owned device
		// is absent from freshlyClaimed, so it stays bound + owned = still reserved. Strict
		// (all-or-nothing): if a freshly-claimed member cannot be confirmed unbound, release
		// NOTHING and return the error so the caller leaves the start recovery-required (it
		// stays owned + bound, never unowned + bound). Tombstone realizations only once the
		// release has converged, so a recovery-required rollback keeps this start's rows.
		if rerr := s.unbindAndReleaseOwnership(ctx, vm.Name, freshlyClaimed); rerr != nil {
			return rerr
		}
		// A device the VM keeps owning (it owned it before this start: not in
		// freshlyClaimed) keeps its realization row: retiring it would leave
		// the VM owning a device no row says realizes its intent, which a
		// type selector's next start does not reuse.
		fresh := make(map[string]bool, len(freshlyClaimed))
		for _, a := range freshlyClaimed {
			fresh[a] = true
		}
		for _, dev := range deviceOrder {
			var kept []ResolvedMember
			for _, m := range byDevice[dev] {
				if !fresh[m.Address] {
					kept = append(kept, m)
				}
			}
			var terr error
			switch {
			case len(kept) == 0:
				terr = corrosion.TombstonePCIRealizations(ctx, s.db, vm.Name, dev)
			case len(kept) < len(byDevice[dev]):
				terr = corrosion.ReplacePCIRealizations(ctx, s.db, vm.Name, dev, true, s.realizationRows(vm.Name, dev, kept))
			}
			if terr != nil {
				slog.Warn("pci start-preflight: retire realizations on rollback", "vm", vm.Name, "device", dev, "error", terr)
			}
		}
		return nil
	}
	for _, dev := range deviceOrder {
		if werr := s.replacePCIRealizations(ctx, vm.Name, dev, byDevice[dev]); werr != nil {
			if rbErr := rollback(); rbErr != nil {
				// The release could not confirm the unbind → leave the start recovery-required:
				// do NOT finish() the lease (retain it), propagate so startVMLocked leaves it
				// recoverable. The freshly-claimed member stays owned + bound; retry converges.
				slog.Error("pci start-preflight: rollback release incomplete after realization write failure — left recoverable", "vm", vm.Name, "error", rbErr)
				return nil, status.Errorf(codes.Internal,
					"persist PCI realizations for %q failed and rollback could not release freshly-claimed device(s); left recoverable: %v", vm.Name, werr)
			}
			finish()
			return nil, status.Errorf(codes.Internal, "persist PCI realizations for %q: %v", vm.Name, werr)
		}
	}

	// ── Reconcile the aliased hostdevs into the domain definition ──
	if rerr := s.reconcileDomainDefinition(ctx, vm, members); rerr != nil {
		if rbErr := rollback(); rbErr != nil {
			slog.Error("pci start-preflight: rollback release incomplete after reconcile failure — left recoverable", "vm", vm.Name, "error", rbErr)
			return nil, status.Errorf(codes.Internal,
				"reconcile domain for %q failed and rollback could not release freshly-claimed device(s); left recoverable: %v", vm.Name, rerr)
		}
		finish()
		return nil, rerr
	}

	// Success: the realization rows are the durable record now — clear the F1 lease.
	// The returned release is invoked ONLY if the caller's StartDomain then fails; a
	// release that cannot confirm the unbind leaves the freshly-claimed member owned +
	// bound (recoverable on the operator's start retry), never unowned + bound.
	finish()
	return func() {
		if rbErr := rollback(); rbErr != nil {
			slog.Error("pci start-preflight: post-StartDomain-failure release incomplete — freshly-claimed device(s) left owned+bound (recoverable on retry)", "vm", vm.Name, "error", rbErr)
		}
	}, nil
}

// mergeAddrs returns a followed by each address of b not already in a.
func mergeAddrs(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	seen := make(map[string]bool, len(a)+len(b))
	for _, list := range [][]string{a, b} {
		for _, x := range list {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return out
}

// releaseDevices is the STRICT, HOST-SCOPED whole-VM PCI teardown: for every device
// THIS host records as owned by vmName it consults the ACTUAL vfio driver state
// (IsBoundToVFIO ground truth) and unbinds the ones still bound to vfio-pci, then
// releases ownership PER DEVICE and owner-scoped (ReleasePCIDevice) ONLY if EVERY unbind
// succeeded. If any unbind (or bound-check) failed it releases NOTHING and returns an
// error — the same all-or-nothing invariant unbindAndReleaseOwnership enforces per-member,
// applied to the whole VM set — so a still-bound device is NEVER left unowned-but-vfio-
// bound. A release-WRITE failure after a clean unbind is likewise recoverable: it returns
// the joined error so the caller does not complete over a leaked ownership row (a retry
// converges — an owner-scoped re-release of an already-released row is a 0-row no-op and an
// already-unbound device reads IsBoundToVFIO=false).
//
// It is HOST-SCOPED: it clears ONLY this host's ownership rows (the ones it just unbound).
// A device a stale/migrated VM still owns on a DIFFERENT host is left for THAT host's own
// teardown to release — clearing it here would leave the remote device unowned-but-vfio-
// bound, since this host cannot unbind on the remote host. Cross-host cleanup is each
// involved host's own responsibility.
//
// Both callers treat the error the same: they do NOT proceed past it. The pre-latch stop
// leaves the stop recoverable; VM delete FAILS before tombstoning the vms row (so it never
// leaves a stale owner of a deleted VM — which would block every future claim on that BDF),
// leaving the delete retryable once the operator resolves the stuck device.
func (s *Server) releaseDevices(ctx context.Context, vmName string) error {
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return fmt.Errorf("list devices for release: %w", err)
	}

	var owned []string // THIS host's devices owned by vmName — the exact set to release
	var failures []error
	for _, d := range devices {
		if d.VMName != vmName {
			continue
		}
		owned = append(owned, d.Address)
		bound, berr := vfio.IsBoundToVFIO(d.Address)
		if berr != nil {
			// Cannot prove the binding state → fail closed (treat as an unbind failure) so
			// ownership is never released for a device we cannot confirm is unbound.
			failures = append(failures, fmt.Errorf("check vfio binding for %s: %w", d.Address, berr))
			continue
		}
		if !bound {
			// Not bound → never Unbind it; only clear a stale vfio-pci override.
			if rerr := s.vfioHost().ReleaseUnbound(d.Address); rerr != nil {
				failures = append(failures, rerr)
			}
			continue
		}
		if uerr := s.vfioHost().Unbind(d.Address, d.Driver); uerr != nil {
			failures = append(failures, fmt.Errorf("unbind %s from vfio-pci: %w", d.Address, uerr))
			if vfio.IsBlocked(uerr) {
				break // all-or-nothing: no further bounded waits under the VM lock
			}
		} else {
			// The inventory's Driver is what the last scan saw, which after a rescan
			// of a bound device is "vfio-pci", not where the release put it. Log the
			// driver the device is on now.
			final, ferr := vfio.CurrentDriver(d.Address)
			if ferr != nil {
				final = "unknown: " + ferr.Error()
			} else if final == "" {
				final = "none"
			}
			slog.Info("device unbound from vfio-pci", "address", d.Address, "driver", final)
		}
	}

	if len(failures) > 0 {
		// Release NOTHING: every device stays owned by vmName and the still-bound ones stay
		// bound. This is the invariant that prevents an unowned-but-vfio-bound orphan.
		return fmt.Errorf("pci release: %d device(s) for %q could not be unbound: %w",
			len(failures), vmName, errors.Join(failures...))
	}

	// Every unbind succeeded → release ONLY this host's ownership rows, per device and
	// owner-scoped, so a remote host's rows are never touched. A release-write failure is
	// recoverable (see the doc comment): return the joined error rather than complete over
	// a leaked ownership row.
	var relFailures []error
	for _, addr := range owned {
		if rerr := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); rerr != nil {
			slog.Warn("failed to release PCI device in DB", "vm", vmName, "address", addr, "error", rerr)
			relFailures = append(relFailures, fmt.Errorf("release %s ownership: %w", addr, rerr))
		}
	}
	if len(relFailures) > 0 {
		return fmt.Errorf("pci release: %d device(s) for %q could not be released in DB: %w",
			len(relFailures), vmName, errors.Join(relFailures...))
	}
	return nil
}

// unbindAndReleaseOwnership is the ALL-OR-NOTHING, crash-safe release primitive — the
// SOLE PCI release primitive, used by every op/recovery release site (the attach/start
// rollbacks, lease recovery, and both the live detach and its crash recovery). It
// discriminates bound-ness by the ACTUAL vfio driver state (vfio.IsBoundToVFIO), the
// ground truth — NOT by realization presence,
// which lies after a FIX-9c failed-start rollback that tombstones realizations while
// retaining the binding.
//
// It requires owner == vmName for the NORMAL contract: it first reads host_pci_devices
// ownership (fail-closed — a read error releases NOTHING and returns recoverable, since
// ownership can't be determined) and, in BOTH the unbind and the release loops, ACTS ONLY on
// addrs owned by vmName, SKIPS an unowned/absent addr, and ERRORS on a foreign owner:
//   - owner == vmName → ACT (unbind if bound, then owner-scoped release). Our own member.
//   - owner == "" (unowned) or addr ABSENT from the owner map → SKIP (unbind nothing, release
//     nothing). In every legitimate normal flow the caller acts on its own owned members;
//     an unowned addr was already released (idempotent retry no-op) or was never ours, so the
//     primitive must never unbind a device it cannot prove is vmName's. (The durable-lease-
//     authorized reclaim of a genuinely leaked unowned device lives in the SEPARATE
//     reclaimLeasedDevices primitive — do NOT fold that reclaim back in here.)
//   - owner == a DIFFERENT non-empty VM (foreign) → do NOT unbind, and collect a FOREIGN
//     failure so the whole call returns a non-nil error. A foreign BDF handed to a normal
//     release is a caller/operator bug (e.g. a legacy detach forwarding an operator-supplied
//     BDF), not a success — failing keeps the op recovery-required rather than reporting a
//     bogus success, and NO caller can unbind another live VM's OR an arbitrary unowned device.
//
// This is a no-op for every current legitimate caller (detach/start-rollback/attach-rollback/
// migrate/releaseDevices all pass the VM's own owned members → owner == vmName).
//
// Per owned member: read the vfio driver state; if the device is bound to vfio-pci,
// unbind it (restoring the host driver from host_pci_devices.Driver). A device that is NOT
// bound is skipped — vfio.Unbind on a never-bound device is not a clean no-op (it clears
// driver_override and reprobes). A bound-check FS error counts as a failure.
//
//   - If ANY member's unbind (or bound-check) failed → RELEASE NOTHING (no
//     ReleasePCIDevice) and return the error. Every member stays owned, and the still-
//     bound ones stay bound, so the caller can leave the operation recovery-required. A
//     retry re-reads vfio state: a since-unbound member is skipped and the release
//     converges — never leaving a device unowned-but-vfio-bound.
//   - If every bound member unbound cleanly → owner-release ALL addrs (owner-scoped, a
//     no-op for a device another VM has since claimed). If any release WRITE errors,
//     attempt the rest anyway (a partial release is safe — owner-scoped release is
//     idempotent) and RETURN the joined error so the caller leaves the op recovery-
//     required rather than completing over a leaked, unclaimable ownership row. A retry
//     re-reads vfio state: the already-unbound members are skipped (IsBoundToVFIO=false)
//     and the owner-scoped re-release of an already-released device is a 0-row no-op, so
//     the release converges.
func (s *Server) unbindAndReleaseOwnership(ctx context.Context, vmName string, addrs []string) error {
	// Read host PCI ownership + the host-driver map. This read is the ONLY signal for which of
	// the passed addrs are actually vmName's, so it is fail-closed: if it ERRORS we cannot
	// determine ownership and must NOT act — release NOTHING and return a recoverable error
	// rather than proceed on an empty map and risk unbinding a device another VM owns. (An
	// operator-driven legacy detach forwards a raw BDF straight to this primitive; this
	// ownership scope is what stops it from tearing down a DIFFERENT live VM's passthrough.)
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return fmt.Errorf("pci release: read device ownership for %q: %w", vmName, err)
	}
	drivers := map[string]string{}
	owners := map[string]string{}
	for _, d := range devices {
		drivers[d.Address] = d.Driver
		owners[d.Address] = d.VMName
	}

	var failures []error
	for _, addr := range addrs {
		// Require owner == vmName. An unowned/absent addr is SKIPPED (nothing proven ours);
		// a foreign owner is a FOREIGN failure (fail the whole call). This makes the primitive
		// structurally safe for EVERY caller: it never unbinds another live VM's device NOR an
		// arbitrary unowned device, and a legacy detach that forwards a foreign operator-
		// supplied BDF now errors instead of silently reporting success.
		switch owner := owners[addr]; {
		case owner == vmName:
			// ours — fall through to the vfio act below.
		case owner == "":
			slog.Debug("pci release: skipping unowned/absent addr (not proven ours to unbind)",
				"caller_vm", vmName, "address", addr)
			continue
		default:
			failures = append(failures,
				fmt.Errorf("refusing to release %s: owned by %q, not %q", addr, owner, vmName))
			continue
		}
		bound, berr := vfio.IsBoundToVFIO(addr)
		if berr != nil {
			// Cannot prove the device's binding state → fail closed (treat as an unbind
			// failure) so we never release a device we can't confirm is unbound.
			failures = append(failures, fmt.Errorf("check vfio binding for %s: %w", addr, berr))
			continue
		}
		if !bound {
			// Not bound → never Unbind it; only clear a stale vfio-pci override.
			if rerr := s.vfioHost().ReleaseUnbound(addr); rerr != nil {
				failures = append(failures, rerr)
			}
			continue
		}
		if uerr := s.vfioHost().Unbind(addr, drivers[addr]); uerr != nil {
			failures = append(failures, fmt.Errorf("unbind %s from vfio-pci: %w", addr, uerr))
			if vfio.IsBlocked(uerr) {
				break // all-or-nothing: no further bounded waits under the VM lock
			}
		}
	}

	if len(failures) > 0 {
		// Release NOTHING: a still-bound member stays owned + bound (recoverable). This is
		// the invariant that prevents an unowned-but-vfio-bound orphan.
		return fmt.Errorf("pci release: %d of %d member(s) could not be unbound: %w",
			len(failures), len(addrs), errors.Join(failures...))
	}

	var relFailures []error
	for _, addr := range addrs {
		// Release ONLY addrs owned by vmName — the same subset the unbind loop acted on. An
		// unowned/absent addr has no ownership row of ours to release (skip); a foreign owner
		// can't reach here (it would have short-circuited via failures above).
		if owners[addr] != vmName {
			continue
		}
		if err := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); err != nil {
			slog.Warn("failed to release PCI device in DB", "vm", vmName, "address", addr, "error", err)
			relFailures = append(relFailures, fmt.Errorf("release %s ownership: %w", addr, err))
		}
	}
	if len(relFailures) > 0 {
		// The unbind already succeeded but a release WRITE failed → return recoverable so
		// the caller does NOT tombstone/complete over a leaked ownership row. The retry
		// converges: unbound members are skipped and owner-scoped re-release is a no-op.
		return fmt.Errorf("pci release: %d of %d member(s) could not be released in DB: %w",
			len(relFailures), len(addrs), errors.Join(relFailures...))
	}
	return nil
}

// reclaimGuestMode selects how reclaimLeasedDevices detaches a leased device from the
// guest before unbinding it — chosen by the caller from the VM's live-domain disposition.
type reclaimGuestMode int

const (
	// reclaimNoDomain: the VM row is gone (orphan lease) → no live domain to touch; skip
	// the guest detach and go straight to unbind + owner-scoped release.
	reclaimNoDomain reclaimGuestMode = iota
	// reclaimLive: the domain is running → LIVE|CONFIG membership detach.
	reclaimLive
	// reclaimConfig: the domain is POSITIVELY shut off → CONFIG-only membership detach
	// (the persistent definition), since a live-flagged detach on a shut-off domain is
	// rejected by libvirt.
	reclaimConfig
)

// reclaimLeasedDevices is the durable-lease-authorized RECOVERY primitive — the ONLY
// primitive permitted to reclaim an UNOWNED (owner == "") device. That authorization comes
// SOLELY from its addrs originating in a durable device-lease journal entry: the lease is the
// proof that a dead/rolled-back allocation for vmName leaked these BDFs, so an
// unowned-and-leased addr is a leak this reclaim must clean up. This is exactly what
// unbindAndReleaseOwnership (the NORMAL primitive) must NEVER do — it cannot prove an
// arbitrary unowned addr is anyone's, so it skips it. The two primitives are DELIBERATELY
// separate; do NOT "simplify" them back together, or the normal release paths would regain a
// hole that lets a raw BDF unbind an arbitrary unowned device.
//
// mode tells the primitive which guest-detach to run FIRST, keyed on the live-domain
// DISPOSITION (not merely "the vm row exists"):
//   - reclaimNoDomain (orphan lease, the VM row is gone): no domain to DumpXML → skip the
//     guest detach entirely.
//   - reclaimLive (domain running): LIVE|CONFIG membership detach (detachHostdevIfPresent).
//   - reclaimConfig (domain shut off): CONFIG-only membership detach
//     (detachHostdevConfigIfPresent) — a live-flagged detach a shut-off domain rejects
//     would error and wedge the reclaim.
//
// Per addr (owner read from a fail-closed host_pci_devices read — a read error reclaims
// NOTHING and returns recoverable):
//   - owner == vmName OR owner == "" (unowned/absent) → RECLAIMABLE (ours, or an unowned leak
//     the lease authorizes us to reclaim).
//   - owner == a DIFFERENT non-empty VM → SKIP (the BDF was legitimately reclaimed by another
//     live VM after the lease was written; never touch its passthrough).
//
// For each RECLAIMABLE addr the guest detach (when a domain exists) is membership-aware and
// FAIL-CLOSED on a DumpXML error → return the error so the caller RETAINS the lease and
// retries; never unbind a device still in a live guest. Then unbind-if-bound by the vfio
// ground truth (all-or-nothing: any unbind/bound-check failure reclaims NOTHING and returns
// recoverable) and, ONLY for addrs owned by vmName, owner-scoped ReleasePCIDevice (an unowned
// addr has no ownership row to release — unbinding it is the whole reclaim).
func (s *Server) reclaimLeasedDevices(ctx context.Context, vmName string, addrs []string, mode reclaimGuestMode) error {
	// Fail-closed ownership read: the ONLY signal for which leased addrs are still ours (or
	// unowned) vs since-reclaimed by another VM. On error, reclaim NOTHING (recoverable).
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return fmt.Errorf("pci reclaim: read device ownership for %q: %w", vmName, err)
	}
	drivers := map[string]string{}
	owners := map[string]string{}
	for _, d := range devices {
		drivers[d.Address] = d.Driver
		owners[d.Address] = d.VMName
	}

	// Partition: only addrs owned by this VM (or unowned — the lease authorizes the reclaim)
	// are ours. An addr a DIFFERENT non-empty VM owns was legitimately reclaimed — skip it.
	var reclaimable []string
	for _, addr := range addrs {
		if owner := owners[addr]; owner != "" && owner != vmName {
			slog.Warn("pci reclaim: skipping addr reclaimed by another VM — not ours",
				"lease_vm", vmName, "address", addr, "current_owner", owner)
			continue
		}
		reclaimable = append(reclaimable, addr)
	}

	// Guest detach FIRST (only when a domain still exists), keyed on disposition. Fail
	// closed on a DumpXML error and BEFORE any unbind: a device still in a live guest must
	// never be unbound. A shut-off domain uses the CONFIG-only detach — a live-flagged
	// detach it would reject. Retaining the lease (via the caller's error path) lets a
	// later pass retry.
	switch mode {
	case reclaimLive:
		// Runs in startup device-lease recovery, inside the startup barrier. A
		// paused guest is refused without a wait (detachHostdevIfPresent), and the
		// first device that times out ends the loop, leaving the rest for the
		// next pass.
		for _, addr := range reclaimable {
			if derr := s.detachHostdevIfPresent(ctx, vmName, addr); derr != nil {
				return fmt.Errorf("pci reclaim: guest-detach %s from %q: %w", addr, vmName, derr)
			}
		}
	case reclaimConfig:
		for _, addr := range reclaimable {
			if derr := s.detachHostdevConfigIfPresent(vmName, addr); derr != nil {
				return fmt.Errorf("pci reclaim: config-detach %s from %q: %w", addr, vmName, derr)
			}
		}
	}

	var failures []error
	for _, addr := range reclaimable {
		bound, berr := vfio.IsBoundToVFIO(addr)
		if berr != nil {
			failures = append(failures, fmt.Errorf("check vfio binding for %s: %w", addr, berr))
			continue
		}
		if !bound {
			// Not bound → never Unbind it; only clear a stale vfio-pci override.
			if rerr := s.vfioHost().ReleaseUnbound(addr); rerr != nil {
				failures = append(failures, rerr)
			}
			continue
		}
		if uerr := s.vfioHost().Unbind(addr, drivers[addr]); uerr != nil {
			failures = append(failures, fmt.Errorf("unbind %s from vfio-pci: %w", addr, uerr))
			if vfio.IsBlocked(uerr) {
				break // all-or-nothing: no further bounded waits under the VM lock
			}
		}
	}
	if len(failures) > 0 {
		// All-or-nothing: release NOTHING so a still-bound member stays reclaimable on retry.
		return fmt.Errorf("pci reclaim: %d of %d leased member(s) could not be unbound: %w",
			len(failures), len(reclaimable), errors.Join(failures...))
	}

	var relFailures []error
	for _, addr := range reclaimable {
		// Owner-scoped release ONLY for addrs owned by vmName. An unowned leak has no
		// ownership row to release — the unbind above was the whole reclaim.
		if owners[addr] != vmName {
			continue
		}
		if rerr := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, addr, vmName); rerr != nil {
			slog.Warn("pci reclaim: failed to release PCI device in DB", "vm", vmName, "address", addr, "error", rerr)
			relFailures = append(relFailures, fmt.Errorf("release %s ownership: %w", addr, rerr))
		}
	}
	if len(relFailures) > 0 {
		return fmt.Errorf("pci reclaim: %d leased member(s) for %q could not be released in DB: %w",
			len(relFailures), vmName, errors.Join(relFailures...))
	}
	return nil
}

// checkIOMMUConflict verifies that no device in the same IOMMU group is already
// assigned to a different VM. It fails CLOSED: a device whose group cannot be
// established — the inventory is unreadable, the device is not in it, or it is
// recorded with no group (the IOMMU is off, or the device has none) — is refused
// with the reason, because a device that cannot be isolated may share DMA with
// another VM's device or the host.
//
// The group's members come from the same inventory read as the device itself, so
// the lookup and the conflict check see one snapshot.
func (s *Server) checkIOMMUConflict(ctx context.Context, address, vmName string) error {
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return status.Errorf(codes.Unavailable,
			"refusing PCI passthrough of %s: cannot read host %s's PCI inventory (host_pci_devices) "+
				"to check its IOMMU group: %v; retry once the local database is readable",
			address, s.hostName, err)
	}
	iommuGroup, found := -1, false
	for _, d := range devices {
		if d.Address == address {
			iommuGroup, found = d.IOMMUGroup, true
			break
		}
	}
	if !found {
		return status.Errorf(codes.FailedPrecondition,
			"refusing PCI passthrough of %s: it is not in host %s's PCI inventory, so its IOMMU group "+
				"cannot be checked; confirm the address with `lspci -D` on the host and run `lv host rescan %s`",
			address, s.hostName, s.hostName)
	}
	if iommuGroup < 0 {
		return s.noIOMMUGroupError(address)
	}

	for _, d := range devices {
		if d.IOMMUGroup == iommuGroup && d.VMName != "" && d.VMName != vmName {
			return status.Errorf(codes.FailedPrecondition,
				"IOMMU group %d conflict: device %s is already assigned to VM %q, "+
					"cannot assign device %s from the same group to VM %q",
				iommuGroup, d.Address, d.VMName, address, vmName)
		}
	}
	return nil
}

// noIOMMUGroupError is the refusal for a device the inventory records with no
// IOMMU group. It reads sysfs only to say WHY and what to do; the refusal itself
// does not depend on what sysfs shows.
func (s *Server) noIOMMUGroupError(address string) error {
	prefix := fmt.Sprintf("refusing PCI passthrough of %s on host %s: the PCI inventory records no IOMMU group for it", address, s.hostName)
	groups := pci.IOMMUGroupsPath()
	on, err := pci.IOMMUEnabled()
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"%s, and cannot read %s to tell whether the IOMMU is on: %v; check that the daemon can read sysfs, then run `lv host rescan %s`",
			prefix, groups, err, s.hostName)
	}
	if !on {
		return status.Errorf(codes.FailedPrecondition,
			"%s: the IOMMU is off (%s lists no groups), so the device cannot be isolated from other VMs or the host; "+
				"on Intel, enable VT-d in the firmware and add intel_iommu=on to the kernel command line; "+
				"on AMD, enable IOMMU / AMD-Vi in the firmware and make sure neither amd_iommu=off nor iommu=off is on the kernel command line; "+
				"reboot, then run `lv host rescan %s`",
			prefix, groups, s.hostName)
	}
	link := pci.DeviceIOMMUGroupLink(address)
	if !pci.DeviceInSysfs(address) {
		return status.Errorf(codes.FailedPrecondition,
			"%s, and %s does not exist: the device is no longer present; run `lv host rescan %s`",
			prefix, filepath.Join(pci.SysDevicesPath(), address), s.hostName)
	}
	group, gerr := pci.DeviceIOMMUGroup(address)
	if gerr == nil {
		return status.Errorf(codes.FailedPrecondition,
			"%s, but %s now names group %d: the inventory is stale (scanned before the IOMMU was on); run `lv host rescan %s`",
			prefix, link, group, s.hostName)
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s, and the device has no IOMMU group (%v), so it cannot be isolated; "+
			"check `dmesg | grep -i -e DMAR -e AMD-Vi -e iommu` for why the IOMMU does not cover it, then run `lv host rescan %s`",
		prefix, gerr, s.hostName)
}

// iommuGroupSiblings returns all PCI addresses in the same IOMMU group. A device
// absent from the inventory or recorded with no group yields just itself; an
// inventory read error is returned, never papered over with the device alone.
func (s *Server) iommuGroupSiblings(ctx context.Context, address string) ([]string, error) {
	devices, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return nil, err
	}
	group := -1
	for _, d := range devices {
		if d.Address == address {
			group = d.IOMMUGroup
			break
		}
	}
	if group < 0 {
		return []string{address}, nil
	}
	var addrs []string
	for _, d := range devices {
		if d.IOMMUGroup == group {
			addrs = append(addrs, d.Address)
		}
	}
	return addrs, nil
}

func pciDeviceToProto(d corrosion.PCIDeviceRecord) *pb.PCIDevice {
	var linkPeers []string
	if d.LinkPeers != "" {
		for _, p := range strings.Split(d.LinkPeers, ",") {
			if p = strings.TrimSpace(p); p != "" {
				linkPeers = append(linkPeers, p)
			}
		}
	}
	return &pb.PCIDevice{
		HostName:      d.HostName,
		Address:       d.Address,
		VendorId:      d.VendorID,
		DeviceId:      d.DeviceID,
		VendorName:    d.VendorName,
		DeviceName:    d.DeviceName,
		Type:          d.Type,
		IommuGroup:    int32(d.IOMMUGroup),
		SriovCapable:  d.SRIOVCapable,
		SriovVfsTotal: int32(d.SRIOVVFsTotal),
		SriovVfsFree:  int32(d.SRIOVVFsFree),
		Driver:        d.Driver,
		VmName:        d.VMName,
		NumaNode:      int32(d.NUMANode),
		PcieRootPort:  d.PCIeRootPort,
		PcieBridge:    d.PCIeBridge,
		LinkClique:    d.LinkClique,
		LinkPeers:     linkPeers,
	}
}

// releaseAllocatedDevices gives back the devices a create or restore
// allocated when it fails with its domain provably not running: the owner is
// cleared and the device leaves vfio-pci, through the owner-scoped release
// (an address no longer the VM's is skipped, another VM's is never touched).
// A release that fails is logged and left to the stranded-ownership sweep.
func (s *Server) releaseAllocatedDevices(ctx context.Context, op, vmName string, addrs []string) {
	if len(addrs) == 0 {
		return
	}
	if err := s.unbindAndReleaseOwnership(context.WithoutCancel(ctx), vmName, addrs); err != nil {
		slog.Warn("pci: a failed "+op+" could not give its devices back; the stranded-ownership sweep releases them",
			"vm", vmName, "addresses", addrs, "error", err)
		return
	}
	slog.Info("pci: devices of a failed "+op+" released", "vm", vmName, "addresses", addrs)
}

// deviceSpecsSummary names each requested device for an operator message:
// its address, or its mapping, or its type/vendor/model, with a count over 1.
func deviceSpecsSummary(specs []*pb.DeviceSpec) string {
	parts := make([]string, 0, len(specs))
	for _, d := range specs {
		var f []string
		switch {
		case d.GetAddress() != "":
			f = append(f, d.GetAddress())
		case d.GetMapping() != "":
			f = append(f, "mapping="+d.GetMapping())
		}
		if d.GetAddress() == "" {
			for _, kv := range [][2]string{{"type", d.GetType()}, {"vendor", d.GetVendor()}, {"model", d.GetModel()}} {
				if kv[1] != "" {
					f = append(f, kv[0]+"="+kv[1])
				}
			}
			if d.GetSriov() {
				f = append(f, "sriov")
			}
		}
		if d.GetCount() > 1 {
			f = append(f, fmt.Sprintf("count=%d", d.GetCount()))
		}
		parts = append(parts, strings.Join(f, " "))
	}
	return strings.Join(parts, ", ")
}

// ownedRealizationsHere is the devices on this host that realize vmName's
// intent deviceID, by its live vm_pci_realizations rows, and that the VM
// still owns, in member order. A row the VM no longer owns there (released,
// or another VM's since) is not its device.
func (s *Server) ownedRealizationsHere(ctx context.Context, vmName, deviceID string) ([]corrosion.PCIDeviceRecord, error) {
	reals, err := corrosion.ListVMPCIRealizations(ctx, s.db, vmName)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read the PCI realizations of %s: %v", vmName, err)
	}
	var mine []corrosion.PCIRealizationRecord
	for _, r := range reals {
		if r.DeviceID == deviceID && r.HostName == s.hostName && r.ResolvedAddress != "" {
			mine = append(mine, r)
		}
	}
	if len(mine) == 0 {
		return nil, nil
	}
	sort.Slice(mine, func(i, j int) bool { return mine[i].Ordinal < mine[j].Ordinal })
	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return nil, status.Errorf(codes.Internal, "query devices: %v", err)
	}
	byAddr := make(map[string]corrosion.PCIDeviceRecord, len(devs))
	for _, d := range devs {
		byAddr[d.Address] = d
	}
	var out []corrosion.PCIDeviceRecord
	for _, r := range mine {
		if d, ok := byAddr[r.ResolvedAddress]; ok && d.VMName == vmName {
			out = append(out, d)
		}
	}
	return out, nil
}

// replacePCIRealizations makes members the live realization set of vmName's
// intent deviceID. When the set of member ids changed (the intent took a group
// sibling before and does not now, or the other way round), the old rows are
// tombstoned first: an upsert alone would leave the extra member live, and the
// next reconcile would refuse the intent for a realized set larger than what
// it resolves to. Tombstone and upserts are one batch
// (corrosion.ReplacePCIRealizations), so a crash cannot leave the intent with
// no live row while the VM still owns its device.
func (s *Server) replacePCIRealizations(ctx context.Context, vmName, deviceID string, members []ResolvedMember) error {
	reals, err := corrosion.ListVMPCIRealizations(ctx, s.db, vmName)
	if err != nil {
		return fmt.Errorf("read PCI realizations of %s: %w", vmName, err)
	}
	want := make(map[string]bool, len(members))
	for _, m := range members {
		want[m.MemberID] = true
	}
	have := map[string]bool{}
	for _, r := range reals {
		if r.DeviceID == deviceID {
			have[r.MemberID] = true
		}
	}
	changed := len(have) > 0 && len(have) != len(want)
	for id := range have {
		changed = changed || !want[id]
	}
	if err := corrosion.ReplacePCIRealizations(ctx, s.db, vmName, deviceID, changed, s.realizationRows(vmName, deviceID, members)); err != nil {
		return fmt.Errorf("record PCI realizations of %s/%s: %w", vmName, deviceID, err)
	}
	return nil
}

// realizationRows is members as this host's realization rows of vmName's
// intent deviceID.
func (s *Server) realizationRows(vmName, deviceID string, members []ResolvedMember) []corrosion.PCIRealizationRecord {
	rows := make([]corrosion.PCIRealizationRecord, 0, len(members))
	for _, m := range members {
		rows = append(rows, corrosion.PCIRealizationRecord{VMName: vmName, DeviceID: deviceID, MemberID: m.MemberID, HostName: s.hostName,
			ResolvedAddress: m.Address, XMLAlias: pciMemberAlias(deviceID, m.MemberID), Ordinal: m.Ordinal})
	}
	return rows
}
