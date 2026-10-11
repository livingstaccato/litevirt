package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// validateSpecTuning normalizes and checks a create's per-disk tuning
// (discard on/off spellings, detect_zeroes, I/O throttle) and NIC queues, so a
// bad value is refused before anything is created. The spec is normalized in
// place: it is the copy CreateVM persists.
func validateSpecTuning(spec *pb.VMSpec) error {
	for _, d := range spec.GetDisks() {
		if d == nil {
			continue
		}
		d.Discard = compose.NormalizeDiscard(d.Discard)
		if err := compose.ValidateDiskTuning(d); err != nil {
			return fmt.Errorf("disk %q: %w", d.Name, err)
		}
	}
	for i, n := range spec.GetNetwork() {
		if err := compose.ValidateQueues(n.GetModel(), n.GetQueues()); err != nil {
			return fmt.Errorf("network %d: %w", i, err)
		}
	}
	return nil
}

// ioFeatureGate is the entry-node check of the disk/NIC tuning feature
// (capabilities.FeatureVMDiskNICIO): nil when its release token has latched,
// else the release gate's refusal (the hosts still to upgrade with their
// versions, and `lv cluster upgrade-status`). It drives the latch, so a call
// made just after the last host upgraded succeeds without waiting for the HA
// monitor, but records and grants nothing (Server.ReleaseFeatureRefusal): a
// request that later fails leaves no used record. The node that WRITES the
// tuning runs the real gate and takes the grant itself (ioGrant), so a
// forwarded request is gated there.
func (s *Server) ioFeatureGate(ctx context.Context) error {
	return s.ReleaseFeatureRefusal(ctx, capabilities.FeatureVMDiskNICIO)
}

// ioGrant runs the feature's gate on THIS node, the one that will write the
// tuning, and returns the grant its writers take. A refusal is the release
// gate's error, unchanged.
func (s *Server) ioGrant(ctx context.Context) (capabilities.FeatureGrant, error) {
	var g capabilities.FeatureGrant
	err := s.WithReleaseFeature(ctx, capabilities.FeatureVMDiskNICIO,
		func(_ context.Context, got capabilities.FeatureGrant) error { g = got; return nil })
	return g, err
}

// ioGrantIfUsed is ioGrant for a write that must never perform the feature's
// FIRST use: the default discard of a plain create. ok is true only when the
// token has latched here AND the feature is already recorded used and
// acknowledged in this replica (a local read, no peer). A plain create then
// never triggers or waits on the first-use protocol, however degraded the
// cluster, and behaves as main until an operator (or a restore) has used the
// feature.
func (s *Server) ioGrantIfUsed(ctx context.Context) (g capabilities.FeatureGrant, ok bool) {
	if !s.ReleaseFeatureAvailable(capabilities.FeatureVMDiskNICIO) {
		return g, false
	}
	present, acked, err := corrosion.ReleaseFeatureState(ctx, s.db, featureToken(capabilities.FeatureVMDiskNICIO), string(capabilities.FeatureVMDiskNICIO))
	if err != nil || !present || !acked {
		return g, false
	}
	g, err = s.ioGrant(ctx)
	return g, err == nil
}

// specSetsDiskNICIO reports whether a spec sets discard, detect_zeroes, a disk
// throttle (an empty one included: it is a clear, which only means something
// to a spec that has one) or NIC queues.
func specSetsDiskNICIO(spec *pb.VMSpec) bool {
	for _, d := range spec.GetDisks() {
		if d.GetDiscard() != "" || d.GetDetectZeroes() != "" || compose.IOLimitsSet(d.GetIo()) {
			return true
		}
	}
	for _, n := range spec.GetNetwork() {
		if n.GetQueues() != 0 {
			return true
		}
	}
	return false
}

// refuseUnlatchedDiskNICIO is the entry-node gate: a spec that sets any of them
// is refused until the token has latched, before anything is created or
// forwarded. A spec that sets none passes, so the cluster behaves as before.
func (s *Server) refuseUnlatchedDiskNICIO(ctx context.Context, spec *pb.VMSpec) error {
	if specSetsDiskNICIO(spec) {
		return s.ioFeatureGate(ctx)
	}
	return nil
}

// refuseUnlatchedStackDiskNICIO refuses a compose file that sets any of them,
// up front, rather than by the Nth VM's create after N-1 are up.
func (s *Server) refuseUnlatchedStackDiskNICIO(ctx context.Context, f *compose.File) error {
	// The scan comes first: a file that sets no tuning never asks the gate, so a
	// plain deploy mid-roll pings nobody. The check runs once, for the first VM
	// that does.
	for name, vm := range f.VMs {
		if vm.IsContainer() {
			continue
		}
		set := false
		for _, d := range vm.Disks {
			set = set || d.Discard != "" || d.DetectZeroes != "" || (d.IOTune != nil && *d.IOTune != (compose.IOTuneDef{}))
		}
		for _, n := range vm.Network {
			set = set || !n.Queues.IsZero()
		}
		if set {
			if gateErr := s.ioFeatureGate(ctx); gateErr != nil {
				return status.Errorf(codes.FailedPrecondition, "vm %q: %s", name, status.Convert(gateErr).Message())
			}
			return nil
		}
	}
	return nil
}

// defaultDiscard is the discard a NEW disk gets when its spec leaves it unset:
// "unmap" on thin-capable storage and a bus that carries TRIM, nothing
// otherwise. It is stored in the spec at create, so it is a property of that
// VM from then on — a VM created before this existed keeps rendering no
// discard, and a later change of the default moves no existing guest.
func defaultDiscard(storageType, bus string) string {
	if storage.DiscardDefault(storageType) && lv.DiscardCapableBus(bus) {
		return lv.DiscardUnmap
	}
	return ""
}

// SetDiskIO replaces one disk's I/O throttle. A running VM is throttled live
// (libvirt blkdeviotune) and the persistent definition updated; the limits are
// also stored in the VM's spec, which is what a restart, a redefine, a failover
// start and a migration destination render from.
func (s *Server) SetDiskIO(ctx context.Context, req *pb.SetDiskIORequest) (*pb.VM, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if req.GetVmName() == "" || req.GetDiskName() == "" {
		return nil, status.Error(codes.InvalidArgument, "vm_name and disk_name are required")
	}
	tune := compose.IOTuneFromSpec(req.Limits)
	if err := tune.Validate(); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// Setting a limit waits for the latch, at the entry node, before the call is
	// forwarded; clearing (nothing set) does not.
	if !tune.IsZero() {
		if err := s.ioFeatureGate(ctx); err != nil {
			return nil, err
		}
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if err := s.RequirePerm(ctx, vmRBACPath(vm), "vm.update", "operator"); err != nil {
		return nil, err
	}
	// Forward to the owner BEFORE taking the local lock.
	if vm.HostName != s.hostName {
		client, conn, err := s.peerClient(ctx, vm.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "cannot reach host %s: %v", vm.HostName, err)
		}
		defer conn.Close()
		return client.SetDiskIO(ctx, req)
	}
	if s.virt == nil {
		return nil, status.Errorf(codes.Internal, "libvirt not connected on host %s", s.hostName)
	}

	unlock := s.lockVM(req.VmName)
	defer unlock()
	vm, err = corrosion.GetVM(ctx, s.db, req.VmName)
	if err != nil || vm == nil {
		return nil, status.Errorf(codes.NotFound, "VM %q not found", req.VmName)
	}
	if vm.HostName != s.hostName {
		return nil, status.Errorf(codes.Aborted, "ownership of %q moved to %s mid-operation; retry", req.VmName, vm.HostName)
	}
	if vm.ActiveOperationID != "" {
		return nil, status.Errorf(codes.FailedPrecondition,
			"cannot set I/O limits for %q: an operation is in progress", req.VmName)
	}

	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		return nil, status.Errorf(codes.Internal, "parse VM spec: %v", err)
	}
	key := compose.DiskKey(req.DiskName)
	diskIdx := -1
	bus := ""
	for i, d := range spec.Disks {
		if compose.DiskKey(d.GetName()) == key {
			diskIdx, bus = i, d.GetBus()
			break
		}
	}
	dev := ""
	recs, rerr := corrosion.GetVMDisks(ctx, s.db, req.VmName)
	if rerr != nil {
		return nil, status.Errorf(codes.Internal, "list disks: %v", rerr)
	}
	var rec *corrosion.DiskRecord
	for i := range recs {
		if compose.DiskKey(recs[i].DiskName) == key && (recs[i].DeviceKind == "" || recs[i].DeviceKind == "disk") {
			rec = &recs[i]
			break
		}
	}
	switch {
	case diskIdx < 0 && rec == nil:
		return nil, status.Errorf(codes.NotFound, "VM %q has no disk %q", req.VmName, req.DiskName)
	case diskIdx < 0:
		// The spec does not list a disk vm_disks has (an implicit root disk, a
		// hot-plugged one): the entry is made when the limits are recorded, so
		// every later render carries them.
		bus = rec.Bus
	}
	if bus == "" {
		bus = "virtio"
	}
	switch {
	case rec != nil && rec.TargetDev != "":
		dev = rec.TargetDev
	case diskIdx >= 0:
		dev = lv.DiskDevName(bus, diskIdx)
	default:
		dev = lv.DiskDevName(bus, len(spec.Disks))
	}

	// Setting a limit adds tuning to the spec: this node writes it, so it takes
	// the feature's grant before anything is changed (a forwarded call is gated
	// here, not on the entry node). Clearing adds nothing and takes none.
	var grant capabilities.FeatureGrant
	if !tune.IsZero() {
		g, gerr := s.ioGrant(ctx)
		if gerr != nil {
			return nil, gerr
		}
		grant = g
	}

	// What the disk has now, so a partial failure can put it back.
	oldCfg, haveCfg := ioTuneNow(s.virt.DumpXMLInactive, req.VmName, dev)
	restore := func(why string) {
		if !haveCfg {
			slog.Error("SetDiskIO: the previous limits could not be read, so a failed step cannot be undone — the definition may hold limits the spec does not",
				"vm", req.VmName, "disk", req.DiskName, "after", why)
			return
		}
		if rerr := s.virt.SetDiskIOTune(req.VmName, dev, oldCfg); rerr != nil {
			slog.Error("SetDiskIO: restoring the previous limits failed — the definition may hold limits the spec does not",
				"vm", req.VmName, "disk", req.DiskName, "after", why, "error", rerr)
		}
	}

	// libvirt first: a spec that says "limited" while the disk is not would be
	// worse than a refusal. A stopped VM whose domain is not defined has nothing
	// to throttle yet; its next define renders the spec.
	if err := s.virt.SetDiskIOTune(req.VmName, dev, tune); err != nil {
		if !(lv.IsNotFound(err) && vm.State != "running") {
			restore("a failed set")
			if !haveCfg {
				return nil, status.Errorf(codes.Internal, "set I/O limits failed and the previous limits could not be read to put them back, so the definition may have changed: %v", err)
			}
			return nil, status.Errorf(codes.Internal, "set I/O limits (the previous limits were kept): %v", err)
		}
	}
	if s.ioSpecWriteHook != nil {
		s.ioSpecWriteHook()
	}

	var stored *pb.DiskIOLimits
	if !tune.IsZero() {
		stored = proto.Clone(req.Limits).(*pb.DiskIOLimits)
	}
	mutate := corrosion.MutateDesiredSpec
	if !tune.IsZero() {
		mutate = func(ctx context.Context, c *corrosion.Client, name string, fn func(string) (string, error)) (bool, int64, error) {
			return corrosion.MutateDesiredSpecTuning(ctx, c, grant, name, fn)
		}
	}
	applied, _, merr := mutate(ctx, s.db, req.VmName, func(old string) (string, error) {
		fresh := &pb.VMSpec{}
		if old != "" {
			if uerr := json.Unmarshal([]byte(old), fresh); uerr != nil {
				return "", uerr
			}
		}
		found := false
		for _, d := range fresh.Disks {
			if compose.DiskKey(d.GetName()) == key {
				d.Io, found = stored, true
			}
		}
		if !found {
			fresh.Disks = append(fresh.Disks, &pb.DiskSpec{Name: key, Bus: bus, Io: stored})
		}
		b, jerr := json.Marshal(fresh)
		return string(b), jerr
	})
	if merr != nil || !applied {
		restore("a failed spec write")
		if !haveCfg {
			return nil, status.Errorf(codes.Internal, "I/O limits were applied but not recorded in %q's spec, and the previous limits could not be read to take them back: %v", req.VmName, merr)
		}
		if merr != nil {
			return nil, status.Errorf(codes.Internal, "I/O limits were not recorded in %q's spec, so they were taken back: %v", req.VmName, merr)
		}
		return nil, status.Errorf(codes.FailedPrecondition,
			"I/O limits were not recorded in %q's spec because an operation is in progress, so they were taken back; set them again once it ends", req.VmName)
	}

	slog.Info("disk I/O limits set", "vm", req.VmName, "disk", req.DiskName, "dev", dev, "cleared", tune.IsZero())
	s.recordVMEvent(ctx, req.VmName, "disk.io", "ok", req.DiskName)
	return s.vmToProto(ctx, req.VmName)
}

// ioTuneNow reads the throttle a domain definition carries for dev.
func ioTuneNow(dump func(string) (string, error), vm, dev string) (lv.IOTune, bool) {
	x, err := dump(vm)
	if err != nil {
		return lv.IOTune{}, false
	}
	return lv.DiskIOTuneFromXML(x, dev)
}

// applyDesiredDiskIO applies, through SetDiskIO, every disk throttle the
// desired spec names that differs from the stored one. SetDiskIO forwards to the
// owning host and records each in the spec itself.
func (s *Server) applyDesiredDiskIO(ctx context.Context, name string, desired *pb.VMSpec) error {
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", name)
	}
	stored := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), stored); err != nil {
			return status.Errorf(codes.Internal, "parse stored spec for %q: %v", name, err)
		}
	}
	storedByName := map[string]*pb.DiskSpec{}
	for _, d := range stored.Disks {
		if d != nil {
			storedByName[compose.DiskKey(d.Name)] = d
		}
	}
	for _, d := range desired.Disks {
		if d == nil || d.Io == nil {
			continue
		}
		var cur *pb.DiskIOLimits
		if sd, ok := storedByName[compose.DiskKey(d.Name)]; ok {
			cur = sd.Io
		}
		if compose.IOTuneFromSpec(cur) == compose.IOTuneFromSpec(d.Io) {
			continue
		}
		if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: name, DiskName: compose.DiskKey(d.Name), Limits: d.Io}); err != nil {
			return fmt.Errorf("disk %s I/O limits: %w", d.Name, err)
		}
	}
	return nil
}

// applyTuningRequest merges an UpdateVM request's discard / detect_zeroes and
// queue changes into spec, validating the result. It touches only the in-memory
// spec: the owner writes it after the domain has the setting. A disk the spec
// does not list but vm_disks has gets its entry made here.
func applyTuningRequest(spec *pb.VMSpec, dbDisks []corrosion.DiskRecord, req *pb.UpdateVMRequest) error {
	for _, u := range req.GetDiskTuning() {
		key := compose.DiskKey(u.GetName())
		var d *pb.DiskSpec
		for _, c := range spec.Disks {
			if compose.DiskKey(c.GetName()) == key {
				d = c
				break
			}
		}
		if d == nil {
			for _, r := range dbDisks {
				if compose.DiskKey(r.DiskName) == key && (r.DeviceKind == "" || r.DeviceKind == "disk") {
					d = &pb.DiskSpec{Name: key, Bus: r.Bus}
					spec.Disks = append(spec.Disks, d)
					break
				}
			}
		}
		if d == nil {
			return status.Errorf(codes.NotFound, "VM %q has no disk %q", spec.GetName(), u.GetName())
		}
		if v := compose.NormalizeDiscard(u.GetDiscard()); v != "" {
			d.Discard = v
		}
		if v := strings.ToLower(strings.TrimSpace(u.GetDetectZeroes())); v != "" {
			d.DetectZeroes = v
		}
		if err := compose.ValidateDiskTuning(d); err != nil {
			return status.Errorf(codes.InvalidArgument, "disk %q: %v", u.GetName(), err)
		}
	}
	for _, u := range req.GetNicQueues() {
		i := int(u.GetOrdinal())
		if i < 0 || i >= len(spec.Network) {
			return status.Errorf(codes.NotFound, "VM %q has no NIC %d in its spec", spec.GetName(), i)
		}
		if err := compose.ValidateQueues(spec.Network[i].GetModel(), u.GetQueues()); err != nil {
			return status.Errorf(codes.InvalidArgument, "NIC %d: %v", i, err)
		}
		spec.Network[i].Queues = u.GetQueues()
	}
	return nil
}

// restoredTuning is what restrictRestoredTuning decided for a restored or
// promoted spec.
type restoredTuning struct {
	// stripped: the spec's tuning was dropped.
	stripped bool
	// grant is the feature's grant when the tuning is kept: the row this spec is
	// written to must go through insertVMWithGrants with it.
	grant capabilities.FeatureGrant
	// refused is the gate's error when the token HAD latched but the gate still
	// refused (a first use that could not be acknowledged, a host rolled back
	// after the latch). Nil when the strip is only "the upgrade has not finished".
	refused error
}

// why words the strip for a progress line or a log: the two causes differ.
func (r restoredTuning) why() string {
	if r.refused != nil {
		return "the disk/NIC feature gate refused after the latch: " + status.Convert(r.refused).Message()
	}
	return "the cluster upgrade has not finished"
}

// auditDropped writes the audit row for a strip caused by a refusal after the
// latch. It is called by the restore or promote ONLY once that operation can no
// longer be refused, and with the VM's actual name (--new-name included), so a
// restore that fails later leaves no row and a renamed one names the right VM.
func (s *Server) auditTuningDropped(ctx context.Context, r restoredTuning, vm, op string) {
	if r.refused == nil || !r.stripped {
		return
	}
	s.audit(ctx, "vm.tuning_dropped", vm, op+": disk/NIC tuning dropped: "+r.why(), "degraded")
}

// restrictRestoredTuning is the gate for a spec that did not come from a
// validated create: a backup manifest or a promoted record. When the token has
// not latched, or has latched but the feature's gate refuses, the tuning is
// STRIPPED (a restore main allows is never refused; older peers would drop the
// fields anyway), a warning is logged and the result says which it was; when the
// gate opens the values are validated like a create's, so a hand-edited
// manifest cannot define a domain libvirt refuses or open hundreds of queues.
func (s *Server) restrictRestoredTuning(ctx context.Context, spec *pb.VMSpec) (restoredTuning, error) {
	var r restoredTuning
	if !specSetsDiskNICIO(spec) {
		return r, nil
	}
	if s.ReleaseFeatureAvailable(capabilities.FeatureVMDiskNICIO) {
		g, gerr := s.ioGrant(ctx)
		if gerr == nil {
			if err := validateSpecTuning(spec); err != nil {
				return r, status.Errorf(codes.InvalidArgument, "restored spec: %v", err)
			}
			r.grant = g
			return r, nil
		}
		r.refused = gerr
	}
	for _, d := range spec.Disks {
		d.Discard, d.DetectZeroes, d.Io = "", "", nil
	}
	for _, n := range spec.Network {
		n.Queues = 0
	}
	r.stripped = true
	slog.Warn("restored spec: disk/NIC tuning dropped", "vm", spec.GetName(), "why", r.why())
	return r, nil
}

// requestsHardwareTuning reports whether an UpdateVM request redefines the
// domain for disk/NIC tuning: its payload, or the explicit regenerate flag.
func requestsHardwareTuning(req *pb.UpdateVMRequest) bool {
	return req.GetRedefineHardware() || len(req.GetDiskTuning()) > 0 || len(req.GetNicQueues()) > 0
}

// requestsTuningWrite reports whether an UpdateVM adds tuning to the stored
// spec: its payload, or a hardware redefine of a VM whose spec already carries
// tuning. A redefine of an untuned VM writes none and needs no gate.
func requestsTuningWrite(req *pb.UpdateVMRequest, storedSpec string) bool {
	if len(req.GetDiskTuning()) > 0 || len(req.GetNicQueues()) > 0 {
		return true
	}
	if !req.GetRedefineHardware() || storedSpec == "" {
		return false
	}
	st := &pb.VMSpec{}
	return json.Unmarshal([]byte(storedSpec), st) == nil && specSetsDiskNICIO(st)
}

// patchTuningInPlace applies a request's discard / detect_zeroes / queue
// changes to the persistent definition by patching it (the merged spec holds the
// final values), so the addresses libvirt assigned are not reshuffled.
func patchTuningInPlace(x string, req *pb.UpdateVMRequest, spec *pb.VMSpec, disks []lv.DiskConfig, ifaces []corrosion.InterfaceRecord) (string, error) {
	var err error
	for _, u := range req.GetDiskTuning() {
		key := compose.DiskKey(u.GetName())
		var sd *pb.DiskSpec
		for _, d := range spec.Disks {
			if compose.DiskKey(d.GetName()) == key {
				sd = d
			}
		}
		dev := ""
		for i, dc := range disks {
			if compose.DiskKey(dc.Name) == key {
				if dev = dc.TargetDev; dev == "" {
					dev = lv.DiskDevName(dc.Bus, i)
				}
			}
		}
		if sd == nil || dev == "" {
			return "", fmt.Errorf("disk %q not found for an in-place patch", u.GetName())
		}
		if x, err = lv.PatchInactiveDiskDriver(x, dev, sd.Discard, sd.DetectZeroes); err != nil {
			return "", err
		}
	}
	for _, u := range req.GetNicQueues() {
		mac := ""
		if o := int(u.GetOrdinal()); o >= 0 && o < len(spec.Network) {
			mac = spec.Network[o].GetMac()
		}
		if mac == "" {
			for _, ic := range ifaces {
				if ic.Ordinal == int(u.GetOrdinal()) {
					mac = ic.MAC
				}
			}
		}
		if mac == "" {
			return "", fmt.Errorf("NIC %d has no MAC to patch by", u.GetOrdinal())
		}
		if x, err = lv.PatchInactiveNICQueues(x, mac, int(spec.Network[u.GetOrdinal()].GetQueues())); err != nil {
			return "", err
		}
	}
	return x, nil
}
