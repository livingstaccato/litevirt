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

const diskNICIORefusal = "disk discard, I/O limits and NIC queues cannot be set yet: an older host would ignore " +
	"or drop them, so the cluster upgrade must finish first (not every host is known to keep them)"

// ioFeatureToken is a PLACEHOLDER for the shared release token ("this build
// preserves the new spec fields"), which is not registered in the capabilities
// package: nothing latches it, so until the swap the feature stays refused in a
// real cluster (fail closed). Tests latch it with a wrapping gate.
const ioFeatureToken = "vm_disk_nic_io_v1"

// ioFeatureGate is the one place the disk/NIC tuning feature asks whether the
// whole cluster keeps and re-applies it: nil when it does, else the
// FailedPrecondition every refusal returns. Swapping in the shared release
// token is a change to this function's body alone.
func (s *Server) ioFeatureGate(ctx context.Context) error {
	if s.gate != nil && s.gate.Enforced(ctx, ioFeatureToken) {
		return nil
	}
	return status.Error(codes.FailedPrecondition, diskNICIORefusal)
}

// diskNICIOActive reports whether ioFeatureGate lets the feature through.
func (s *Server) diskNICIOActive(ctx context.Context) bool { return s.ioFeatureGate(ctx) == nil }

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
	if s.diskNICIOActive(ctx) {
		return nil
	}
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
			return status.Errorf(codes.FailedPrecondition, "vm %q: %s", name, diskNICIORefusal)
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
	applied, _, merr := corrosion.MutateDesiredSpec(ctx, s.db, req.VmName, func(old string) (string, error) {
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

// restrictRestoredTuning is the gate for a spec that did not come from a
// validated create: a backup manifest or a promoted record. Before the gate
// opens the tuning is STRIPPED (a restore main allows still works; older peers
// would drop the fields anyway) and stripped=true says so; after it the values
// are validated like a create's, so a hand-edited manifest cannot define a
// domain libvirt refuses or open hundreds of queues.
func (s *Server) restrictRestoredTuning(ctx context.Context, spec *pb.VMSpec) (stripped bool, err error) {
	if !specSetsDiskNICIO(spec) {
		return false, nil
	}
	if s.ioFeatureGate(ctx) != nil {
		for _, d := range spec.Disks {
			d.Discard, d.DetectZeroes, d.Io = "", "", nil
		}
		for _, n := range spec.Network {
			n.Queues = 0
		}
		slog.Warn("restore: the spec carries disk/NIC tuning and the cluster upgrade has not finished: tuning dropped", "vm", spec.GetName())
		return true, nil
	}
	if err := validateSpecTuning(spec); err != nil {
		return false, status.Errorf(codes.InvalidArgument, "restored spec: %v", err)
	}
	return false, nil
}

// requestsHardwareTuning reports whether an UpdateVM request redefines the
// domain for disk/NIC tuning: its payload, or the explicit regenerate flag.
func requestsHardwareTuning(req *pb.UpdateVMRequest) bool {
	return req.GetRedefineHardware() || len(req.GetDiskTuning()) > 0 || len(req.GetNicQueues()) > 0
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
