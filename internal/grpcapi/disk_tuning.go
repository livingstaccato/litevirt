package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

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
	var disk *pb.DiskSpec
	diskIdx := -1
	for i, d := range spec.Disks {
		name := d.GetName()
		if name == "" {
			name = "root"
		}
		if name == req.DiskName {
			disk, diskIdx = d, i
			break
		}
	}
	if disk == nil {
		return nil, status.Errorf(codes.NotFound,
			"disk %q is not in %q's spec (I/O limits are kept in the spec, so a disk hot-plugged onto the VM cannot carry them)",
			req.DiskName, req.VmName)
	}
	bus := disk.Bus
	if bus == "" {
		bus = "virtio"
	}
	dev := lv.DiskDevName(bus, diskIdx)
	if recs, rerr := corrosion.GetVMDisks(ctx, s.db, req.VmName); rerr == nil {
		for _, r := range recs {
			if r.DiskName == req.DiskName && r.TargetDev != "" {
				dev = r.TargetDev
				break
			}
		}
	}

	// libvirt first: a spec that says "limited" while the disk is not would be
	// worse than a refusal. A stopped VM whose domain is not defined has nothing
	// to throttle yet; its next define renders the spec.
	if err := s.virt.SetDiskIOTune(req.VmName, dev, tune); err != nil {
		if !(lv.IsNotFound(err) && vm.State != "running") {
			return nil, status.Errorf(codes.Internal, "set I/O limits: %v", err)
		}
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
		for _, d := range fresh.Disks {
			name := d.GetName()
			if name == "" {
				name = "root"
			}
			if name == req.DiskName {
				d.Io = stored
			}
		}
		b, jerr := json.Marshal(fresh)
		return string(b), jerr
	})
	if merr != nil {
		return nil, status.Errorf(codes.Internal,
			"I/O limits applied to %q but not recorded in its spec: %v (a redefine would lose them; set them again)", req.VmName, merr)
	}
	if !applied {
		return nil, status.Errorf(codes.FailedPrecondition,
			"I/O limits applied to %q but not recorded in its spec: an operation is in progress (set them again once it ends)", req.VmName)
	}

	slog.Info("disk I/O limits set", "vm", req.VmName, "disk", req.DiskName, "dev", dev, "cleared", tune.IsZero())
	s.recordVMEvent(ctx, req.VmName, "disk.io", "ok", req.DiskName)
	return s.vmToProto(ctx, req.VmName)
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
			storedByName[d.Name] = d
		}
	}
	for _, d := range desired.Disks {
		if d == nil || d.Io == nil {
			continue
		}
		if sd, ok := storedByName[d.Name]; ok && compose.IOTuneFromSpec(sd.Io) == compose.IOTuneFromSpec(d.Io) {
			continue
		}
		if _, err := s.SetDiskIO(ctx, &pb.SetDiskIORequest{VmName: name, DiskName: d.Name, Limits: d.Io}); err != nil {
			return fmt.Errorf("disk %s I/O limits: %w", d.Name, err)
		}
	}
	return nil
}

// persistHardwareTuning writes the desired spec's disk discard / detect_zeroes
// and NIC queues into the stored spec, ahead of the redefine that renders them.
// A value the desired spec leaves unset keeps what is stored.
func (s *Server) persistHardwareTuning(ctx context.Context, name string, desired *pb.VMSpec) error {
	applied, _, err := corrosion.MutateDesiredSpec(ctx, s.db, name, func(old string) (string, error) {
		fresh := &pb.VMSpec{}
		if old != "" {
			if uerr := json.Unmarshal([]byte(old), fresh); uerr != nil {
				return "", uerr
			}
		}
		byName := map[string]*pb.DiskSpec{}
		for _, d := range desired.Disks {
			if d != nil {
				byName[d.Name] = d
			}
		}
		for _, d := range fresh.Disks {
			dd, ok := byName[d.Name]
			if !ok {
				continue
			}
			if dd.Discard != "" {
				d.Discard = dd.Discard
			}
			if dd.DetectZeroes != "" {
				d.DetectZeroes = dd.DetectZeroes
			}
		}
		for i, n := range fresh.Network {
			if i < len(desired.Network) && desired.Network[i].GetQueues() != 0 {
				n.Queues = desired.Network[i].Queues
			}
		}
		b, jerr := json.Marshal(fresh)
		return string(b), jerr
	})
	if err != nil {
		return status.Errorf(codes.Internal, "record the disk and NIC tuning of %q: %v", name, err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot record the disk and NIC tuning of %q: an operation is in progress", name)
	}
	return nil
}
