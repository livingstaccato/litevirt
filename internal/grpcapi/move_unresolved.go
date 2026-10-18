package grpcapi

import (
	"context"
	"errors"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// moveMarker is the unresolved-move record (health.UnresolvedMove) of one
// move-volume cutover. It is written before the first step that can leave the
// persistent config and the disk row naming different files, kept when the
// move returns with the two possibly disagreeing (keep), and removed by done
// otherwise. A nil *moveMarker (no libvirt backend: no persistent config to
// disagree with) does nothing.
type moveMarker struct {
	s          *Server
	m          health.UnresolvedMove
	unresolved bool
	endFlight  func()
}

// beginMoveMarker records the cutover of src to dstPath. A record that cannot
// be written refuses the cutover: nothing has been changed yet.
func (s *Server) beginMoveMarker(vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath, dstType, dstPool string, live, pivoted bool) (*moveMarker, error) {
	if s.virt == nil {
		return nil, nil
	}
	mk := &moveMarker{s: s, m: health.UnresolvedMove{
		VM: vm.Name, Disk: src.DiskName, TargetDev: src.TargetDev,
		Src: src.Path, SrcType: src.StorageType, SrcPool: src.StorageVolume,
		Dst: dstPath, DstType: dstType, DstPool: dstPool,
		Live: live, Pivoted: pivoted,
	}}
	mk.endFlight = health.MarkMoveInFlight(vm.Name, src.DiskName)
	if err := health.RecordUnresolvedMove(s.dataDir, mk.m); err != nil {
		mk.endFlight()
		return nil, status.Errorf(codes.Internal, "record the move of %s's disk %s before its cutover (cutover aborted, nothing changed): %v", vm.Name, src.DiskName, err)
	}
	return mk, nil
}

// pivoted records that the guest now writes the copy. Best effort: the
// earlier record says it did not, which refuses a start rather than heal one.
func (mk *moveMarker) pivoted() {
	if mk == nil {
		return
	}
	mk.m.Pivoted = true
	if err := health.RecordUnresolvedMove(mk.s.dataDir, mk.m); err != nil {
		slog.Warn("move: recording the pivot in the unresolved-move record failed", "vm", mk.m.VM, "disk", mk.m.Disk, "error", err)
	}
}

// keep leaves the record in place when the move returns: the persistent config
// and the disk row may name different files. It returns err.
func (mk *moveMarker) keep(err error) error {
	if mk == nil {
		return err
	}
	mk.unresolved = true
	if err != nil {
		mk.m.Error = err.Error()
		if werr := health.RecordUnresolvedMove(mk.s.dataDir, mk.m); werr != nil {
			slog.Warn("move: recording the error in the unresolved-move record failed", "vm", mk.m.VM, "disk", mk.m.Disk, "error", werr)
		}
	}
	return err
}

// done ends the move: the record is removed unless keep was called.
func (mk *moveMarker) done() {
	if mk == nil {
		return
	}
	defer mk.endFlight()
	if mk.unresolved {
		return
	}
	if err := health.ClearUnresolvedMove(mk.s.dataDir, mk.m.VM, mk.m.Disk); err != nil {
		slog.Warn("move: removing the unresolved-move record failed; the next start of the VM settles it", "vm", mk.m.VM, "disk", mk.m.Disk, "error", err)
	}
}

// resolveUnresolvedMoves is health.ResolveUnresolvedMoves for a VM on this
// host, before its domain starts or its disk rows are read for a copy.
func (s *Server) resolveUnresolvedMoves(ctx context.Context, vmName string) error {
	read := func() (string, error) {
		if s.virt == nil {
			return "", errors.New("no libvirt backend")
		}
		return s.virt.DumpXMLInactive(vmName)
	}
	if err := health.ResolveUnresolvedMoves(ctx, s.db, s.dataDir, s.hostName, vmName, read); err != nil {
		return status.Error(codes.FailedPrecondition, err.Error())
	}
	return nil
}

// settleMoveRecordAtDest removes the unresolved-move record of a disk whose row
// already names the move's copy, once the persistent config names the copy too
// and a running guest writes it: lv move-volume retried after the operator
// pivoted by hand. The caller holds the VM's lock. A config that cannot be read,
// or a guest still on the source, leaves the record.
func (s *Server) settleMoveRecordAtDest(vm *corrosion.VMRecord, row *corrosion.DiskRecord) {
	if s.virt == nil {
		return
	}
	moves, err := health.UnresolvedMovesOf(s.dataDir, vm.Name)
	if err != nil {
		return
	}
	for _, m := range moves {
		if m.Disk != row.DiskName || m.Dst != row.Path {
			continue
		}
		x, err := s.virt.DumpXMLInactive(vm.Name)
		if err != nil {
			return
		}
		if _, changed, rerr := libvirt.RewriteDiskSource(x, m.TargetDev, m.Src, m.Dst); rerr != nil || changed {
			return
		}
		if !s.sourceClosedForPlainCopy(vm) {
			was := *row
			was.Path = m.Src
			if live, lerr := s.movedDiskLiveSource(vm, &was, m.Dst); lerr != nil || live != m.Dst {
				return
			}
		}
		if err := health.ClearUnresolvedMove(s.dataDir, vm.Name, m.Disk); err != nil {
			slog.Warn("move: removing a settled unresolved-move record failed", "vm", vm.Name, "disk", m.Disk, "error", err)
		}
	}
}
