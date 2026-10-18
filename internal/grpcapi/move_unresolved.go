package grpcapi

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// moveMarker is the unresolved-move record (health.UnresolvedMove) of one
// move-volume cutover, and its replicated condition. It is written before the
// first step that can leave the persistent config and the disk row naming
// different files, kept when the move returns with the two possibly
// disagreeing (keep), and removed by done otherwise. A nil *moveMarker (no
// libvirt backend: no persistent config to disagree with) does nothing.
type moveMarker struct {
	s          *Server
	ctx        context.Context
	m          health.UnresolvedMove
	unresolved bool
	endFlight  func()
}

// beginMoveMarker records the cutover of src to dstPath. On a forward path a
// record that cannot be written refuses the cutover: nothing has been changed
// yet. On a catch-up (catchUp: the commit that makes the config and the row
// agree) the failure is logged and the catch-up goes on: refusing it would
// keep the split it heals.
//
// A record this host already holds for the same move keeps its live and
// pivoted facts: a retry must not record a live move as an offline one.
func (s *Server) beginMoveMarker(ctx context.Context, vm *corrosion.VMRecord, src *corrosion.DiskRecord, dstPath, dstType, dstPool string, live, pivoted, catchUp bool) (*moveMarker, error) {
	if s.virt == nil {
		return nil, nil
	}
	mk := &moveMarker{s: s, ctx: context.WithoutCancel(ctx), m: health.UnresolvedMove{
		VM: vm.Name, Disk: src.DiskName, TargetDev: src.TargetDev,
		Src: src.Path, SrcType: src.StorageType, SrcPool: src.StorageVolume,
		Dst: dstPath, DstType: dstType, DstPool: dstPool,
		Live: live, Pivoted: pivoted,
		At:             time.Now().UTC().Format(time.RFC3339Nano),
		SrcBackingDisk: src.BackingDisk, SrcBackingImage: src.BackingImage,
	}}
	if cur, err := corrosion.GetVM(ctx, s.db, vm.Name); err == nil && cur != nil {
		// Who owns the VM as the move begins: a later owner, or generation,
		// shows it changed hands since (health.OwnerChangedSince).
		mk.m.Owner, mk.m.OwnerEpoch = cur.HostName, cur.OwnerEpoch
	}
	prior, hadPrior := s.moveRecordOf(vm.Name, src.DiskName)
	if hadPrior && prior.Dst == dstPath && (prior.Src == src.Path || prior.Dst == src.Path) {
		// The same move, retried: it keeps its identity (At, which a hand
		// resolution matches), the owner it began under, and what the first
		// attempt knew.
		mk.m.Src, mk.m.SrcType, mk.m.SrcPool = prior.Src, prior.SrcType, prior.SrcPool
		mk.m.SrcBackingDisk, mk.m.SrcBackingImage = prior.SrcBackingDisk, prior.SrcBackingImage
		if prior.At != "" {
			mk.m.At = prior.At
		}
		if prior.Owner != "" {
			mk.m.Owner, mk.m.OwnerEpoch = prior.Owner, prior.OwnerEpoch
		}
		mk.m.Live = mk.m.Live || prior.Live
		mk.m.Pivoted = mk.m.Pivoted || prior.Pivoted
		mk.m.CatchUp = mk.m.CatchUp || prior.CatchUp
	} else if catchUp && !live {
		// The config named the copy before this move: it may hold writes the
		// source lacks.
		mk.m.CatchUp = true
	}
	mk.endFlight = health.MarkMoveInFlight(vm.Name, src.DiskName)
	err := health.RecordUnresolvedMove(s.dataDir, mk.m)
	if err == nil {
		if err = health.PublishUnresolvedMoves(mk.ctx, s.db, s.dataDir, s.hostName, vm.Name); err != nil {
			// Leave the record as it was before this move.
			if hadPrior {
				_ = health.RecordUnresolvedMove(s.dataDir, prior)
			} else {
				_ = health.ClearUnresolvedMove(s.dataDir, vm.Name, src.DiskName)
			}
		}
	}
	if err != nil {
		if health.IsMoveUnresolved(err) {
			// Another host's unresolved move of this VM is open: never
			// overwritten, catch-up or not.
			mk.endFlight()
			return nil, err
		}
		if catchUp {
			slog.Error("move: the unresolved-move record could not be written; committing the catch-up anyway, as it makes the config and the disk row agree",
				"vm", vm.Name, "disk", src.DiskName, "error", err)
			return mk, nil
		}
		mk.endFlight()
		return nil, status.Errorf(codes.Internal, "record the move of %s's disk %s before its cutover (cutover aborted, nothing changed): %v", vm.Name, src.DiskName, err)
	}
	return mk, nil
}

// moveRecordOf returns this host's record of vm's disk, if it holds one.
func (s *Server) moveRecordOf(vm, disk string) (health.UnresolvedMove, bool) {
	moves, err := health.UnresolvedMovesOf(s.dataDir, vm)
	if err != nil {
		return health.UnresolvedMove{}, false
	}
	for _, m := range moves {
		if m.Disk == disk {
			return m, true
		}
	}
	return health.UnresolvedMove{}, false
}

// rerecord writes the record and its condition again. Best effort: the
// earlier record errs towards refusing a start, never towards healing one.
func (mk *moveMarker) rerecord(what string) {
	if err := health.RecordUnresolvedMove(mk.s.dataDir, mk.m); err != nil {
		slog.Warn("move: recording "+what+" in the unresolved-move record failed", "vm", mk.m.VM, "disk", mk.m.Disk, "error", err)
		return
	}
	if err := health.PublishUnresolvedMoves(mk.ctx, mk.s.db, mk.s.dataDir, mk.s.hostName, mk.m.VM); err != nil {
		slog.Warn("move: publishing "+what+" of the unresolved move failed", "vm", mk.m.VM, "disk", mk.m.Disk, "error", err)
	}
}

// pivoted records that the guest now writes the copy.
func (mk *moveMarker) pivoted() {
	if mk == nil {
		return
	}
	mk.m.Pivoted = true
	mk.rerecord("the pivot")
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
	}
	mk.rerecord("the error")
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
		return
	}
	if err := health.PublishUnresolvedMoves(mk.ctx, mk.s.db, mk.s.dataDir, mk.s.hostName, mk.m.VM, mk.m.Disk); err != nil {
		slog.Warn("move: resolving the unresolved-move condition failed; the next start of the VM settles it", "vm", mk.m.VM, "disk", mk.m.Disk, "error", err)
	}
}

// settleBeforeMove is run before a move of row's disk (a retry included). A
// record of a live move that was never pivoted is not trusted to have pivoted:
// only a running guest whose disk is on the copy proves it, and then the
// record says so. Every record of the VM is then settled as a start settles
// it (resolveUnresolvedMoves): the row follows the config, or the move is
// refused with the record's state. It returns the disk row as it is after, or
// nil when there was nothing to settle.
func (s *Server) settleBeforeMove(ctx context.Context, vm *corrosion.VMRecord, row *corrosion.DiskRecord) (*corrosion.DiskRecord, error) {
	if s.virt == nil {
		return nil, nil
	}
	m, ok := s.moveRecordOf(vm.Name, row.DiskName)
	if !ok {
		// Another host's unresolved move of this disk (or this host's, its
		// record lost): honoured by the rule a start on this host follows.
		if !health.MoveConditionCovers(ctx, s.db, vm.Name, row.DiskName) {
			return nil, nil
		}
		if err := s.resolveUnresolvedMoves(ctx, vm.Name); err != nil {
			return nil, err
		}
		return s.diskRowOf(ctx, vm.Name, row.DiskName)
	}
	if m.Live && !m.Pivoted && !s.sourceClosedForPlainCopy(vm) {
		was := *row
		was.Path = m.Src
		if live, lerr := s.movedDiskLiveSource(vm, &was, m.Dst); lerr == nil && live == m.Dst {
			m.Pivoted = true
			if err := health.RecordUnresolvedMove(s.dataDir, m); err != nil {
				return nil, status.Errorf(codes.Internal, "record the pivot of %s's disk %s: %v", vm.Name, row.DiskName, err)
			}
			_ = health.PublishUnresolvedMoves(ctx, s.db, s.dataDir, s.hostName, vm.Name)
		}
	}
	if err := s.resolveUnresolvedMoves(ctx, vm.Name); err != nil {
		return nil, err
	}
	return s.diskRowOf(ctx, vm.Name, row.DiskName)
}

// diskRowOf re-reads one disk row.
func (s *Server) diskRowOf(ctx context.Context, vm, disk string) (*corrosion.DiskRecord, error) {
	disks, err := corrosion.GetVMDisks(ctx, s.db, vm)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list disks: %v", err)
	}
	for i := range disks {
		if disks[i].DiskName == disk {
			return &disks[i], nil
		}
	}
	return nil, status.Errorf(codes.NotFound, "vm %q has no disk %q", vm, disk)
}

// resolveUnresolvedMoves is health.ResolveUnresolvedMoves for a VM on this
// host, before its domain starts or its disk rows are read for a copy.
func (s *Server) resolveUnresolvedMoves(ctx context.Context, vmName string) error {
	dom := health.MoveDomain{InactiveXML: func() (string, error) { return "", errors.New("no libvirt backend") }}
	if s.virt != nil {
		dom = health.MoveDomain{
			InactiveXML: func() (string, error) { return s.virt.DumpXMLInactive(vmName) },
			State:       func() (string, error) { return s.virt.DomainState(vmName) },
			Active:      func() (bool, error) { return s.virt.DomainIsActive(vmName) },
		}
	}
	return health.ResolveUnresolvedMoves(ctx, s.db, s.dataDir, s.hostName, vmName, dom)
}

// forgetMoveRecords drops vm's unresolved-move records here and resolves its
// condition: the name now belongs to a new domain (create, import, restore,
// promote) or to none (delete, rebuild).
func (s *Server) forgetMoveRecords(ctx context.Context, vm string) {
	if err := health.ForgetUnresolvedMoves(context.WithoutCancel(ctx), s.db, s.dataDir, vm); err != nil {
		slog.Warn("removing the VM's unresolved volume-move records failed", "vm", vm, "error", err)
	}
}
