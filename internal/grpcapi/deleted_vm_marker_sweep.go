package grpcapi

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/safename"
)

// A deleted VM's owner-epoch marker on a host the delete did not reach.
//
// DeleteVM asks the other active and draining hosts to remove what the VM
// left on them (cleanupDeletedVMLeftovers), once. A host in another state —
// in maintenance, offline, fenced — or one it could not reach is not asked
// again, and kept <dataDir>/vms/<name>/owner_epoch for good: on the lab, a
// host drained while its VMs were deleted held three. A marker outliving its
// VM is not merely untidy (RemoveVMOwnerEpochMarker says why), so the host
// removes such markers itself, from its own records, when it becomes active —
// at a daemon start that finds it active, and on every move back to active,
// `lv host undrain` included.
//
// It removes a marker only by the rules a deleting owner's request is judged
// by on the receiving side (removeDeletedVMLeftoversHere), plus one: its own
// replica must record the VM as DELETED — a tombstone and no live row. With no
// row at all it keeps the marker: a replica that has not caught up, or was
// reseeded, cannot tell a deleted VM from one it has not heard of, and while
// the VM lives the marker is its fence. Detached disk files are never touched
// here: which of them were the deleted incarnation's only the deleting owner
// can tell (departedDetachedDisks).
//
// Purely local: it reads this host's replica and removes files under its own
// dataDir. It writes nothing replicated.

// deletedVMMarkerSweepInterval is how often the host looks at its own state.
const deletedVMMarkerSweepInterval = time.Minute

// RunDeletedVMMarkerSweep looks at this host's state now and every interval,
// and sweeps deleted VMs' markers each time it finds the host has become
// active (DeletedVMMarkerSweepTick).
func (s *Server) RunDeletedVMMarkerSweep(ctx context.Context) {
	ticker := time.NewTicker(deletedVMMarkerSweepInterval)
	defer ticker.Stop()
	for {
		s.DeletedVMMarkerSweepTick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// DeletedVMMarkerSweepTick is one look of RunDeletedVMMarkerSweep: it reads
// this host's state and sweeps when the host is active and was not at the
// previous look — or there was none, as at a daemon start.
//
// A look that could not act changes nothing, so the next one that can still
// sees the activation:
//   - a replica that has not caught up with a peer (ReplicaCaughtUp). At a
//     daemon start the replica holds the cluster as it was when the host went
//     down — the case this sweep exists for — so the tombstone it needs has
//     not arrived yet, and the host's own record most likely still says it is
//     active. Sweeping then removes nothing and would use up the activation.
//   - no libvirt connection: the sweep cannot tell whether a domain of a name
//     is defined, so it removes nothing.
//   - a state it cannot read.
func (s *Server) DeletedVMMarkerSweepTick(ctx context.Context) {
	if s.virt == nil {
		return
	}
	if ok, _ := s.db.ReplicaCaughtUp(); !ok {
		return
	}
	h, err := corrosion.GetHost(ctx, s.db, s.hostName)
	if err != nil || h == nil {
		return
	}
	s.markerSweepMu.Lock()
	defer s.markerSweepMu.Unlock()
	prev, seen := s.markerSweepLastState, s.markerSweepSeen
	s.markerSweepLastState, s.markerSweepSeen = h.State, true
	if h.State == "active" && (!seen || prev != "active") {
		s.sweepDeletedVMMarkers(ctx)
	}
}

// sweepDeletedVMMarkers removes the owner-epoch marker of every VM this
// host's replica records as deleted, unless a domain of that name is defined
// here. Without libvirt it removes nothing: it cannot tell whether one is
// (DeletedVMMarkerSweepTick does not count such a look).
func (s *Server) sweepDeletedVMMarkers(ctx context.Context) {
	if s.virt == nil || s.dataDir == "" {
		return
	}
	ents, err := os.ReadDir(filepath.Join(s.dataDir, "vms"))
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("deleted VM markers: cannot list this host's VM markers", "error", err)
		}
		return
	}
	for _, e := range ents {
		name := e.Name()
		if !e.IsDir() || safename.ValidateVMName(name) != nil {
			continue
		}
		if _, found, rerr := health.ReadVMOwnerEpochMarker(s.dataDir, name); rerr != nil || !found {
			continue
		}
		s.removeDeletedVMMarker(ctx, name)
	}
}

// removeDeletedVMMarker removes name's marker if this host's replica records
// the VM as deleted and no domain of the name is defined here. It reads the
// row and the domain as late as it can, under the VM's lock.
//
// The lock serializes with this host's other lockVM holders (delete, hotplug,
// migration out, the deleting owner's request). It does NOT hold off a create
// of the same name — createVM does not take it. Such a create defines its
// domain, then revives the row, then writes the marker, so it is refused by
// the tombstone and domain checks here unless it does all three between those
// checks and the removal; that is the residual window, as on the receiving
// side (removeDeletedVMLeftoversHere), and it would remove the new VM's marker,
// which the reconciler's convergeOwnerEpochMarker writes again from its row
// once the VM runs here.
func (s *Server) removeDeletedVMMarker(ctx context.Context, name string) {
	unlock := s.lockVM(name)
	defer unlock()
	// A name has one row (vms.name is its key), so a tombstoned row is also
	// the absence of a live one: a VM created again under the name revives
	// the row and is not deleted here.
	if createdAt, err := corrosion.GetTombstonedVMCreatedAt(ctx, s.db, name); err != nil || createdAt == "" {
		return
	}
	if s.virt.DomainExists(name) {
		return
	}
	if err := health.RemoveVMOwnerEpochMarker(s.dataDir, name); err != nil {
		slog.Warn("deleted VM markers: marker not removed", "vm", name, "error", err)
		return
	}
	slog.Info("deleted VM markers: removed the owner-epoch marker of a deleted VM", "vm", name, "host", s.hostName)
}
