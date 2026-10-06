package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// markerSweepHost is a host holding owner-epoch markers for four names, each
// a different case of what its own replica and runtime say about it:
//
//   - gone: the VM's row is tombstoned and no domain of the name is here — a
//     deleted VM's leftover, the only one the sweep may remove;
//   - live: the VM has a live row (its marker is a fence);
//   - unknown: no row at all — a replica that has not caught up, or was
//     reseeded, cannot prove the VM was deleted;
//   - defined: tombstoned, but a domain of the name is defined here.
type markerSweepHost struct {
	s    *Server
	fake *libvirtfake.Fake
}

func newMarkerSweepHost(t *testing.T) *markerSweepHost {
	t.Helper()
	s := testServerWithLocks(t)
	fake := libvirtfake.New()
	s.virt = fake
	ctx := adminCtx()
	for _, name := range []string{"gone", "live", "defined"} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: "owner-host", State: "running"}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", name, err)
		}
	}
	for _, name := range []string{"gone", "defined"} {
		if err := corrosion.DeleteVM(ctx, s.db, name); err != nil {
			t.Fatalf("tombstone %s: %v", name, err)
		}
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>defined</name></domain>`); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"gone", "live", "unknown", "defined"} {
		if err := health.WriteVMOwnerEpochMarker(s.dataDir, name, 2); err != nil {
			t.Fatalf("marker %s: %v", name, err)
		}
	}
	// Caught up, as a running host is once it has exchanged with a peer;
	// TestDeletedVMMarkerSweep_WaitsForAReplicaItCanTrust starts without.
	s.db.MarkReplicaCaughtUpForTests("peer")
	return &markerSweepHost{s: s, fake: fake}
}

func (h *markerSweepHost) markers(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, name := range []string{"gone", "live", "unknown", "defined"} {
		_, found, err := health.ReadVMOwnerEpochMarker(h.s.dataDir, name)
		if err != nil {
			t.Fatalf("read marker %s: %v", name, err)
		}
		out[name] = found
	}
	return out
}

func (h *markerSweepHost) setState(t *testing.T, state string) {
	t.Helper()
	ctx := context.Background()
	if existing, _ := corrosion.GetHost(ctx, h.s.db, h.s.hostName); existing == nil {
		if err := corrosion.InsertHost(ctx, h.s.db, corrosion.HostRecord{Name: h.s.hostName, Address: "10.0.0.1", State: state}); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := corrosion.UpdateHostState(ctx, h.s.db, h.s.hostName, state); err != nil {
		t.Fatal(err)
	}
}

// The sweep removes a marker only for a name its own replica records as
// deleted (a tombstone and no live row) with no domain of that name here —
// the receiving side's rules for a deleting owner's request
// (removeDeletedVMLeftoversHere), plus the tombstone, since nobody asked.
//
// Mutations, each turning exactly its case red: accept a live row as well as a
// tombstone ("live"); drop the tombstone check ("live" and "unknown"); drop
// the domain check ("defined"); remove nothing ("gone").
func TestSweepDeletedVMMarkers_RemovesOnlyAProvablyDeletedVMsMarker(t *testing.T) {
	h := newMarkerSweepHost(t)
	h.s.sweepDeletedVMMarkers(adminCtx())
	want := map[string]bool{"gone": false, "live": true, "unknown": true, "defined": true}
	got := h.markers(t)
	for name, present := range want {
		if got[name] != present {
			t.Errorf("marker %q present = %v after the sweep, want %v", name, got[name], present)
		}
	}
	if fileExists(filepath.Join(h.s.dataDir, "vms", "gone")) {
		t.Error("the deleted VM's vms/<name> directory is still here")
	}
}

// The sweep runs when the host becomes active — at its first look, if it is
// active then (a daemon start), and on every move from another state to
// active — and not while it is draining or in maintenance, nor again while it
// stays active.
//
// Mutations: sweep on every tick — the marker written while the host stays
// active is removed and goes red; sweep only on a change of state (not at the
// first look) — the startup case keeps its marker; never sweep — the
// undrained case keeps its marker.
func TestDeletedVMMarkerSweep_RunsWhenTheHostBecomesActive(t *testing.T) {
	ctx := adminCtx()
	t.Run("startup", func(t *testing.T) {
		h := newMarkerSweepHost(t)
		h.setState(t, "active")
		h.s.DeletedVMMarkerSweepTick(ctx)
		if h.markers(t)["gone"] {
			t.Error("a host that starts active kept a deleted VM's marker")
		}
	})
	t.Run("undrained", func(t *testing.T) {
		h := newMarkerSweepHost(t)
		h.setState(t, "maintenance")
		h.s.DeletedVMMarkerSweepTick(ctx)
		if !h.markers(t)["gone"] {
			t.Fatal("swept while the host is in maintenance")
		}
		h.setState(t, "draining")
		h.s.DeletedVMMarkerSweepTick(ctx)
		if !h.markers(t)["gone"] {
			t.Fatal("swept while the host is draining")
		}
		h.setState(t, "active")
		h.s.DeletedVMMarkerSweepTick(ctx)
		if h.markers(t)["gone"] {
			t.Fatal("the host became active and kept a deleted VM's marker")
		}
		// Still active: no new sweep. A marker that appears now is the
		// delete fan-out's to remove, or the next activation's.
		if err := health.WriteVMOwnerEpochMarker(h.s.dataDir, "gone", 2); err != nil {
			t.Fatal(err)
		}
		h.s.DeletedVMMarkerSweepTick(ctx)
		if !h.markers(t)["gone"] {
			t.Error("swept again while the host stayed active")
		}
	})
}

// A daemon start is the case the startup sweep exists for — a host that was
// down while a VM was deleted — and its replica then holds the cluster as it
// was when it went down: no tombstone yet, and probably its own record still
// `active`. So the sweep waits until the replica has caught up with a peer,
// and a look it could not act on (not caught up, or no libvirt to ask about
// domains) does not count as having seen the host active: the next look that
// can act still sweeps.
//
// Mutations: don't wait for the replica — the first look sweeps an
// uncaught-up replica, finds no tombstone, and (having seen the host active)
// never sweeps again, so the marker stays; record the state before the
// libvirt check — the look without libvirt consumes the activation and the
// marker stays.
func TestDeletedVMMarkerSweep_WaitsForAReplicaItCanTrust(t *testing.T) {
	ctx := adminCtx()
	t.Run("replica not caught up", func(t *testing.T) {
		s := testServerWithLocks(t)
		s.virt = libvirtfake.New()
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := health.WriteVMOwnerEpochMarker(s.dataDir, "gone", 2); err != nil {
			t.Fatal(err)
		}
		// The daemon's first look: the tombstone has not arrived.
		s.DeletedVMMarkerSweepTick(ctx)
		// Anti-entropy delivers it, and marks the replica caught up.
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "gone", HostName: "owner-host", State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteVM(ctx, s.db, "gone"); err != nil {
			t.Fatal(err)
		}
		s.db.MarkReplicaCaughtUpForTests("peer")
		s.DeletedVMMarkerSweepTick(ctx)
		if _, found, _ := health.ReadVMOwnerEpochMarker(s.dataDir, "gone"); found {
			t.Error("the deleted VM's marker survived the host's start: the sweep ran on a replica that had not caught up")
		}
	})
	t.Run("no libvirt yet", func(t *testing.T) {
		h := newMarkerSweepHost(t)
		h.setState(t, "active")
		virt := h.s.virt
		h.s.virt = nil
		h.s.DeletedVMMarkerSweepTick(ctx)
		h.s.virt = virt
		h.s.DeletedVMMarkerSweepTick(ctx)
		if h.markers(t)["gone"] {
			t.Error("a look without libvirt consumed the activation; the deleted VM's marker stayed")
		}
	})
}
