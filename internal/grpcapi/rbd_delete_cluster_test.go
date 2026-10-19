package grpcapi

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// rbdCalls records every rbd command a test's server runs, answering as a
// cluster that has every image and no watcher.
type rbdCalls struct {
	mu    sync.Mutex
	calls []string
}

func installRBDCalls(t *testing.T) *rbdCalls {
	t.Helper()
	r := &rbdCalls{}
	t.Cleanup(storage.OverrideCephPurgeLoopForTest())
	t.Cleanup(storage.OverrideCephRunnerForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		r.mu.Lock()
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		r.mu.Unlock()
		switch {
		case slices.Contains(args, "status"):
			return []byte(`{"watchers":[]}`), nil
		case slices.Contains(args, "info"):
			return []byte(`{"id":"1abc","size":1}`), nil
		}
		return nil, nil
	}))
	return r
}

func (r *rbdCalls) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.calls)
}

// requireOnlyClusterA fails unless rbd ran, and every run addressed cluster
// A's monitor and never cluster B's.
func (r *rbdCalls) requireOnlyClusterA(t *testing.T) {
	t.Helper()
	calls := r.all()
	if len(calls) == 0 {
		t.Fatal("no rbd command ran")
	}
	for _, c := range calls {
		if strings.Contains(c, "10.0.9.1") || !strings.Contains(c, "-m 10.0.0.1:6789") {
			t.Errorf("rbd ran %q, want it on cluster A's monitor 10.0.0.1:6789 only", c)
		}
	}
}

const (
	// staleB is a disk of litevirt pool ceph1 whose locator still names
	// cluster B's monitor: a domain defined now is given ceph1's current
	// monitors (cluster A), so B is not where its image is.
	staleB = `rbd:lv/vm1-data:id=litevirt:keyring=/k:lvpool=ceph1:mon_host=10.0.9.1\:6789`
)

var ceph1OnA = StoragePoolRef{Driver: "ceph", Source: "lv", Options: map[string]string{"id": "litevirt", "keyring": "/k", "mon_host": "10.0.0.1:6789"}}

func insertRBDDisk(t *testing.T, s *Server, volume, path string) corrosion.DiskRecord {
	t.Helper()
	ctx := context.Background()
	insertTestVM(t, ctx, s.db, "vm1", "test-host", "stopped")
	d := corrosion.DiskRecord{VMName: "vm1", DiskName: "data", HostName: "test-host", StorageType: "ceph",
		StorageVolume: volume, Path: path, DeleteWithVM: true}
	if err := corrosion.InsertDisk(ctx, s.db, d); err != nil {
		t.Fatal(err)
	}
	return d
}

// A recorded rbd image is removed on its litevirt pool's cluster on this
// host — the monitors a domain defined now is given — never on a monitor its
// locator still names. The pool configured under the row's own name already
// held (pinned here); the gaps were a row naming no pool or another pool than
// its locator's, and a pool this host has in its table but has not loaded.
//
// Mutation: the old diskDriver (the row's storage_volume pool from the loaded
// list only, else the locator's own options) — every case but "pool
// configured" reaches B, red.
func TestDeleteRecordedVMDiskVolumes_RBDOnThePoolsCurrentCluster(t *testing.T) {
	ceph2OnB := StoragePoolRef{Driver: "ceph", Source: "lv", Options: map[string]string{"id": "litevirt", "keyring": "/k", "mon_host": "10.0.9.1:6789"}}
	for _, tc := range []struct {
		name   string
		volume string
		setup  func(t *testing.T, s *Server)
	}{
		{"pool configured", "ceph1", func(t *testing.T, s *Server) { s.addStoragePoolRef("ceph1", ceph1OnA) }},
		{"row naming no pool", "", func(t *testing.T, s *Server) { s.addStoragePoolRef("ceph1", ceph1OnA) }},
		{"row naming another pool than its locator", "ceph2", func(t *testing.T, s *Server) {
			s.addStoragePoolRef("ceph1", ceph1OnA)
			s.addStoragePoolRef("ceph2", ceph2OnB)
		}},
		{"pool in the table, not loaded yet", "ceph1", func(t *testing.T, s *Server) {
			if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
				HostName: "test-host", Name: "ceph1", Driver: "ceph", Source: "lv", Options: ceph1OnA.Options, State: "active",
			}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerWithLocks(t)
			r := installRBDCalls(t)
			tc.setup(t, s)
			insertRBDDisk(t, s, tc.volume, staleB)
			if kept := s.deleteRecordedVMDiskVolumes(context.Background(), "vm1"); len(kept) != 0 {
				t.Errorf("kept %v, want the image removed", kept)
			}
			r.requireOnlyClusterA(t)
		})
	}
}

// A recorded rbd image whose cluster cannot be told as its domain would be
// given it is not acted on at all, and is named as kept: its conf cannot be
// read with nothing before it, its litevirt pool is on this host but that
// pool's monitors cannot be read or it is not a ceph pool, its pool is not on
// this host and its locator recorded monitors (which may no longer be its
// cluster's), or it carries an option no domain is given a cluster for.
//
// Mutations: let an unknowable cluster through — rbd runs, red; use the
// locator's recorded mon_host when its pool is not here — "pool not on this
// host" red.
func TestDeleteRecordedVMDiskVolumes_RBDOnAnUnknowableClusterIsKept(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		pool       *StoragePoolRef
	}{
		{"unreadable conf", "rbd:lv/vm1-data:id=litevirt:keyring=/k:conf=/nonexistent/c.conf", nil},
		{"pool's monitors unreadable", staleB,
			&StoragePoolRef{Driver: "ceph", Source: "lv", Options: map[string]string{"id": "litevirt", "keyring": "/k", "conf": "/nonexistent/c.conf"}}},
		{"pool of the name is not ceph", staleB, &StoragePoolRef{Driver: "dir", Target: "/var/lib/x"}},
		{"pool not on this host, recorded monitors", staleB, nil},
		{"ceph's own spelling of mon_host", `rbd:lv/vm1-data:id=litevirt:keyring=/k:mon-host=10.0.9.1\:6789`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerWithLocks(t)
			r := installRBDCalls(t)
			if tc.pool != nil {
				s.addStoragePoolRef("ceph1", *tc.pool)
			}
			insertRBDDisk(t, s, "", tc.path)
			kept := s.deleteRecordedVMDiskVolumes(context.Background(), "vm1")
			if calls := r.all(); len(calls) != 0 {
				t.Errorf("rbd ran %q on a cluster that cannot be told", calls)
			}
			if len(kept) != 1 || kept[0].Image != "lv/vm1-data" {
				t.Errorf("kept = %+v, want lv/vm1-data named", kept)
			}
		})
	}
}

// A journaled cutover cleanup frees a captured rbd disk on the same cluster,
// and reports one it cannot tell the cluster of rather than acting on it.
//
// Mutation: the old diskDriver — B reached, red; an unknowable cluster let
// through — rbd runs and no error, red.
func TestDeleteCapturedVMDiskVolumes_RBDOnThePoolsCurrentCluster(t *testing.T) {
	t.Run("stale locator", func(t *testing.T) {
		s := testServerWithLocks(t)
		r := installRBDCalls(t)
		s.addStoragePoolRef("ceph1", ceph1OnA)
		d := corrosion.DiskRecord{VMName: "gone", DiskName: "data", HostName: "test-host", StorageType: "ceph", Path: staleB}
		if err := s.deleteCapturedVMDiskVolumes(context.Background(), []corrosion.DiskRecord{d}); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		r.requireOnlyClusterA(t)
	})
	t.Run("unknowable", func(t *testing.T) {
		s := testServerWithLocks(t)
		r := installRBDCalls(t)
		d := corrosion.DiskRecord{VMName: "gone", DiskName: "data", HostName: "test-host", StorageType: "ceph",
			Path: "rbd:lv/vm1-data:id=litevirt:keyring=/k:conf=/nonexistent/c.conf"}
		if err := s.deleteCapturedVMDiskVolumes(context.Background(), []corrosion.DiskRecord{d}); err == nil {
			t.Error("cleanup of a disk whose cluster cannot be told succeeded")
		}
		if calls := r.all(); len(calls) != 0 {
			t.Errorf("rbd ran %q on a cluster that cannot be told", calls)
		}
	})
}

// The recheck of a kept image asks the cluster its domain is given whether
// the image is gone, never a stale monitor: B answering "not there" would
// forget an image A still holds.
//
// Mutation: the old diskDriver — the recheck asks B, red.
func TestRecheckKeptCephImages_AsksThePoolsCurrentCluster(t *testing.T) {
	s := testServerWithLocks(t)
	r := installRBDCalls(t)
	s.addStoragePoolRef("ceph1", ceph1OnA)
	d := corrosion.DiskRecord{VMName: "vm1", DiskName: "data", Path: staleB}
	if _, ok := s.recordKeptCephImage("vm1", &d, context.Canceled); !ok {
		t.Fatal("not recorded")
	}
	s.recheckKeptCephImages(context.Background())
	r.requireOnlyClusterA(t)
}

// stackOnA stores stack stk, whose ceph volume rbd-fast is on cluster A.
func stackOnA(t *testing.T, s *Server) {
	t.Helper()
	yaml := `name: stk
volumes:
  rbd-fast:
    driver: ceph
    source: lv
    options:
      id: litevirt
      keyring: /k
      mon_host: "10.0.0.1:6789"
vms:
  vm1:
    cpu: 1
`
	if err := corrosion.UpsertStack(context.Background(), s.db, corrosion.StackRecord{Name: "stk", ComposeYAML: yaml, State: "running"}); err != nil {
		t.Fatal(err)
	}
}

// staleStackB is a disk of compose volume rbd-fast of stack stk whose locator
// still names cluster B's monitor.
const staleStackB = `rbd:lv/vm1-data:id=litevirt:keyring=/k:lvpool=stk/rbd-fast:mon_host=10.0.9.1\:6789`

// A compose stack's ceph volume is a litevirt pool too ("<stack>/<volume>"),
// read from the stored stack: its image is removed on the volume's cluster,
// never on the monitors its locator recorded, and never kept for want of a
// host pool of that name (no host pool can be named with a "/").
//
// Mutation: look a "<stack>/<volume>" pool up among the host's pools only —
// the image is kept (or, without the recorded-mon_host refusal, removed on
// B), red.
func TestDeleteRecordedVMDiskVolumes_RBDStackVolumeOnItsCluster(t *testing.T) {
	s := testServerWithLocks(t)
	r := installRBDCalls(t)
	stackOnA(t, s)
	insertRBDDisk(t, s, "rbd-fast", staleStackB)
	if kept := s.deleteRecordedVMDiskVolumes(context.Background(), "vm1"); len(kept) != 0 {
		t.Errorf("kept %v, want the image removed on the volume's cluster", kept)
	}
	r.requireOnlyClusterA(t)
}

// A stack volume the stored stack no longer has, or a stack that is gone,
// is not a cluster that can be told: with a recorded mon_host the image is
// kept and named, with nothing run against any cluster. The refusal names
// the image and a manual removal, since a VM delete does not come back for it.
//
// Mutation: fall back to the locator's recorded mon_host — rbd runs on B,
// red.
func TestDeleteRecordedVMDiskVolumes_RBDStackVolumeGoneIsKept(t *testing.T) {
	s := testServerWithLocks(t)
	r := installRBDCalls(t)
	insertRBDDisk(t, s, "rbd-fast", staleStackB)
	kept := s.deleteRecordedVMDiskVolumes(context.Background(), "vm1")
	if calls := r.all(); len(calls) != 0 {
		t.Errorf("rbd ran %q", calls)
	}
	if len(kept) != 1 {
		t.Fatalf("kept = %+v, want lv/vm1-data named", kept)
	}
	for _, want := range []string{"stk/rbd-fast", "rbd -m", "rm lv/vm1-data"} {
		if !strings.Contains(kept[0].Reason, want) {
			t.Errorf("reason %q does not name %q", kept[0].Reason, want)
		}
	}
}

// The refusal for a locator that names no litevirt pool says so, rather than
// naming an empty pool.
func TestDeleteRecordedVMDiskVolumes_RBDNoPoolNamedInTheRefusal(t *testing.T) {
	s := testServerWithLocks(t)
	installRBDCalls(t)
	insertRBDDisk(t, s, "", `rbd:lv/vm1-data:id=litevirt:keyring=/k:mon_host=10.0.9.1\:6789`)
	kept := s.deleteRecordedVMDiskVolumes(context.Background(), "vm1")
	if len(kept) != 1 || strings.Contains(kept[0].Reason, "pool  ") || !strings.Contains(kept[0].Reason, "names no litevirt pool") {
		t.Errorf("kept = %+v, want a reason saying it names no litevirt pool", kept)
	}
}

// A locator that names no litevirt pool is acted on as the renderer gives it
// a cluster — by its own options — whatever pool the row's storage_volume
// names: a row's pool is not where its domain's monitors come from.
//
// Mutation: use the row's storage_volume pool for such a locator — rbd runs
// on that pool's cluster B, red.
func TestDeleteRecordedVMDiskVolumes_RBDLvpoolLessLocatorIgnoresTheRowsPool(t *testing.T) {
	s := testServerWithLocks(t)
	r := installRBDCalls(t)
	s.addStoragePoolRef("ceph2", StoragePoolRef{Driver: "ceph", Source: "lv", Options: map[string]string{"id": "litevirt", "keyring": "/k", "mon_host": "10.0.9.1:6789"}})
	insertRBDDisk(t, s, "ceph2", "rbd:lv/vm1-data:id=litevirt:keyring=/k")
	if kept := s.deleteRecordedVMDiskVolumes(context.Background(), "vm1"); len(kept) != 0 {
		t.Errorf("kept %v, want the image removed", kept)
	}
	for _, c := range r.all() {
		if strings.Contains(c, "10.0.9.1") {
			t.Errorf("rbd ran %q on the row's pool's cluster", c)
		}
	}
}

// The renderer's monitors for a compose stack volume are the stored stack's.
//
// Mutation: host pools only — no monitors, red.
func TestCephMonitorsForPool_ReadsAStackVolume(t *testing.T) {
	s := testServerWithLocks(t)
	stackOnA(t, s)
	mons, ok := s.CephMonitorsForPool("stk/rbd-fast")
	if !ok || len(mons) != 1 || mons[0] != "10.0.0.1:6789" {
		t.Errorf("CephMonitorsForPool = %v, %v; want [10.0.0.1:6789]", mons, ok)
	}
}
