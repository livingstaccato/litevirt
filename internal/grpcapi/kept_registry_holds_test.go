package grpcapi

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// registryKeep records in s's kept-disks.json, as an older build's
// stale-record delete (or the main delete's "cannot tell") left it with no
// note, a kept disk of VM vm: an overlay in its own directory backing on base
// (raw, so base may hold anything). It returns the overlay.
func registryKeep(t *testing.T, s *Server, vm, base string) string {
	t.Helper()
	top := filepath.Join(t.TempDir(), vm+"-kept-top.qcow2")
	if err := qcow2.CreateWithBackingFormat(top, base, "raw", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s.recordKeptDisks(adminCtx(), vm, []KeptDisk{{Path: top, Disk: "root", Host: s.hostName,
		Reason: "whether the VM runs elsewhere cannot be told: no answer from node-3"}})
	return top
}

func sameBytes(t *testing.T, what, p string, was []byte) {
	t.Helper()
	got, err := os.ReadFile(p)
	if err != nil || !bytes.Equal(got, was) {
		t.Errorf("%s %s was removed or changed (err=%v)", what, filepath.Base(p), err)
	}
}

// Fix round 1, I1: a kept chain whose backing file was removed by hand does
// not wedge every create on the host. The missing file ends the chain (nothing
// is there to keep, nothing under it is reached), so a create of another
// name clears its own debris. A chain that is there and cannot be read still
// refuses, FailedPrecondition (no retry helps), naming the entry and the way
// out.
//
// Red on a8c7a7a50: both answer Unavailable ("retry"). Mutations: walk the
// chain with keptChainLayers (missing is an error): "missing base" red; map
// every chain error to the retryable code: "unreadable" red.
func TestCreateVM_ABrokenKeptChainElsewhereDoesNotWedgeCreates(t *testing.T) {
	t.Run("missing base", func(t *testing.T) {
		s, base, _ := debrisFixture(t)
		registryKeep(t, s, "other", filepath.Join(t.TempDir(), "other-base-removed-by-hand.qcow2"))
		if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("web")); err != nil {
			t.Fatalf("create web with another VM's kept chain missing its base: %v", err)
		}
		if exists(base) {
			t.Fatal("web's debris was not cleared: the create did nothing, so this proves nothing")
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		bad := filepath.Join(t.TempDir(), "other-base.qcow2")
		if err := os.WriteFile(bad, []byte("not a qcow2 header"), 0o600); err != nil {
			t.Fatal(err)
		}
		top := filepath.Join(t.TempDir(), "other-kept-top.qcow2")
		if err := qcow2.CreateWithBackingFormat(top, bad, "qcow2", 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		s.recordKeptDisks(adminCtx(), "other", []KeptDisk{{Path: top, Disk: "root", Host: s.hostName, Reason: "no answer"}})
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("web"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) ||
			!strings.Contains(err.Error(), "remove its entry from "+filepath.Join(s.dataDir, diskKeptFile)) {
			t.Fatalf("create web with an unreadable kept chain = %v; want FailedPrecondition naming %s and the entry's removal", err, top)
		}
		sameBytes(t, "web's debris", base, was)
	})
}

// Fix round 1, I2: every path that removes disk files on this host honours a
// kept-disks.json entry with no note, and its chain, as the create does: the
// debris sweep, a VM's own snapshot layers, the recorded-location delete, and
// the reference check. An unreadable kept-disks.json keeps everything.
//
// Red on a8c7a7a50 (they read the notes only). Mutation: drop the registry
// from keptHolds (notes only): red.
func TestKeptRegistry_RemovalsKeepWhatItHolds(t *testing.T) {
	t.Run("debris sweep", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		registryKeep(t, s, "web", base)
		swap := s.images.DiskPath("web", "swap")
		if err := os.WriteFile(swap, []byte("debris"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.sweepVMDiskDebris(adminCtx(), "web")
		sameBytes(t, "the base a kept disk backs on", base, was)
		if exists(swap) {
			t.Error("unheld debris survived: the sweep did nothing, so this proves nothing")
		}
	})
	t.Run("debris sweep, kept-disks.json unreadable", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		if err := os.WriteFile(filepath.Join(s.dataDir, diskKeptFile), []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.sweepVMDiskDebris(adminCtx(), "web")
		sameBytes(t, "a candidate while kept-disks.json cannot be read", base, was)
	})
	t.Run("own snapshot layers", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		registryKeep(t, s, "web", base)
		s.removeOwnDiskLayers(adminCtx(), "web", []string{base})
		sameBytes(t, "the base a kept disk backs on", base, was)
	})
	t.Run("recorded location", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		top := registryKeep(t, s, "web", base)
		d := &corrosion.DiskRecord{VMName: "web2", DiskName: "root", HostName: s.hostName, Path: base, StorageType: "local"}
		if err := s.deleteDiskAtRecordedLocation(adminCtx(), d); err != nil {
			t.Fatalf("deleteDiskAtRecordedLocation: %v", err)
		}
		sameBytes(t, "the base a kept disk backs on", base, was)
		if !exists(top) {
			t.Fatal("the kept disk went")
		}
	})
	t.Run("reference check", func(t *testing.T) {
		s, base, _ := debrisFixture(t)
		registryKeep(t, s, "web", base)
		if ref, why, _ := s.pathStillReferenced(adminCtx(), base, "web2", "root"); !ref || !strings.Contains(why, diskKeptFile) {
			t.Errorf("the base a kept disk backs on reads as unreferenced (%v, %q)", ref, why)
		}
	})
}

// `lv iso rm <pool>/<file>` and a replica delete refuse a file a
// kept-disks.json entry with no note holds (I2), naming the record.
//
// Red on a8c7a7a50. Mutation: notes only in keptHolds: red.
func TestDeleteStoragePoolContent_RefusesWhatKeptDisksJSONHolds(t *testing.T) {
	t.Run("pool file", func(t *testing.T) {
		s := newPoolTestServer(t)
		dir := filepath.Join(s.dataDir, "pools", "fast")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "fast", Driver: "dir", Target: dir})
		base := filepath.Join(dir, "sv-root.qcow2")
		writePoolFile(t, base, "kept base")
		registryKeep(t, s, "sv", base)
		_, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "fast", Filename: "sv-root.qcow2"})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), diskKeptFile) {
			t.Fatalf("lv iso rm of a kept chain's base = %v; want FailedPrecondition naming %s", err, diskKeptFile)
		}
		sameBytes(t, "the kept chain's base", base, []byte("kept base"))
	})
	t.Run("replica", func(t *testing.T) {
		f := newPoolFixture(t)
		kept := areaReplica(t, f.dr, "a", "web", "1", "20261007-120000")
		was, err := os.ReadFile(kept)
		if err != nil {
			t.Fatal(err)
		}
		f.s.recordKeptDisks(adminCtx(), "web", []KeptDisk{{Path: kept, Disk: "root", Host: f.s.hostName, Reason: "no answer"}})
		_, err = f.s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(kept), ReplicaVm: "web"})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), diskKeptFile) {
			t.Fatalf("deleting a replica kept-disks.json names = %v; want FailedPrecondition naming it", err)
		}
		sameBytes(t, "the kept replica", kept, was)
	})
}
