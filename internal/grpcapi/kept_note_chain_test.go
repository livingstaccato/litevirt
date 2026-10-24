package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// noteKeep is a linked clone vm kept the way `lv rm --keep-disks` keeps it
// (rc7 lab 1 F1): an overlay backing on base, outside the disk directory,
// that the note kept-disks/<vm>.json names, alone. Nothing names base, which
// is another VM's disk, and kept-disks.json has no entry. It returns the
// overlay.
func noteKeep(t *testing.T, s *Server, vm, base string) string {
	t.Helper()
	top := filepath.Join(t.TempDir(), vm+"-root.qcow2")
	if err := qcow2.CreateWithBackingFormat(top, base, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptDisks(s.dataDir, vm, []string{top}); err != nil {
		t.Fatal(err)
	}
	return top
}

// rc7 lab 1 F1: every path that removes disk files on this host leaves a
// file the backing chain of a noted kept disk reaches, though no note names
// it: the debris sweep, a VM's own snapshot layers, the recorded-location
// delete, the reference check (migrate and move cleanup), replica pruning
// and the pool-content delete. An unreadable noted chain keeps everything.
//
// Red on 3720ac768 (the notes held only the files they name, and below a
// ".." layer). Mutation: drop keptNoteChainHeld from keptHolds: every
// subtest red; hold only the ".." layers again (keptNoteChainHolds skips a
// layer above c.dotdot): every subtest but "unreadable chain" red.
func TestKeptNoteChain_RemovalsKeepTheBaseANotedOverlayReaches(t *testing.T) {
	t.Run("debris sweep", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		noteKeep(t, s, "clone", base)
		swap := s.images.DiskPath("web", "swap")
		if err := os.WriteFile(swap, []byte("debris"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.sweepVMDiskDebris(adminCtx(), "web")
		sameBytes(t, "the base a noted kept overlay backs on", base, was)
		if exists(swap) {
			t.Error("unheld debris survived: the sweep did nothing, so this proves nothing")
		}
	})
	t.Run("own snapshot layers", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		noteKeep(t, s, "clone", base)
		s.removeOwnDiskLayers(adminCtx(), "web", []string{base})
		sameBytes(t, "the base a noted kept overlay backs on", base, was)
	})
	t.Run("recorded location", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		top := noteKeep(t, s, "clone", base)
		d := &corrosion.DiskRecord{VMName: "web", DiskName: "root", HostName: s.hostName, Path: base, StorageType: "local"}
		if err := s.deleteDiskAtRecordedLocation(adminCtx(), d); err != nil {
			t.Fatalf("deleteDiskAtRecordedLocation: %v", err)
		}
		sameBytes(t, "the base a noted kept overlay backs on", base, was)
		if !exists(top) {
			t.Fatal("the kept overlay went")
		}
	})
	t.Run("reference check", func(t *testing.T) {
		s, base, _ := debrisFixture(t)
		top := noteKeep(t, s, "clone", base)
		if ref, why, _ := s.pathStillReferenced(adminCtx(), base, "web", "root"); !ref || !strings.Contains(why, top) {
			t.Errorf("the base a noted kept overlay backs on reads as unreferenced (%v, %q)", ref, why)
		}
	})
	t.Run("replica prune", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		dir := t.TempDir()
		var names []string
		for _, n := range []string{"vm1-root-20260101-000000.qcow2", "vm1-root-20260102-000000.qcow2", "vm1-root-20260103-000000.qcow2"} {
			p := filepath.Join(dir, n)
			if err := qcow2.Create(p, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
			names = append(names, p)
		}
		noteKeep(t, s, "clone", names[0])
		if got := s.pruneLocalReplicas(context.Background(), dir, replicaKey{VM: "vm1", Disk: "root"}, 1); got != 1 {
			t.Fatalf("pruned %d, want 1", got)
		}
		if !exists(names[0]) {
			t.Error("a replica a noted kept overlay backs on was pruned")
		}
		if exists(names[1]) {
			t.Error("an unheld old replica survived: the prune did nothing, so this proves nothing")
		}
	})
	t.Run("pool file", func(t *testing.T) {
		s := newPoolTestServer(t)
		dir := filepath.Join(s.dataDir, "pools", "fast")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "fast", Driver: "dir", Target: dir})
		base := filepath.Join(dir, "sv-root.qcow2")
		if err := qcow2.Create(base, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		was, _ := os.ReadFile(base)
		top := noteKeep(t, s, "svc", base)
		_, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "fast", Filename: "sv-root.qcow2"})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("lv iso rm of a noted kept overlay's base = %v; want FailedPrecondition naming %s", err, top)
		}
		sameBytes(t, "the noted kept overlay's base", base, was)
	})
	t.Run("unreadable chain", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		bad := filepath.Join(t.TempDir(), "other-base.qcow2")
		if err := os.WriteFile(bad, []byte("not a qcow2 header"), 0o600); err != nil {
			t.Fatal(err)
		}
		noteKeep(t, s, "clone", bad) // declared qcow2, no qcow2 header: unreadable
		s.sweepVMDiskDebris(adminCtx(), "web")
		sameBytes(t, "a candidate while a noted chain cannot be read", base, was)
	})
}

// rc7 lab 1 F1, step 4: a create that would write the missing backing file
// of a noted kept overlay is refused, naming the overlay, as one recorded in
// kept-disks.json is: the new disk would become the kept overlay's base. A
// note or a noted chain that cannot be read refuses every create that writes
// a disk here (fail closed); a missing base elsewhere refuses nothing.
//
// Red on 3720ac768 (the create goes ahead). Mutations: drop the
// keptNoteMissingBase check from keptMissingBaseRefusal: "create", "import"
// and "unreadable note" red; drop it from keptFileCreateRefusal: "create with
// debris to clear" red; let keptMissingBaseRefusal ignore an unreadable note
// (return nil on unknown): "unreadable note" red.
func TestKeptNoteChain_NeverWritesTheMissingBaseOfANotedOverlay(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		base := s.images.DiskPath("web", "root")
		top := noteKeep(t, s, "clone", base) // base missing: removed by an older build's lv rm web
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
		_, err := s.CreateVM(adminCtx(), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), base) {
			t.Fatalf("create web over a noted kept overlay's missing base = %v; want FailedPrecondition naming %s and %s", err, top, base)
		}
		if exists(base) {
			t.Fatal("a file was written at the noted kept overlay's missing base")
		}
	})
	t.Run("create with debris to clear", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		base := s.images.DiskPath("web", "root")
		swap := s.images.DiskPath("web", "swap")
		if err := os.MkdirAll(filepath.Dir(swap), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(swap, []byte("debris"), 0o600); err != nil {
			t.Fatal(err)
		}
		top := noteKeep(t, s, "clone", base)
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
		if _, err := s.CreateVM(adminCtx(), req); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("create web over a noted kept overlay's missing base, with debris = %v; want FailedPrecondition naming %s", err, top)
		}
		if exists(base) {
			t.Fatal("a file was written at the noted kept overlay's missing base")
		}
	})
	t.Run("import", func(t *testing.T) {
		s, dst := orphanFixture(t, "imp-mb")
		top := noteKeep(t, s, "clone", dst)
		err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-mb", false)}})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("import at a noted kept overlay's missing base = %v; want FailedPrecondition naming %s", err, top)
		}
		if exists(dst) {
			t.Fatal("the import wrote the noted kept overlay's missing base")
		}
	})
	t.Run("unreadable note", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		note := filepath.Join(s.dataDir, "kept-disks", "clone.json")
		if err := os.MkdirAll(filepath.Dir(note), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(note, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
		_, err := s.CreateVM(adminCtx(), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), note) {
			t.Fatalf("create web with an unreadable kept-disk note = %v; want FailedPrecondition naming %s", err, note)
		}
		if exists(s.images.DiskPath("web", "root")) {
			t.Fatal("the create wrote its disk while a note could not be read")
		}
	})
	t.Run("missing base elsewhere", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		noteKeep(t, s, "clone", filepath.Join(t.TempDir(), "other-base-removed-by-hand.qcow2"))
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
		if _, err := s.CreateVM(adminCtx(), req); err != nil {
			t.Fatalf("create web with another kept overlay's base missing elsewhere: %v", err)
		}
	})
}

// A create of name leaves only a file name's own note lists to
// SetAsideBeforeCreate, which reads that one note: a file another deleted
// VM's note lists, or one another noted chain reaches, at a path the create
// clears is refused before anything is moved. Moving the base of a kept
// linked clone to a .kept- name breaks the clone's chain as surely as
// removing it (rc7 lab 1 F1, after `lv rm --keep-disks` of the source).
//
// Red on 3720ac768 (the base is moved aside, or swept). Mutations: restore
// the `notesGovern && noted[f] != ""` skip of the chain holds: "base the
// source's own note lists" red; leave a file another VM's note lists to
// SetAsideBeforeCreate (refuse only without notesGovern): "file another
// VM's note lists" red.
func TestKeptNoteChain_CreateNeverMovesAnotherKeptChainsFile(t *testing.T) {
	t.Run("base the source's own note lists", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		top := noteKeep(t, s, "clone", base)
		if err := health.NoteKeptDisks(s.dataDir, "web", []string{base}); err != nil {
			t.Fatal(err)
		}
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("web"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("create web over the base of a noted kept overlay = %v; want FailedPrecondition naming %s", err, top)
		}
		sameBytes(t, "the base a noted kept overlay backs on", base, was)
	})
	t.Run("file another VM's note lists", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		if err := health.NoteKeptDisks(s.dataDir, "other", []string{base}); err != nil {
			t.Fatal(err)
		}
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("web"))
		note := filepath.Join(s.dataDir, "kept-disks", "other.json")
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), note) {
			t.Fatalf("create web over a file another VM's note lists = %v; want FailedPrecondition naming %s", err, note)
		}
		sameBytes(t, "the file another VM's note lists", base, was)
	})
	t.Run("own kept disk is still set aside", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		if err := health.NoteKeptDisks(s.dataDir, "web", []string{base}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("web")); err != nil {
			t.Fatalf("create web over its own kept disk: %v", err)
		}
		moved, _ := filepath.Glob(base + ".kept-*")
		if len(moved) != 1 {
			t.Fatalf("web's own kept disk was not set aside: %v", moved)
		}
		sameBytes(t, "web's own kept disk, set aside", moved[0], was)
	})
}

// A plain delete or a rebuild of the source of a kept linked clone is
// refused before anything is done, for a disk in a pool as in the disk
// directory: the clone's disk row is gone, so linkedClonesOf no longer sees
// it, and the kept overlay, noted or recorded, still names the source's disk
// as its base. A rebuild, with no variant that spares the disks, also
// refuses while a noted chain cannot be read; a delete then leaves that to
// the removal's own holds.
//
// Red on 3720ac768 (no such refusal). Mutation: keptBaseRefusal returns nil:
// red; skip the registry chains in it: "recorded" red.
func TestKeptBaseRefusal_SourceOfAKeptLinkedClone(t *testing.T) {
	setup := func(t *testing.T) (*Server, string) {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "pools", "kp")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(dir, "sv-root.qcow2")
		if err := qcow2.Create(base, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "sv", HostName: s.hostName, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: "sv", DiskName: "root", HostName: s.hostName, Path: base, StorageType: "dir",
				StorageVolume: "kp", DeleteWithVM: true}}); err != nil {
			t.Fatal(err)
		}
		return s, base
	}
	t.Run("noted", func(t *testing.T) {
		s, base := setup(t)
		top := noteKeep(t, s, "svc", base)
		err := s.keptBaseRefusal(adminCtx(), "sv", "delete VM", "", true, false)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), base) {
			t.Fatalf("keptBaseRefusal = %v; want FailedPrecondition naming %s and %s", err, top, base)
		}
	})
	t.Run("recorded", func(t *testing.T) {
		s, base := setup(t)
		top := registryKeep(t, s, "svc", base)
		err := s.keptBaseRefusal(adminCtx(), "sv", "delete VM", "", true, false)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("keptBaseRefusal = %v; want FailedPrecondition naming %s", err, top)
		}
	})
	t.Run("nothing kept on it", func(t *testing.T) {
		s, _ := setup(t)
		noteKeep(t, s, "other", filepath.Join(t.TempDir(), "unrelated.qcow2"))
		if err := s.keptBaseRefusal(adminCtx(), "sv", "delete VM", "", true, true); err != nil {
			t.Fatalf("keptBaseRefusal with nothing kept on sv's disk = %v", err)
		}
	})
	t.Run("unreadable", func(t *testing.T) {
		s, _ := setup(t)
		note := filepath.Join(s.dataDir, "kept-disks", "svc.json")
		if err := os.MkdirAll(filepath.Dir(note), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(note, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := s.keptBaseRefusal(adminCtx(), "sv", "delete VM", "", true, false); err != nil {
			t.Fatalf("delete: keptBaseRefusal with an unreadable note = %v; want it left to the removal's holds", err)
		}
		if err := s.keptBaseRefusal(adminCtx(), "sv", "rebuild", "", false, true); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("rebuild: keptBaseRefusal with an unreadable note = %v; want FailedPrecondition", err)
		}
	})
}
