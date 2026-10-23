package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// staleChain lays out, in dir, a disk with two external snapshots as the rc3
// lab 2 drill had it: base <vm>-root.qcow2, overlay <vm>-root.s1 on it, and
// <vm>-root.s2 on s1, the file the disk record names. It returns base, s1
// and s2.
func staleChain(t *testing.T, dir, vm string) (string, string, string) {
	t.Helper()
	base := filepath.Join(dir, vm+"-root.qcow2")
	s1 := filepath.Join(dir, vm+"-root.s1")
	s2 := filepath.Join(dir, vm+"-root.s2")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(s1, base, "qcow2", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(s2, s1, "qcow2", 0, nil); err != nil {
		t.Fatal(err)
	}
	return base, s1, s2
}

// rc3 lab 2, F1: a VM with no domain anywhere is deleted while a host does not
// answer whether it runs there, so the stale-record path keeps its disk. It
// used to record only the top of the disk's chain, in kept-disks.json, and
// write no kept-disk note, so nothing held s1 or the base under it, and a
// create of the name cleared the base and wrote its own disk there. Now the
// delete writes the note `lv rm --keep-disks` writes: every kept file in
// paths, and every file the kept disk backs on in under too, so the guards
// that read the note hold them.
//
// Red on 7e610a7f7 (no note). Mutation: drop the noteDeleteKeptDisks call
// from the stale-record path, or note only the tops (skip under): red.
func TestDeleteVM_StaleRecordWithASilentPeerNotesTheKeptChain(t *testing.T) {
	base, s1, s2 := staleChain(t, t.TempDir(), "a")
	s, _ := deleteDiskServerWith(t, false,
		corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: s2, StorageType: "local", DeleteWithVM: true})
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "peer-x", Address: "203.0.113.9", State: "active", CPUTotal: 4, MemTotal: 4096,
	}); err != nil {
		t.Fatal(err)
	}

	kept, err := deleteNamed(t, s)
	if err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm != nil {
		t.Fatal("the record survived: this is not the stale-record path's success")
	}
	for _, p := range []string{base, s1, s2} {
		if !exists(p) {
			t.Fatalf("%s went while a host did not answer", filepath.Base(p))
		}
	}
	assertNamed(t, s, kept, true, s2, "peer-x")

	raw, err := os.ReadFile(filepath.Join(s.dataDir, "kept-disks", "a.json"))
	if err != nil {
		t.Fatalf("no kept-disk note for a: %v", err)
	}
	var note struct {
		Paths []string `json:"paths"`
		Under []string `json:"under"`
	}
	if err := json.Unmarshal(raw, &note); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{s2, s1, base} {
		if !slices.Contains(note.Paths, p) {
			t.Errorf("the note's paths %v do not name %s", note.Paths, filepath.Base(p))
		}
	}
	for _, p := range []string{s1, base} {
		if !slices.Contains(note.Under, p) {
			t.Errorf("the note's under %v does not name %s, which the kept disk backs on", note.Under, filepath.Base(p))
		}
		if held, _ := s.keptNoteHolds(p); !held {
			t.Errorf("%s is not held by the note", filepath.Base(p))
		}
	}
}

// A note that cannot be read fails the stale-record delete closed: the
// record, and so the name, is kept, rather than the kept chain left with no
// note.
//
// Mutation: ignore noteDeleteKeptDisks's error: red.
func TestDeleteVM_StaleRecordKeepsTheRecordWhenTheNoteCannotBeRead(t *testing.T) {
	_, _, s2 := staleChain(t, t.TempDir(), "a")
	s, _ := deleteDiskServerWith(t, false,
		corrosion.DiskRecord{VMName: "a", DiskName: "root", Path: s2, StorageType: "local", DeleteWithVM: true})
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "peer-x", Address: "203.0.113.9", State: "active", CPUTotal: 4, MemTotal: 4096,
	}); err != nil {
		t.Fatal(err)
	}
	note := filepath.Join(s.dataDir, "kept-disks", "a.json")
	if err := os.MkdirAll(filepath.Dir(note), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(note, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := deleteNamed(t, s)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), note) {
		t.Fatalf("DeleteVM with an unreadable note = %v; want FailedPrecondition naming %s", err, note)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "a"); vm == nil {
		t.Fatal("the record went with the kept chain unnoted")
	}
}

// debrisFixture is a server with an image store and no VM web, and web's
// base disk <disks>/web-root.qcow2 holding data, as a deleted VM of the name
// left it. It returns the server, the base and its bytes.
func debrisFixture(t *testing.T) (*Server, string, []byte) {
	t.Helper()
	s, _ := provableCreateServer(t)
	base := s.images.DiskPath("web", "root")
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(base, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("THE ONLY COPY OF THE GUEST'S DATA"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	b, err := os.ReadFile(base)
	if err != nil {
		t.Fatal(err)
	}
	return s, base, b
}

// createRefused runs a create of web and checks it was refused
// FailedPrecondition naming want, with base byte-identical and in place.
func createRefused(t *testing.T, s *Server, base string, was []byte, want string) {
	t.Helper()
	_, err := s.CreateVM(adminCtx(), disklessCreateRequest("web"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		t.Fatalf("create web = %v; want FailedPrecondition naming %q", err, want)
	}
	got, rerr := os.ReadFile(base)
	if rerr != nil || !bytes.Equal(got, was) {
		t.Fatalf("%s was cleared or changed by a refused create (err=%v)", filepath.Base(base), rerr)
	}
	if vm, _ := corrosion.GetVM(adminCtx(), s.db, "web"); vm != nil {
		t.Fatal("a refused create wrote the VM's row")
	}
}

// A create never clears a disk file a kept chain backs on: its debris sweep
// removes <vm>-*.qcow2 left by an earlier VM of the name before the create
// writes its own disk there, so before this it removed the base of a kept
// snapshot chain whenever no kept-disk note named it, and the new VM's disk
// took its place (rc3 lab 2, F1). The create is refused, naming the file and
// why, with the base as it was:
//
//   - an overlay beside it of the name whose qcow2 chain reaches it, with no
//     note and no record at all;
//   - a disk kept-disks.json records as kept, whose chain reaches it, as an
//     older build's stale-record delete left it (registry only, no note);
//   - kept-disks.json that cannot be read (fail closed).
//
// The control shows the sweep does clear the base when nothing holds it, so
// the refusals are not the sweep doing nothing.
//
// Red on 7e610a7f7: the create succeeds and the base is gone. Mutations: drop
// the sibling scan, the kept-disks.json chain walk, or its unreadable check
// from keptFileCreateRefusal: the matching subtest goes red.
func TestCreateVM_NeverClearsAFileAKeptChainBacksOn(t *testing.T) {
	t.Run("control: unheld debris is cleared", func(t *testing.T) {
		s, base, _ := debrisFixture(t)
		if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("web")); err != nil {
			t.Fatalf("create web: %v", err)
		}
		if exists(base) {
			t.Fatal("the sweep left unheld debris: the refusals below would prove nothing")
		}
	})
	t.Run("overlay beside it", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		ov := strings.TrimSuffix(base, ".qcow2") + ".s1"
		if err := qcow2.CreateWithBackingFormat(ov, base, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		createRefused(t, s, base, was, ov+" beside it backs on")
		if !exists(ov) {
			t.Fatal("the overlay went")
		}
	})
	t.Run("kept-disks.json only", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		top := filepath.Join(t.TempDir(), "kept-top.qcow2") // not beside it: the record alone holds the base
		if err := qcow2.CreateWithBackingFormat(top, base, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		s.recordKeptDisks(adminCtx(), "web", []KeptDisk{{Path: top, Disk: "root", Host: s.hostName,
			Reason: "whether the VM runs elsewhere cannot be told: no answer from node-3"}})
		createRefused(t, s, base, was, diskKeptFile)
	})
	t.Run("kept-disks.json unreadable", func(t *testing.T) {
		s, base, was := debrisFixture(t)
		if err := os.WriteFile(filepath.Join(s.dataDir, diskKeptFile), []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := s.CreateVM(adminCtx(), disklessCreateRequest("web"))
		if err == nil || !strings.Contains(err.Error(), diskKeptFile) {
			t.Fatalf("create web with kept-disks.json unreadable = %v; want a refusal naming it", err)
		}
		if got, _ := os.ReadFile(base); !bytes.Equal(got, was) {
			t.Fatal("the base was cleared while kept-disks.json could not be read")
		}
	})
}

// An import never moves aside, as an orphan, a file a delete kept or one a
// kept disk backs on: only kept-disks.json, or only a note, names it, and no
// database row does (rc3 lab 2, F1, at the import's disk name).
//
// Red on 7e610a7f7: the file is moved aside as an orphan. Mutation: drop the
// keptFileCreateRefusal call from clearImportDiskName: red.
func TestImportVM_AFileAKeptDiskHoldsIsNotAnOrphan(t *testing.T) {
	t.Run("kept-disks.json", func(t *testing.T) {
		s, dst := orphanFixture(t, "imp-kn")
		plantOld(t, dst, "kept base")
		top := filepath.Join(t.TempDir(), "kept-top.qcow2")
		if err := qcow2.CreateWithBackingFormat(top, dst, "raw", 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		s.recordKeptDisks(adminCtx(), "imp-kn", []KeptDisk{{Path: top, Disk: "root", Host: s.hostName, Reason: "no answer from node-3"}})
		refusedAndUntouched(t, s, "imp-kn", dst, "kept base")
	})
	t.Run("note", func(t *testing.T) {
		s, dst := orphanFixture(t, "imp-kn")
		plantOld(t, dst, "kept base")
		if err := health.NoteKeptBackingFiles(s.dataDir, "imp-kn", []string{dst}); err != nil {
			t.Fatal(err)
		}
		refusedAndUntouched(t, s, "imp-kn", dst, "kept base")
	})
}
