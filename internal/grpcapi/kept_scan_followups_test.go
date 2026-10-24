package grpcapi

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// While kept-disks.json cannot be read, a symlink below a directory the scan
// lists is followed: a kept overlay in a symlinked subdirectory of a pool is
// on this host as much as one in the pool itself, and refuses the create
// that would write its missing base. A link back to a directory already
// listed ends there, a link naming nothing holds nothing, and a link that
// cannot be followed refuses, naming it, as a directory that cannot be
// listed does.
//
// Red on ac354d1a6: "an overlay below a symlinked subdirectory" and "an
// overlay a symlinked file names" (the create goes ahead and writes the
// base), and "a link that cannot be followed" (skipped). Mutation: skip
// symlinks again in keptCollisionScan (drop the ModeSymlink case): the same
// three red; list a followed directory by its link path instead of its
// resolved one: "a link back to the pool" red (the walk descends the loop
// until the path cannot be listed, and refuses).
func TestCreateVM_KeptScanFollowsASymlinkBelowARoot(t *testing.T) {
	pool := func(t *testing.T) (*Server, string) {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "ssd")
		writePathsDirPool(t, s, "ssd", dir)
		return s, dir
	}
	link := func(t *testing.T, target, at string) {
		t.Helper()
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("an overlay below a symlinked subdirectory", func(t *testing.T) {
		s, dir := pool(t)
		real := filepath.Join(t.TempDir(), "real")
		ov := filepath.Join(real, "deeper", "db-snap1.qcow2")
		base := filepath.Join(dir, "web-root.qcow2")
		overlayOn(t, ov, base)
		link(t, real, filepath.Join(dir, "sub"))
		named := unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		wantMissingBaseRefusal(t, "create with an overlay below a symlinked subdirectory", err, "db-snap1.qcow2", base)
		if !strings.Contains(err.Error(), named) {
			t.Fatalf("create web = %v; want it naming %s", err, named)
		}
	})
	t.Run("an overlay a symlinked file names", func(t *testing.T) {
		s, dir := pool(t)
		ov := filepath.Join(t.TempDir(), "db-snap1.qcow2")
		base := filepath.Join(dir, "web-root.qcow2")
		overlayOn(t, ov, base)
		link(t, ov, filepath.Join(dir, "db-snap1.qcow2"))
		unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		wantMissingBaseRefusal(t, "create with an overlay a symlink in the pool names", err, ov, base)
	})
	t.Run("a link back to the pool, and one naming nothing, go ahead", func(t *testing.T) {
		s, dir := pool(t)
		link(t, dir, filepath.Join(dir, "loop"))
		link(t, filepath.Join(t.TempDir(), "gone"), filepath.Join(dir, "dangling"))
		unreadableKeptRegistry(t, s)
		if _, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd")); err != nil {
			t.Fatalf("create on a pool no file on this host names, while kept-disks.json cannot be read: %v", err)
		}
		if !exists(filepath.Join(dir, "web-root.qcow2")) {
			t.Fatal("the create did not write its disk in the pool: this proves nothing")
		}
	})
	t.Run("a link that cannot be followed", func(t *testing.T) {
		s, dir := pool(t)
		a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
		link(t, b, a)
		link(t, a, b)
		named := unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) ||
			!(strings.Contains(err.Error(), a) || strings.Contains(err.Error(), b)) {
			t.Fatalf("create web = %v; want FailedPrecondition naming %s and the link", err, named)
		}
		if exists(filepath.Join(dir, "web-root.qcow2")) {
			t.Fatal("a refused create wrote its disk")
		}
	})
}

// While kept-disks.json cannot be read, the scan reads every file a
// kept-disk note names, wherever it is: the notes are what covers a kept
// overlay outside every directory the scan lists (a restore to an admin's
// --target-path, kept by a later delete). One that names the create's disk
// as its missing base refuses it; one that names nothing it writes does
// not.
//
// Red with the noted files dropped from the scan (review mutation m2a:
// `for f := range noted { add(f) }` removed): "a noted overlay elsewhere"
// red (the create goes ahead and writes the base).
func TestCreateVM_KeptScanReadsTheNotedFiles(t *testing.T) {
	t.Run("a noted overlay elsewhere", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		base := s.images.DiskPath("web", "root")
		ov := filepath.Join(t.TempDir(), "elsewhere", "db-snap1.qcow2")
		overlayOn(t, ov, base)
		if err := health.NoteKeptDisks(s.dataDir, "db", []string{ov}); err != nil {
			t.Fatal(err)
		}
		named := unreadableKeptRegistry(t, s)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", ""))
		wantMissingBaseRefusal(t, "create with a noted overlay elsewhere naming its disk", err, ov, base)
		if !strings.Contains(err.Error(), named) {
			t.Fatalf("create web = %v; want it naming %s", err, named)
		}
	})
	t.Run("a noted overlay elsewhere naming something else goes ahead", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		ov := filepath.Join(t.TempDir(), "elsewhere", "db-snap1.qcow2")
		overlayOn(t, ov, s.images.DiskPath("db", "root"))
		if err := health.NoteKeptDisks(s.dataDir, "db", []string{ov}); err != nil {
			t.Fatal(err)
		}
		unreadableKeptRegistry(t, s)
		if _, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "")); err != nil {
			t.Fatalf("create web, no noted file naming its disk: %v", err)
		}
		if !exists(s.images.DiskPath("web", "root")) {
			t.Fatal("the create did not write its disk: this proves nothing")
		}
	})
}

// restartWithUnreadableRegistry forgets the kept-disks.json entries held in
// memory, as a restart of the daemon does, and makes the file unparseable,
// which it returns.
func restartWithUnreadableRegistry(t *testing.T, s *Server) string {
	t.Helper()
	s.diskKept.mu.Lock()
	s.diskKept.m, s.diskKept.sig, s.diskKept.unreadable = nil, diskKeptSig{}, nil
	s.diskKept.unsaved, s.diskKept.unsavedKey, s.diskKept.warned = false, nil, false
	s.diskKept.mu.Unlock()
	named := unreadableKeptRegistry(t, s)
	if records, _ := s.diskKeptRecords(); len(records) != 0 {
		t.Fatalf("after the restart, entries are still held in memory: %+v", records)
	}
	return named
}

// Every kept-disks.json entry of this host is noted (Recorded), not only the
// disks a --keep-disks delete or a delete of a VM with no domain keeps: a
// removal that failed (a leftover), a stack teardown's, and the main
// delete's "whether another VM uses it cannot be told" were in the registry
// alone. After a restart while kept-disks.json cannot be read, the scan of
// this host's disk files then still reads such a kept overlay outside every
// directory it lists, and refuses the create that would write its missing
// base.
//
// Red with recordKeptDisks noting nothing, as on ac354d1a6 (drop its
// NoteKeptRecorded call): every subtest (the create goes ahead and writes
// the base: review NB-2.1, probes P1/P6). Mutation: read the notes in the
// scan with KeptNotedFiles (no Recorded): every subtest red.
func TestCreateVM_KeptScanReadsEveryRegistryEntryAfterARestart(t *testing.T) {
	for _, tc := range []struct {
		name   string
		record func(t *testing.T, s *Server, ov string)
	}{
		{"a removal that failed", func(t *testing.T, s *Server, ov string) {
			s.recordKeptDisks(adminCtx(), "db", s.leftoversKept([]diskLeftover{{disk: "snap1", path: ov, err: errors.New("device or resource busy")}}))
		}},
		{"whether another VM uses it cannot be told", func(t *testing.T, s *Server, ov string) {
			s.recordKeptDisks(adminCtx(), "db", []KeptDisk{{Path: ov, Disk: "snap1", Host: s.hostName,
				Reason: "whether another VM uses it cannot be told"}})
		}},
		{"a stack teardown's", func(t *testing.T, s *Server, ov string) {
			ctx := adminCtx()
			if err := corrosion.InsertVM(ctx, s.db,
				corrosion.VMRecord{Name: "db", StackName: "st", HostName: s.hostName, State: "stopped", CPUActual: 1, MemActual: 256},
				nil, []corrosion.DiskRecord{{VMName: "db", DiskName: "snap1", HostName: s.hostName, Path: ov}}); err != nil {
				t.Fatal(err)
			}
			vm, err := corrosion.GetVM(ctx, s.db, "db")
			if err != nil || vm == nil {
				t.Fatalf("seeded row = %+v, %v", vm, err)
			}
			if err := corrosion.DeleteVM(ctx, s.db, "db"); err != nil {
				t.Fatal(err)
			}
			s.NameStackTeardownKeptDisks(ctx, "st", *vm, "the teardown recorded no disk choice")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := provableCreateServer(t)
			base := s.images.DiskPath("web", "root")
			ov := filepath.Join(t.TempDir(), "elsewhere", "db-snap1.qcow2")
			overlayOn(t, ov, base)
			tc.record(t, s, ov)
			if records, _ := s.diskKeptRecords(); len(records) != 1 || records[0].Path != ov {
				t.Fatalf("kept-disks.json = %+v; want the one entry %s: this proves nothing", records, ov)
			}
			named := restartWithUnreadableRegistry(t, s)
			_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", ""))
			wantMissingBaseRefusal(t, "create after a restart, with "+tc.name+" kept elsewhere naming its disk", err, ov, base)
			if !strings.Contains(err.Error(), named) {
				t.Fatalf("create web = %v; want it naming %s", err, named)
			}
		})
	}
}

// The note of a kept-disks.json entry is for the scan alone: it does not
// hold the file, so a retry of a delete whose removal failed still removes
// it (the leftover's live disk row names it: keptRegistryChains' topNamed),
// and it goes with the entry once the file is gone. An entry on another
// host is not noted here.
//
// Mutations: note the entries as kept disks (NoteKeptDisks, Paths) in
// recordKeptDisks: "a leftover is not held" and "the note goes once the
// file is gone" red; let KeptNotedFiles return Recorded too: "a leftover is
// not held" red; drop the ForgetKeptRecorded call from judgeKeptDisks: "the
// note goes once the file is gone" red.
func TestKeptRegistry_TheNoteOfAnEntryHoldsNothing(t *testing.T) {
	t.Run("a leftover is not held", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		file := filepath.Join(t.TempDir(), "db-root.qcow2")
		if err := os.WriteFile(file, []byte("disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "db", HostName: s.hostName, State: "stopped"},
			nil, []corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: s.hostName, Path: file}}); err != nil {
			t.Fatal(err)
		}
		s.recordKeptDisks(adminCtx(), "db", s.leftoversKept([]diskLeftover{{disk: "root", path: file, err: errors.New("device or resource busy")}}))
		if files, err := health.KeptScanFiles(s.dataDir); err != nil || files[file] != "db" {
			t.Fatalf("scan files = %v (err=%v); want %s noted for db: this proves nothing", files, err, file)
		}
		if held, why := s.keptHolds(adminCtx(), file); held {
			t.Fatalf("the leftover %s is held (%s); a retry of the delete must still remove it", file, why)
		}
	})
	t.Run("the note goes once the file is gone", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		file := filepath.Join(t.TempDir(), "db-root.qcow2")
		if err := os.WriteFile(file, []byte("disk"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.recordKeptDisks(adminCtx(), "db", []KeptDisk{{Path: file, Disk: "root", Host: s.hostName, Reason: "test"}})
		if err := os.Remove(file); err != nil {
			t.Fatal(err)
		}
		s.judgeKeptDisks(context.Background())
		if records, _ := s.diskKeptRecords(); len(records) != 0 {
			t.Fatalf("the gone disk is still recorded: %+v", records)
		}
		if files, err := health.KeptScanFiles(s.dataDir); err != nil || len(files) != 0 {
			t.Fatalf("scan files = %v (err=%v); want none once the file is gone", files, err)
		}
		if _, err := os.Stat(filepath.Join(s.dataDir, "kept-disks", "db.json")); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("the empty note is left (stat err=%v)", err)
		}
	})
	t.Run("an entry on another host is not noted", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		s.recordKeptDisks(adminCtx(), "db", []KeptDisk{{Path: "/var/lib/litevirt/disks/db-root.qcow2", Disk: "root", Host: "node-3", Reason: "test"}})
		if files, err := health.KeptScanFiles(s.dataDir); err != nil || len(files) != 0 {
			t.Fatalf("scan files = %v (err=%v); want none for a disk on another host", files, err)
		}
	})
}

// A release (`lv host kept-disks --release`) of a kept-disks.json entry no
// note names as a kept disk drops the entry's recorded file from the note
// with the entry, and the note with it: judgeKeptDisks, which forgets a
// recorded file whose entry it drops, never sees an entry the release has
// already dropped, so a note left behind would name a released file for
// good.
//
// Mutation: drop the ForgetKeptRecorded call from forgetKeptRecords: red
// (the note still names the released file).
func TestKeptRelease_DropsTheRecordedNoteOfTheEntry(t *testing.T) {
	s, _ := provableCreateServer(t)
	file := s.images.DiskPath("old", "root")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(file, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	s.recordKeptDisks(adminCtx(), "old", []KeptDisk{{Path: file, Disk: "root", Host: s.hostName,
		Reason: "whether another VM uses it cannot be told"}})
	if files, err := health.KeptScanFiles(s.dataDir); err != nil || files[file] != "old" {
		t.Fatalf("scan files = %v (err=%v); want %s recorded for old: this proves nothing", files, err, file)
	}
	if files, err := health.KeptNotedFiles(s.dataDir); err != nil || len(files) != 0 {
		t.Fatalf("noted files = %v (err=%v); want none: the entry is in kept-disks.json alone", files, err)
	}
	resp, err := keptRelease(s, "old")
	if err != nil {
		t.Fatalf("release old: %v", err)
	}
	if len(resp.Chains) != 1 || !resp.Chains[0].Released {
		t.Fatalf("release answer = %+v; want the chain released", resp.Chains)
	}
	if _, err := os.Stat(file); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s is still there after the release (%v)", file, err)
	}
	if records, _ := s.diskKeptRecords(); len(records) != 0 {
		t.Fatalf("kept-disks.json still records %+v after the release", records)
	}
	if files, err := health.KeptScanFiles(s.dataDir); err != nil || len(files) != 0 {
		t.Fatalf("scan files = %v (err=%v); want none once the entry is released", files, err)
	}
	if _, err := os.Stat(filepath.Join(s.dataDir, "kept-disks", "old.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("the note of the released entry is left (stat err=%v)", err)
	}
}
