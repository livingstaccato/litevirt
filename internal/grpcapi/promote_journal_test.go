package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// replicaPathOf is the full path of vm's replica file in poolDir (project "").
func replicaPathOf(t *testing.T, poolDir, vm, file string) string {
	t.Helper()
	return filepath.Join(replicaOwnerDir(poolDir, "", vm), file)
}

// A promotion finished, but its journal of live-disk names outlived it: the
// remove failed (here the journal's directory refuses it; a crash at the
// same point does the same). The promoted VM is later deleted with
// --keep-disks, so its live disk P is a kept disk that no row names. A new
// VM of the name, on the dead host again, is promoted from the same replica.
// That promotion must never take P as the new VM's root: it builds a fresh
// live disk and leaves P exactly as it was.
//
// Red on 723399e05: the leftover journal entry is reused, and the new VM's
// root row names the kept disk.
func TestPromote_ALeftoverJournalNeverAdoptsAKeptDisk(t *testing.T) {
	s := testServer(t)
	poolDir := setPromoteVMRows(t, s, "db", nil)
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
	jdir := filepath.Dir(s.promoteDiskJournalPath("db"))
	f := s.virt.(*libvirtfake.Fake)
	f.FailStartDomain = func(string) error {
		// The journal is written by now; its remove at the end will fail.
		return os.Chmod(jdir, 0o500)
	}
	t.Cleanup(func() { _ = os.Chmod(jdir, 0o700) })
	promoteSet(t, s, req)
	f.FailStartDomain = nil
	if err := os.Chmod(jdir, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(s.promoteDiskJournalPath("db")); err != nil {
		t.Fatalf("the journal did not outlive the promotion (%v); the setup is not the one this test needs", err)
	}
	p := diskRowsOf(t, s, "db")["root"].Path

	// lv rm db --keep-disks: rows and domain gone, P kept and noted.
	if err := corrosion.DeleteVM(context.Background(), s.db, "db"); err != nil {
		t.Fatal(err)
	}
	_ = f.UndefineDomain("db", false)
	if err := health.NoteKeptDisks(s.dataDir, "db", []string{p}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("the kept disk's own data"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A new VM db on dead-host, promoted from the same replica.
	spec, _ := json.Marshal(&pb.VMSpec{Name: "db", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "db", HostName: "dead-host", State: "running", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: "dead-host", Path: "/dead/db-root.qcow2",
			SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda", Bus: "virtio"}}); err != nil {
		t.Fatal(err)
	}
	s.virt = libvirtfake.New()
	promoteSet(t, s, req)

	root := diskRowsOf(t, s, "db")["root"]
	if root.Path == p {
		t.Fatalf("the new VM's root row names the kept disk %s", p)
	}
	if root.HostName != s.hostName || filepath.Dir(root.Path) != poolDir {
		t.Errorf("root row = %+v, want a fresh live disk in %s", root, poolDir)
	}
	if b, err := os.ReadFile(p); err != nil || string(b) != "the kept disk's own data" {
		t.Errorf("the kept disk was touched: %q, %v", b, err)
	}
}

// promoteJournalSetup is a pool with db's replica, a regular file at a
// fresh live-disk name in it, and a journal entry for the root naming that
// file as built from the replica: everything a reuse needs, which each test
// then takes one thing away from.
func promoteJournalSetup(t *testing.T) (s *Server, poolDir, replicaPath, file string, journal map[string]promotedDiskEntry) {
	t.Helper()
	s = testServer(t)
	poolDir = setPromoteVMRows(t, s, "db", nil)
	replica := seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	replicaPath = replicaPathOf(t, poolDir, "db", replica)
	file = s.freshPromotedPath(poolDir, "db", replica)
	if err := os.WriteFile(file, []byte("an earlier attempt's live disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal = map[string]promotedDiskEntry{"root": {Disk: "root", Path: file, Replica: replicaPath}}
	return s, poolDir, replicaPath, file, journal
}

// planReuses is planPromotedDisk's answer for the root: whether it reuses
// file, and that a fresh path is never file.
func planReuses(t *testing.T, s *Server, journal map[string]promotedDiskEntry, poolDir, replicaPath, file string) bool {
	t.Helper()
	got, built, err := s.planPromotedDisk(context.Background(), journal, "db", poolDir, "root", replicaPath, "")
	if err != nil {
		t.Fatal(err)
	}
	if built != (got == file) {
		t.Fatalf("plan = %s built=%v: a reuse must be of the recorded file, a build never at it", got, built)
	}
	return built
}

// The positive control the reuse checks below are judged against: an entry
// of this replica naming a regular file in the pool that no row and no kept
// disk names is reused.
func TestPromoteJournal_AnEntryPassingEveryCheckIsReused(t *testing.T) {
	s, poolDir, replicaPath, file, journal := promoteJournalSetup(t)
	if !planReuses(t, s, journal, poolDir, replicaPath, file) {
		t.Fatal("an entry passing every check was not reused")
	}
}

// NB-3.2: a file a disk row names is never reused.
//
// Mutation m3a (drop diskRowNames from reusablePromotedDisk) — red.
func TestPromoteJournal_AFileADiskRowNamesIsNeverReused(t *testing.T) {
	s, poolDir, replicaPath, file, journal := promoteJournalSetup(t)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "web", HostName: s.hostName, State: "running", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: s.hostName, Path: file, SizeBytes: 1 << 20, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	if planReuses(t, s, journal, poolDir, replicaPath, file) {
		t.Fatalf("%s, the disk of VM web, was reused as db's live disk", file)
	}
}

// NB-3.2 and NB-3.3: an entry built from another replica is never reused,
// even one with the same file name in another VM's owner directory (two VMs'
// replicas taken in the same second).
//
// Mutation m3b (drop the replica check) — red.
// Mutation "bare name" (compare filepath.Base of the two replicas) — red.
func TestPromoteJournal_AnEntryOfAnotherReplicaIsNeverReused(t *testing.T) {
	s, poolDir, replicaPath, file, journal := promoteJournalSetup(t)
	other := filepath.Join(replicaOwnerDir(poolDir, "", "web"), filepath.Base(replicaPath))
	journal["root"] = promotedDiskEntry{Disk: "root", Path: file, Replica: other}
	if planReuses(t, s, journal, poolDir, replicaPath, file) {
		t.Fatalf("a file built from %s was reused for a promotion from %s", other, replicaPath)
	}
}

// B-3.1: a file a kept-disk note names, or a kept-disks.json entry names, is
// never reused; while the notes cannot be read nothing is, and a fresh disk
// is built (the promotion does not block).
//
// Mutation "no kept check" (drop keptHolds from reusablePromotedDisk) — red:
// all three subtests.
func TestPromoteJournal_AKeptDiskIsNeverReused(t *testing.T) {
	t.Run("note", func(t *testing.T) {
		s, poolDir, replicaPath, file, journal := promoteJournalSetup(t)
		if err := health.NoteKeptDisks(s.dataDir, "old", []string{file}); err != nil {
			t.Fatal(err)
		}
		if planReuses(t, s, journal, poolDir, replicaPath, file) {
			t.Fatalf("%s, a disk a kept-disk note names, was reused", file)
		}
	})
	t.Run("registry", func(t *testing.T) {
		s, poolDir, replicaPath, file, journal := promoteJournalSetup(t)
		s.recordKeptDisks(adminCtx(), "old", []KeptDisk{{Path: file, Disk: "root", Host: s.hostName, Reason: "kept by lv rm --keep-disks"}})
		if planReuses(t, s, journal, poolDir, replicaPath, file) {
			t.Fatalf("%s, a disk kept-disks.json names, was reused", file)
		}
	})
	t.Run("notes unreadable", func(t *testing.T) {
		s, poolDir, replicaPath, file, journal := promoteJournalSetup(t)
		dir := filepath.Join(s.dataDir, "kept-disks")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "old.json"), []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if planReuses(t, s, journal, poolDir, replicaPath, file) {
			t.Fatalf("%s was reused while the kept-disk notes cannot be read", file)
		}
	})
}

// B-3.1: the journal is trusted only while the target's promote marker is
// there. With no marker it is dropped; with one it is read.
//
// Mutation "no marker gate" (promoteDisksForAttempt reads the journal with
// no marker) — red.
func TestPromoteJournal_OnlyAPromotionInProgressReadsIt(t *testing.T) {
	s, _, replicaPath, file, journal := promoteJournalSetup(t)
	if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{}, journal["root"]); err != nil {
		t.Fatal(err)
	}
	if err := s.writePromoteMarker("db", ""); err != nil {
		t.Fatal(err)
	}
	if got := s.promoteDisksForAttempt("db"); got["root"].Path != file || got["root"].Replica != replicaPath {
		t.Fatalf("with the marker there the journal reads %+v, want the entry for %s", got, file)
	}
	s.removePromoteMarker("db")
	if got := s.promoteDisksForAttempt("db"); len(got) != 0 {
		t.Fatalf("with no marker the journal reads %+v, want nothing", got)
	}
	if _, err := os.Stat(s.promoteDiskJournalPath("db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a journal with no marker beside it was not dropped (err=%v)", err)
	}
	if _, err := os.Stat(file); err != nil {
		t.Errorf("dropping the journal touched the file it named: %v", err)
	}
}

// B-3.1: an attempt that ends removes its journal and its marker. When the
// journal cannot be removed the marker goes all the same, and the next
// promotion, finding no marker, drops the journal instead of reading it.
// (endPromoteAttempt clears the journal first, so a crash between the two
// leaves a marker with nothing to reuse; that order is not observable
// without a crash, and the marker gate covers the other order.)
//
// Mutation "journal kept" (endPromoteAttempt clears no journal) — red
// ("ends").
func TestPromoteJournal_EndingAnAttemptLeavesNothingToReuse(t *testing.T) {
	start := func(t *testing.T) *Server {
		s, _, _, _, journal := promoteJournalSetup(t)
		if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{}, journal["root"]); err != nil {
			t.Fatal(err)
		}
		if err := s.writePromoteMarker("db", ""); err != nil {
			t.Fatal(err)
		}
		return s
	}
	t.Run("ends", func(t *testing.T) {
		s := start(t)
		s.endPromoteAttempt("db")
		if _, err := os.Stat(s.promoteDiskJournalPath("db")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the journal is left (err=%v)", err)
		}
		if s.promoteMarkerPresent("db") {
			t.Error("the marker is left")
		}
	})
	t.Run("journal not removable", func(t *testing.T) {
		s := start(t)
		jdir := filepath.Dir(s.promoteDiskJournalPath("db"))
		if err := os.Chmod(jdir, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(jdir, 0o700) })
		s.endPromoteAttempt("db")
		if s.promoteMarkerPresent("db") {
			t.Error("the marker is left beside a journal that could not be removed")
		}
		if err := os.Chmod(jdir, 0o700); err != nil {
			t.Fatal(err)
		}
		if got := s.promoteDisksForAttempt("db"); len(got) != 0 {
			t.Errorf("the next attempt reads %+v from an attempt that ended", got)
		}
	})
}

// NB-3.4: adopting a domain an earlier attempt started while its definition
// cannot be read. Its recorded live disk is taken only under the reuse
// rules; otherwise the adoption is refused and nothing is changed — never
// the first regular file found.
//
// Red on 723399e05 ("kept" subtest): the kept disk is taken as the root.
// Mutation "first file" (adoptedPromotedDisk takes the journal entry with no
// reuse check when the definition is unread) — red ("kept").
func TestPromote_AnAdoptionWithAnUnreadDomainTakesOnlyAQualifiedEntry(t *testing.T) {
	setup := func(t *testing.T) (*Server, *libvirtfake.Fake, *pb.PromoteReplicaRequest, string) {
		s := testServer(t)
		poolDir := setPromoteVMRows(t, s, "db", nil)
		seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
		req := &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true}
		f := s.virt.(*libvirtfake.Fake)
		f.FailStartDomain = func(name string) error {
			f.SetState(name, libvirtfake.StateRunning) // qemu is up; the daemon dies
			panic("crash")
		}
		crashPromote(t, s, req)
		f.FailStartDomain = nil
		built := promotedFiles(t, poolDir, "db")
		if len(built) != 1 {
			t.Fatalf("the crashed attempt left %v, want exactly its one live disk", built)
		}
		f.FailDumpXML = func(string) error { return errors.New("libvirt: connection reset") }
		return s, f, req, built[0]
	}
	t.Run("qualified", func(t *testing.T) {
		s, _, req, built := setup(t)
		promoteSet(t, s, req)
		if root := diskRowsOf(t, s, "db")["root"]; root.HostName != s.hostName || root.Path != built {
			t.Errorf("root row = %+v, want the recorded live disk %s", root, built)
		}
	})
	t.Run("kept", func(t *testing.T) {
		s, _, req, built := setup(t)
		if err := health.NoteKeptDisks(s.dataDir, "old", []string{built}); err != nil {
			t.Fatal(err)
		}
		before, _ := os.ReadFile(built)
		err := s.PromoteReplica(req, &streamRecorder[pb.PromoteReplicaProgress]{ctx: adminCtx()})
		if err == nil {
			t.Fatalf("the adoption went ahead; root row = %+v", diskRowsOf(t, s, "db")["root"])
		}
		if root := diskRowsOf(t, s, "db")["root"]; root.Path == built || root.HostName == s.hostName {
			t.Errorf("root row = %+v after a refused adoption, want it unchanged", root)
		}
		if after, rerr := os.ReadFile(built); rerr != nil || !bytes.Equal(after, before) {
			t.Errorf("the kept file was touched (err=%v)", rerr)
		}
	})
}
