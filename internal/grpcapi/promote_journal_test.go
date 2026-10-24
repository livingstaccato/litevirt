package grpcapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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
	got, built, err := s.planPromotedDisk(context.Background(), journal, "db", "", poolDir, "root", replicaPath, "")
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

// defineDomainNaming defines name on s's fake with uuid and a disk at each
// of files: the domain a promotion defined before it wrote its marker.
func defineDomainNaming(t *testing.T, s *Server, name, uuid string, files ...string) {
	t.Helper()
	x := "<domain type='kvm'><name>" + name + "</name><uuid>" + uuid + "</uuid><devices>"
	for i, f := range files {
		x += "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='" + f +
			"'/><target dev='vd" + string(rune('a'+i)) + "' bus='virtio'/></disk>"
	}
	x += "</devices></domain>"
	if err := s.virt.(*libvirtfake.Fake).DefineDomain(x); err != nil {
		t.Fatal(err)
	}
}

const journalUUID = "aaaaaaaa-0000-0000-0000-00000000db01"

// B-3.1, B-R2, NB-R4, NB-R5 (r3): the journal is trusted only for the
// promotion of this VM still in progress here: the marker is there and
// names this VM's uuid, the entry names it too, and the target's domain is
// defined here and names the entry's file. Otherwise nothing is reused; a
// journal of no promotion in progress, or of another VM of the name, is
// dropped, and each file it named that nothing accounts for is reported as a
// vm.disk.left event (never removed, never kept). A marker that cannot be
// read reuses nothing and drops nothing.
//
// Mutations, each red in the subtests named:
//   - "no marker gate" (a missing marker trusts the journal): no marker;
//   - "no uuid" (drop both uuid checks): marker of another VM, entry of
//     another VM;
//   - B-1 "empty matches empty" (no check that both uuids are set): no uuid;
//   - "no definition check" (skip DomainExists and the sources check):
//     domain gone, domain names another file;
//   - r3 "unknown marker trusts the journal": marker unreadable;
//   - "no event" (reportLeftPromotedDisk records nothing): every dropped case.
func TestPromoteJournal_OnlyThisVMsPromotionInProgressReadsIt(t *testing.T) {
	type tc struct {
		name    string
		arrange func(t *testing.T, s *Server, file string)
		reused  bool
		dropped bool // the journal file is gone
		left    bool // a vm.disk.left event names the file
		noUUID  bool // the VM, its marker and its entry name no uuid
	}
	marker := func(uuid string) func(t *testing.T, s *Server) {
		return func(t *testing.T, s *Server) {
			if err := s.writePromoteMarkerFor("db", "", uuid); err != nil {
				t.Fatal(err)
			}
		}
	}
	cases := []tc{
		{name: "in progress", reused: true, arrange: func(t *testing.T, s *Server, file string) {
			defineDomainNaming(t, s, "db", journalUUID, file)
			marker(journalUUID)(t, s)
		}},
		{name: "no marker", dropped: true, left: true, arrange: func(t *testing.T, s *Server, file string) {
			defineDomainNaming(t, s, "db", journalUUID, file)
		}},
		{name: "marker of another VM", dropped: true, left: true, arrange: func(t *testing.T, s *Server, file string) {
			defineDomainNaming(t, s, "db", journalUUID, file)
			marker("bbbbbbbb-0000-0000-0000-000000000002")(t, s)
		}},
		{name: "entry of another VM", left: true, arrange: func(t *testing.T, s *Server, file string) {
			defineDomainNaming(t, s, "db", journalUUID, file)
			marker(journalUUID)(t, s)
			e := s.readPromoteDisks("db")["root"]
			e.UUID = "bbbbbbbb-0000-0000-0000-000000000002"
			if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{}, e); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "domain gone", dropped: true, left: true, arrange: func(t *testing.T, s *Server, file string) {
			marker(journalUUID)(t, s)
		}},
		{name: "domain names another file", left: true, arrange: func(t *testing.T, s *Server, file string) {
			defineDomainNaming(t, s, "db", journalUUID, file+"-other.qcow2")
			marker(journalUUID)(t, s)
		}},
		{name: "no uuid", noUUID: true, dropped: true, left: true, arrange: func(t *testing.T, s *Server, file string) {
			// A uuid-less VM (a plain `lv import`): nothing binds the
			// journal to it, whatever else matches.
			defineDomainNaming(t, s, "db", journalUUID, file)
			marker("")(t, s)
		}},
		{name: "marker unreadable", arrange: func(t *testing.T, s *Server, file string) {
			defineDomainNaming(t, s, "db", journalUUID, file)
			marker(journalUUID)(t, s)
			dir := filepath.Dir(s.promoteMarkerPath("db"))
			if err := os.Chmod(dir, 0o000); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, _, replicaPath, file, journal := promoteJournalSetup(t)
			e := journal["root"]
			e.UUID = journalUUID
			vmUUID := journalUUID
			if c.noUUID {
				e.UUID, vmUUID = "", ""
			}
			if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{}, e); err != nil {
				t.Fatal(err)
			}
			c.arrange(t, s, file)
			got := s.promoteDisksForAttempt(adminCtx(), "db", vmUUID)
			_ = os.Chmod(filepath.Dir(s.promoteMarkerPath("db")), 0o700)
			if reused := got["root"].Path == file && got["root"].Replica == replicaPath; reused != c.reused {
				t.Errorf("journal read = %+v, want the entry for %s read: %v", got, file, c.reused)
			}
			if _, err := os.Stat(s.promoteDiskJournalPath("db")); errors.Is(err, os.ErrNotExist) != c.dropped {
				t.Errorf("journal dropped = %v (err=%v), want %v", errors.Is(err, os.ErrNotExist), err, c.dropped)
			}
			if b, err := os.ReadFile(file); err != nil || string(b) != "an earlier attempt's live disk" {
				t.Errorf("the file the journal named was touched: %q, %v", b, err)
			}
			if held, why := s.keptNoteHolds(file); held {
				t.Errorf("the left file was marked kept: %s", why)
			}
			var left bool
			for _, ev := range vmEventsOf(t, s, "db", "vm.disk.left") {
				if strings.Contains(ev.Detail, file) && ev.Severity == "warn" {
					left = true
				}
			}
			if left != c.left {
				t.Errorf("a vm.disk.left event names %s: %v, want %v", file, left, c.left)
			}
		})
	}
}

// NB-R4: a file a row or a kept-disk record accounts for is not reported as
// left when the journal is dropped: it is a VM's disk, or a kept one.
//
// Mutation "report every file" (reportLeftPromotedDisk without its row and
// kept checks) — red.
func TestPromoteJournal_ADroppedJournalReportsOnlyFilesNothingAccountsFor(t *testing.T) {
	s, _, _, file, journal := promoteJournalSetup(t)
	if err := health.NoteKeptDisks(s.dataDir, "olddb", []string{file}); err != nil {
		t.Fatal(err)
	}
	if err := s.recordPromoteDisk("db", map[string]promotedDiskEntry{}, journal["root"]); err != nil {
		t.Fatal(err)
	}
	s.dropPromoteDisks(adminCtx(), "db", "test")
	if evs := vmEventsOf(t, s, "db", "vm.disk.left"); len(evs) != 0 {
		t.Errorf("a kept disk was reported as left: %+v", evs)
	}
}

// NB-R5 (r2): a recorded file outside the target pool is never reused (a
// retry with another --target-pool).
//
// Mutation r2 (reusablePromotedDisk without its pool check) — red.
func TestPromoteJournal_AFileInAnotherPoolIsNeverReused(t *testing.T) {
	s, poolDir, replicaPath, _, journal := promoteJournalSetup(t)
	elsewhere := filepath.Join(t.TempDir(), filepath.Base(journal["root"].Path))
	if err := os.WriteFile(elsewhere, []byte("built in another pool"), 0o600); err != nil {
		t.Fatal(err)
	}
	journal["root"] = promotedDiskEntry{Disk: "root", Path: elsewhere, Replica: replicaPath}
	if planReuses(t, s, journal, poolDir, replicaPath, elsewhere) {
		t.Fatalf("%s, outside the target pool %s, was reused", elsewhere, poolDir)
	}
}

// B-R1: the in-flight register refuses a second promotion of a target and
// frees it once the first returns.
func TestPromote_BeginPromoteRefusesASecondOfTheTarget(t *testing.T) {
	s := testServer(t)
	end, err := s.beginPromote("db")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.beginPromote("db"); status.Code(err) != codes.Aborted {
		t.Fatalf("a second promotion of db = %v, want Aborted", err)
	}
	if end2, err := s.beginPromote("web"); err != nil {
		t.Fatalf("a promotion of another target: %v", err)
	} else {
		end2()
	}
	end()
	if end3, err := s.beginPromote("db"); err != nil {
		t.Fatalf("after the first returned: %v", err)
	} else {
		end3()
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
		if got := s.promoteDisksForAttempt(adminCtx(), "db", ""); len(got) != 0 {
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

// adoptablePromotedDisk makes, in pool's directory, the live disk an earlier
// attempt of a promotion of target from the fixture's replica
// (root-20260101-000000.raw) built, and returns the <disk> element of the
// domain that runs from it. An adopted domain is taken over only with the
// live disk it runs from (NB-R3).
func adoptablePromotedDisk(t *testing.T, s *Server, pool, target string) string {
	t.Helper()
	ref, ok := s.lookupStoragePool(pool)
	if !ok {
		t.Fatalf("no pool %s", pool)
	}
	f := filepath.Join(ref.Target, target+"-promoted-root-20260101-000000-00000000000000ad.qcow2")
	if err := os.WriteFile(f, []byte("the live disk the adopted domain runs from"), 0o600); err != nil {
		t.Fatal(err)
	}
	return "<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='" + f +
		"'/><target dev='vda' bus='virtio'/></disk>"
}
