package grpcapi

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// keptChainFixture is a deleted VM old's kept chain on s, as a stale-record
// delete leaves it: base <old>-root.qcow2 and the overlay <old>-root.s1 on
// it, both in old's note (the overlay as a kept disk, the base under it), and
// the overlay in kept-disks.json. It returns the overlay and the base.
func keptChainFixture(t *testing.T, s *Server) (string, string) {
	t.Helper()
	base := s.images.DiskPath("old", "root")
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	top := strings.TrimSuffix(base, ".qcow2") + ".s1"
	if err := qcow2.CreateWithBackingFormat(top, base, "qcow2", 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptDisks(s.dataDir, "old", []string{top}); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptBackingFiles(s.dataDir, "old", []string{base}); err != nil {
		t.Fatal(err)
	}
	s.recordKeptDisks(adminCtx(), "old", []KeptDisk{{Path: top, Disk: "root", Host: s.hostName,
		Reason: "whether the VM runs elsewhere cannot be told: no answer from node-3"}})
	return top, base
}

// keptRelease releases what as the CLI does: a dry run, then the release
// with exactly the files and snapshot records the dry run named (sent even
// when the dry run says it is refused, so the server's refusal is what the
// test sees).
func keptRelease(s *Server, what string) (*pb.KeptDisksResponse, error) {
	plan, err := s.KeptDisks(adminCtx(), &pb.KeptDisksRequest{Release: what, DryRun: true})
	if err != nil {
		return nil, err
	}
	req := &pb.KeptDisksRequest{Release: what}
	for _, ch := range plan.Chains {
		for _, f := range ch.Files {
			req.ExpectPaths = append(req.ExpectPaths, f.Path)
		}
		for _, n := range ch.Snapshots {
			if !slices.Contains(req.ExpectSnapshots, n) {
				req.ExpectSnapshots = append(req.ExpectSnapshots, n)
			}
		}
	}
	return s.KeptDisks(adminCtx(), req)
}

// keptIntact checks that a refused release removed nothing: the files, the
// note and the record entry are all there.
func keptIntact(t *testing.T, s *Server, files ...string) {
	t.Helper()
	for _, f := range files {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s went in a refused release: %v", filepath.Base(f), err)
		}
	}
	if _, err := os.Stat(filepath.Join(s.dataDir, "kept-disks", "old.json")); err != nil {
		t.Errorf("old's note went in a refused release: %v", err)
	}
	recs, _ := s.diskKeptRecords()
	if len(recs) == 0 {
		t.Error("the kept-disks.json entry went in a refused release")
	}
}

func keptRefusedNaming(t *testing.T, err error, code codes.Code, want string) {
	t.Helper()
	if status.Code(err) != code || !strings.Contains(err.Error(), want) {
		t.Fatalf("release = %v; want %v naming %q", err, code, want)
	}
}

// The release removes the chain, overlay before base, its note and its
// record entry, writes an audit row naming each file and its size, and
// clears disk_leftover.
//
// Mutation: drop the note removal (health.ForgetKeptNoted): red. (Dropping
// the record removal alone stays green: the judge pass the release runs
// forgets an entry whose file is gone.)
func TestKeptRelease_RemovesTheChainItsNoteAndRecord(t *testing.T) {
	s, _ := provableCreateServer(t)
	top, base := keptChainFixture(t, s)
	s.judgeKeptDisks(adminCtx())
	row, found, _ := corrosion.GetHealthCondition(adminCtx(), s.db, diskLeftoverEvaluator, condDiskLeftover, "host", s.hostName)
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatal("disk_leftover is not raised for the kept chain: the test proves nothing")
	}

	list, err := s.KeptDisks(viewerCtx(), &pb.KeptDisksRequest{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list.Chains) != 1 || len(list.Chains[0].Files) != 2 || list.Chains[0].Files[0].Path != top ||
		list.Chains[0].Files[1].Path != base || !list.Chains[0].Files[1].Under || list.Chains[0].Held != "" ||
		list.Chains[0].VmName != "old" || list.Chains[0].KeptAt == "" || len(list.Chains[0].Records) != 2 {
		t.Fatalf("list = %+v; want one releasable chain of old, %s then %s under, named by its note and the record", list.Chains, top, base)
	}

	resp, err := keptRelease(s, "old")
	if err != nil {
		t.Fatalf("release old: %v", err)
	}
	if len(resp.Chains) != 1 || !resp.Chains[0].Released {
		t.Fatalf("release answer = %+v; want the chain released", resp.Chains)
	}
	for _, f := range []string{top, base} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s is still there after the release (%v)", filepath.Base(f), err)
		}
	}
	if _, err := os.Stat(filepath.Join(s.dataDir, "kept-disks", "old.json")); !os.IsNotExist(err) {
		t.Errorf("old's note is still there after the release (%v)", err)
	}
	if b, _ := os.ReadFile(filepath.Join(s.dataDir, diskKeptFile)); strings.Contains(string(b), top) {
		t.Errorf("kept-disks.json still names %s after the release: %s", top, b)
	}
	row, found, _ = corrosion.GetHealthCondition(adminCtx(), s.db, diskLeftoverEvaluator, condDiskLeftover, "host", s.hostName)
	if !found || row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("disk_leftover after the release = %+v (found %v); want resolved", row, found)
	}
	a := lastAuditRow(t, s, keptReleaseAudit)
	if !a.found || a.result != "ok" || a.user != "admin" || !strings.Contains(a.detail, top+" (") ||
		!strings.Contains(a.detail, base+" (") || !strings.Contains(a.detail, "bytes") {
		t.Errorf("audit row = %+v; want an ok row by admin naming %s and %s with their sizes", a, top, base)
	}
}

// Releasing by a file under the chain releases the whole chain: never the
// base alone under an overlay that names it.
func TestKeptRelease_ByAFileUnderTheChainTakesTheWholeChain(t *testing.T) {
	s, _ := provableCreateServer(t)
	top, base := keptChainFixture(t, s)
	resp, err := s.KeptDisks(adminCtx(), &pb.KeptDisksRequest{Release: base, DryRun: true})
	if err != nil {
		t.Fatalf("dry run by %s: %v", base, err)
	}
	if len(resp.Chains) != 1 || len(resp.Chains[0].Files) != 2 || resp.Chains[0].Files[0].Path != top {
		t.Fatalf("a release by the base would remove %+v; want the overlay %s first, then the base", resp.Chains, top)
	}
	keptIntact(t, s, top, base)
	if _, err := keptRelease(s, base); err != nil {
		t.Fatalf("release by %s: %v", base, err)
	}
	for _, f := range []string{top, base} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s is still there: a release by the base left part of the chain (%v)", filepath.Base(f), err)
		}
	}
}

// Every refusal removes nothing: not a file, not the note, not the record.
//
// Mutations (each red in its own case): drop the live disk row check, the
// backing chain check (snapshotFileUsers), the snapshot record check, the
// other-kept-chain check, either domain check.
func TestKeptRelease_RefusedWhileReferenced(t *testing.T) {
	t.Run("a live disk row names a file", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		if err := corrosion.InsertDisk(adminCtx(), s.db, corrosion.DiskRecord{VMName: "web2", DiskName: "data",
			HostName: s.hostName, Path: base, StorageType: "local"}); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "VM web2 disk data")
		keptIntact(t, s, top, base)
		if a := lastAuditRow(t, s, keptReleaseAudit); !a.found || a.result != "error" {
			t.Errorf("refusal audit row = %+v; want an error row", a)
		}
	})
	t.Run("another VM's disk backs on a file", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		clone := filepath.Join(filepath.Dir(base), "clone-root.qcow2")
		if err := qcow2.CreateWithBackingFormat(clone, top, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "clone", HostName: s.hostName, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: "clone", DiskName: "root", HostName: s.hostName, Path: clone, StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "the disk of VM clone backs on")
		keptIntact(t, s, top, base, clone)
	})
	t.Run("a snapshot record names a file as its memory image", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		if err := corrosion.InsertSnapshot(adminCtx(), s.db, corrosion.SnapshotRecord{ID: "snap-9", VMName: "other", HostName: s.hostName,
			Name: "m1", State: "ok", Type: "memory", VMStatePath: base}); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "memory image of snapshot m1 of VM other")
		keptIntact(t, s, top, base)
	})
	t.Run("a superseded copy backs on a file", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		cp := filepath.Join(filepath.Dir(base), "other-root.qcow2.superseded-20261001T000000.000000000Z")
		if err := qcow2.CreateWithBackingFormat(cp, base, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "a superseded disk copy backs on "+base)
		keptIntact(t, s, top, base, cp)
	})
	t.Run("a .kept- copy backs on a file", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		cp := filepath.Join(filepath.Dir(base), "other-root.qcow2.kept-20261001T000000.000000000Z")
		if err := qcow2.CreateWithBackingFormat(cp, top, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, cp+", a disk a deleted VM was kept with")
		keptIntact(t, s, top, base, cp)
	})
	t.Run("a file on shared storage", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		prev := keptSharedStoreOf
		keptSharedStoreOf = func(string) (storage.SharedStore, error) { return storage.SharedStore{Shared: true}, nil }
		t.Cleanup(func() { keptSharedStoreOf = prev })
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "is on shared storage")
		keptIntact(t, s, top, base)
	})
	t.Run("another deleted VM's kept chain backs on a file", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		other := s.images.DiskPath("zz", "root")
		if err := qcow2.CreateWithBackingFormat(other, base, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		if err := health.NoteKeptDisks(s.dataDir, "zz", []string{other}); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "the delete of VM zz kept")
		keptIntact(t, s, top, base, other)
	})
	t.Run("a domain uses a file", func(t *testing.T) {
		s, fake := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		if err := fake.DefineDomain(`<domain type='kvm'><name>adopter</name><devices><disk type='file' device='disk'>` +
			`<driver name='qemu' type='qcow2'/><source file='` + top + `'/><target dev='vda'/></disk></devices></domain>`); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "the domain adopter")
		keptIntact(t, s, top, base)
	})
	t.Run("a domain of the deleted VM's name", func(t *testing.T) {
		s, fake := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		if err := fake.DefineDomain(`<domain type='kvm'><name>old</name><devices></devices></domain>`); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "a domain old is")
		keptIntact(t, s, top, base)
	})
}

// A note, the record or a chain that cannot be read refuses the release,
// removing nothing: what it names, or what it backs on, is unknown.
//
// Mutations: read an unreadable note, kept-disks.json or chain as nothing to
// list: red in its own case.
func TestKeptRelease_RefusedWhenSomethingCannotBeRead(t *testing.T) {
	t.Run("another VM's note", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		bad := filepath.Join(s.dataDir, "kept-disks", "zz.json")
		if err := os.WriteFile(bad, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, bad)
		keptIntact(t, s, top, base)
		if _, err := s.KeptDisks(viewerCtx(), &pb.KeptDisksRequest{}); status.Code(err) != codes.FailedPrecondition {
			t.Errorf("list with an unreadable note = %v; want FailedPrecondition", err)
		}
	})
	t.Run("kept-disks.json", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		if err := os.WriteFile(filepath.Join(s.dataDir, diskKeptFile), []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, filepath.Join(s.dataDir, diskKeptFile))
		for _, f := range []string{top, base} {
			if _, err := os.Stat(f); err != nil {
				t.Errorf("%s went in a refused release: %v", filepath.Base(f), err)
			}
		}
	})
	t.Run("the chain", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		// The base keeps the qcow2 magic, and its header no longer parses.
		if err := os.WriteFile(base, []byte{'Q', 'F', 'I', 0xfb, 0, 0, 0, 99}, 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "cannot be read")
		keptIntact(t, s, top, base)
	})
}

// A release confirmed for one set of files removes nothing when it would
// now remove another; a viewer may list and dry-run, never release.
func TestKeptRelease_ConfirmedFilesAndRole(t *testing.T) {
	s, _ := provableCreateServer(t)
	top, base := keptChainFixture(t, s)
	_, err := s.KeptDisks(adminCtx(), &pb.KeptDisksRequest{Release: "old", ExpectPaths: []string{top}})
	keptRefusedNaming(t, err, codes.Aborted, "not the files confirmed")
	keptIntact(t, s, top, base)
	_, err = s.KeptDisks(adminCtx(), &pb.KeptDisksRequest{Release: "old"})
	keptRefusedNaming(t, err, codes.InvalidArgument, "expect_paths is required")
	keptIntact(t, s, top, base)
	if _, err := s.KeptDisks(viewerCtx(), &pb.KeptDisksRequest{Release: "old", DryRun: true}); err != nil {
		t.Errorf("a viewer's dry run: %v", err)
	}
	_, err = s.KeptDisks(viewerCtx(), &pb.KeptDisksRequest{Release: "old"})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("a viewer's release = %v; want PermissionDenied", err)
	}
	keptIntact(t, s, top, base)
	if _, err := s.KeptDisks(adminCtx(), &pb.KeptDisksRequest{Release: "old", ExpectPaths: []string{base, top}}); err != nil {
		t.Errorf("a release confirmed for exactly its files: %v", err)
	}
}

// Rule C1 (review of a39d635bc): a layer below a kept top is the deleted VM's
// own only when its note or record names it, or when it is one of the files a
// create of exactly that name clears. Anything else stays, as what the chain
// stands on: VM web-1's disk under a kept web disk, and a file in some
// directory named like the VM.
//
// Mutation: count a <vm>- prefix, or a parent directory named <vm>, as own
// again (the a39d635bc rule): red, the file is removed.
func TestKeptRelease_LeavesWhatIsNotTheVMsOwn(t *testing.T) {
	t.Run("another VM's disk whose name extends the VM's", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		other := s.images.DiskPath("web-1", "root") // disks/web-1-root.qcow2
		if err := os.MkdirAll(filepath.Dir(other), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := qcow2.Create(other, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		top := s.images.DiskPath("web", "root")
		if err := qcow2.CreateWithBackingFormat(top, other, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		if err := health.NoteKeptDisks(s.dataDir, "web", []string{top}); err != nil {
			t.Fatal(err)
		}
		resp, err := keptRelease(s, "web")
		if err != nil {
			t.Fatalf("release web: %v", err)
		}
		if _, err := os.Stat(other); err != nil {
			t.Fatalf("%s, VM web-1's disk, went with web's kept disk: %v", other, err)
		}
		if _, err := os.Stat(top); !os.IsNotExist(err) {
			t.Errorf("web's kept disk is still there (%v)", err)
		}
		if len(resp.Chains) != 1 || !slices.Contains(resp.Chains[0].StandsOn, other) {
			t.Errorf("release answer = %+v; want %s under stands_on", resp.Chains, other)
		}
	})
	t.Run("a directory named like the VM elsewhere", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		elsewhere := filepath.Join(t.TempDir(), "gold", "base.qcow2")
		if err := os.MkdirAll(filepath.Dir(elsewhere), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := qcow2.Create(elsewhere, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		top := s.images.DiskPath("gold", "root")
		if err := os.MkdirAll(filepath.Dir(top), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := qcow2.CreateWithBackingFormat(top, elsewhere, "qcow2", 0, nil); err != nil {
			t.Fatal(err)
		}
		s.recordKeptDisks(adminCtx(), "gold", []KeptDisk{{Path: top, Disk: "root", Host: s.hostName, Reason: "no answer"}})
		resp, err := keptRelease(s, "gold")
		if err != nil {
			t.Fatalf("release gold: %v", err)
		}
		if _, err := os.Stat(elsewhere); err != nil {
			t.Fatalf("%s went with gold's kept disk: %v", elsewhere, err)
		}
		if len(resp.Chains) != 1 || !slices.Contains(resp.Chains[0].StandsOn, elsewhere) {
			t.Errorf("release answer = %+v; want %s under stands_on", resp.Chains, elsewhere)
		}
	})
}

// Rule I1: a record naming no regular file (a link, a device node: a volume
// of a storage driver) is listed, never released: unlinking it would leave
// the volume unnamed, and its record would be forgotten.
//
// Mutation: drop the regular-file check: red, the link is unlinked.
func TestKeptRelease_RefusesWhatIsNoRegularFile(t *testing.T) {
	s, _ := provableCreateServer(t)
	target := filepath.Join(t.TempDir(), "lv-data")
	if err := os.WriteFile(target, []byte("A VOLUME"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "vg-lv")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	s.recordKeptDisks(adminCtx(), "lvm", []KeptDisk{{Path: link, Disk: "root", Host: s.hostName, Reason: "no answer"}})
	_, err := keptRelease(s, "lvm")
	keptRefusedNaming(t, err, codes.FailedPrecondition, "is no regular file")
	if _, err := os.Lstat(link); err != nil {
		t.Errorf("the link went in a refused release: %v", err)
	}
	if recs, _ := s.diskKeptRecords(); len(recs) != 1 {
		t.Errorf("records after a refused release = %+v; want the link's entry kept", recs)
	}
}

// Rule I2: a release removes only the file its plan checked. A file put at
// the path between the plan and the removal (a create elsewhere setting the
// kept file aside and writing its own) is left, the release stops, and what
// is left stays named.
//
// Mutation: drop the device/inode compare: red, the new file is removed.
func TestKeptRelease_LeavesAFileThatIsNoLongerTheOneChecked(t *testing.T) {
	s, _ := provableCreateServer(t)
	top, base := keptChainFixture(t, s)
	prev := keptReleaseBeforeRemove
	keptReleaseBeforeRemove = func(p string) {
		if p == top {
			_ = os.Rename(top, top+".aside")
			_ = os.WriteFile(top, []byte("A NEW VM'S DISK"), 0o600)
		}
	}
	t.Cleanup(func() { keptReleaseBeforeRemove = prev })
	_, err := keptRelease(s, "old")
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "no longer the file the release checked") {
		t.Fatalf("release with the top replaced = %v; want it stopped, naming the replaced file", err)
	}
	if b, err := os.ReadFile(top); err != nil || string(b) != "A NEW VM'S DISK" {
		t.Errorf("the file put at %s was removed or changed (%q, %v)", top, b, err)
	}
	keptIntact(t, s, top, base)
}

// Rule I4: the deleted VM's snapshot records on this host, taken over the
// kept files, go with a release of the VM once the operator confirms them,
// and only when no VM of the name exists and each memory image is gone or
// released too.
//
// Mutations: drop the no-VM check, or the memory image check: red in its own
// case; drop the expect_snapshots compare: red.
func TestKeptRelease_DropsTheDeletedVMsSnapshotRecords(t *testing.T) {
	snap := func(t *testing.T, s *Server, vmstate string) {
		t.Helper()
		if err := corrosion.InsertSnapshot(adminCtx(), s.db, corrosion.SnapshotRecord{ID: "snap-1", VMName: "old", HostName: s.hostName,
			Name: "s1", State: "ok", VMStatePath: vmstate}); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("dropped once confirmed", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		snap(t, s, filepath.Join(s.dataDir, "vmstate", "old-s1.save")) // gone
		plan, err := s.KeptDisks(adminCtx(), &pb.KeptDisksRequest{Release: "old", DryRun: true})
		if err != nil || len(plan.Chains) != 1 || plan.Chains[0].Held != "" || !slices.Equal(plan.Chains[0].Snapshots, []string{"s1"}) {
			t.Fatalf("dry run = %+v, %v; want the chain releasable, dropping s1", plan, err)
		}
		_, err = s.KeptDisks(adminCtx(), &pb.KeptDisksRequest{Release: "old", ExpectPaths: []string{top, base}})
		keptRefusedNaming(t, err, codes.Aborted, "not the ones confirmed")
		keptIntact(t, s, top, base)
		if _, err := keptRelease(s, "old"); err != nil {
			t.Fatalf("release old with s1 confirmed: %v", err)
		}
		if sn, _ := corrosion.GetSnapshot(adminCtx(), s.db, "old", "s1"); sn != nil {
			t.Errorf("snapshot record s1 survived the release: %+v", sn)
		}
		if _, err := os.Stat(top); !os.IsNotExist(err) {
			t.Errorf("%s is still there (%v)", top, err)
		}
		if a := lastAuditRow(t, s, keptReleaseAudit); a.result != "ok" || !strings.Contains(a.detail, "dropped the snapshot records s1 of the deleted VM old") {
			t.Errorf("audit row = %+v; want it to name the dropped record", a)
		}
	})
	t.Run("refused while a VM of the name exists", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		snap(t, s, "")
		if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "old", HostName: "node-x", State: "stopped"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "a VM old exists")
		keptIntact(t, s, top, base)
		if sn, _ := corrosion.GetSnapshot(adminCtx(), s.db, "old", "s1"); sn == nil {
			t.Error("snapshot record s1 went in a refused release")
		}
	})
	t.Run("refused while a memory image is outside the release", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		top, base := keptChainFixture(t, s)
		img := filepath.Join(t.TempDir(), "old-s1.save")
		if err := os.WriteFile(img, []byte("RAM"), 0o600); err != nil {
			t.Fatal(err)
		}
		snap(t, s, img)
		_, err := keptRelease(s, "old")
		keptRefusedNaming(t, err, codes.FailedPrecondition, "the memory image "+img)
		keptIntact(t, s, top, base, img)
	})
}
