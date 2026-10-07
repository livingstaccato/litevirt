package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// A file at the disk's name that nothing in the cluster records or is still
// creating, and that has been quiet longer than importOrphanMinAge — a
// crashed earlier import's output — is moved aside under a new name, kept,
// and the re-import goes ahead.
func TestImportVM_AnOrphanAtTheDisksNameIsMovedAsideAndKept(t *testing.T) {
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(poolDir, "imp-again-root.qcow2")
	plantOld(t, dst, "leftover")
	if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-again", false)}}); err != nil {
		t.Fatalf("a re-import over an orphan: %v", err)
	}
	aside, _ := filepath.Glob(dst + ".orphan-*")
	if len(aside) != 1 {
		t.Fatalf("orphan kept as %v, want one file beside the disk", aside)
	}
	if b, _ := os.ReadFile(aside[0]); string(b) != "leftover" {
		t.Fatalf("the orphan kept aside holds %q", b)
	}
	if b, _ := os.ReadFile(dst); string(b) == "leftover" {
		t.Fatal("the disk's name still holds the orphan")
	}
}

// A file a disk row names is not an orphan even when the row is a tombstone:
// a deleted VM's kept disk belongs to its project. It is refused and left as
// it is.
func TestImportVM_AKeptDiskOfADeletedVMIsNotAnOrphan(t *testing.T) {
	for _, col := range []string{"path", "backing_disk"} {
		t.Run(col, func(t *testing.T) {
			s := concurrentImportServer(t, 10*oneDiskNeed())
			stubQemuImg(t)
			poolDir, err := s.importPoolDir(adminCtx(), "")
			if err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(poolDir, "imp-kept-root.qcow2")
			plantOld(t, dst, "their kept disk")
			now := time.Now().UTC().Format(time.RFC3339Nano)
			path, backing := "/elsewhere/x.qcow2", ""
			if col == "path" {
				path = dst
			} else {
				backing = dst
			}
			if err := s.db.Execute(context.Background(),
				`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, backing_disk, storage_type, updated_at, deleted_at)
				 VALUES ('gone', 'root', 'other-host', ?, ?, 'local', ?, ?)`, path, nullIfEmptyTest(backing), now, now); err != nil {
				t.Fatal(err)
			}
			err = s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-kept", false)}})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "gone") {
				t.Fatalf("an import over a deleted VM's kept disk: %v, want a refusal naming the VM", err)
			}
			if b, _ := os.ReadFile(dst); string(b) != "their kept disk" {
				t.Fatalf("the kept disk now holds %q", b)
			}
			if aside, _ := filepath.Glob(dst + ".orphan-*"); len(aside) != 0 {
				t.Fatalf("the kept disk was moved aside: %v", aside)
			}
			if rec, _ := corrosion.GetVM(context.Background(), s.db, "imp-kept"); rec != nil {
				t.Fatal("a refused import persisted a row")
			}
		})
	}
}

func nullIfEmptyTest(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// An image a host stores at that name is not an orphan either.
func TestImportVM_AnImageAtTheDisksNameIsNotAnOrphan(t *testing.T) {
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(poolDir, "imp-img-root.qcow2")
	plantOld(t, dst, "an image")
	if err := s.db.Execute(context.Background(),
		`INSERT INTO image_hosts (image_name, host_name, path, status, updated_at) VALUES ('base', 'test-host', ?, 'ready', ?)`,
		dst, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	err = s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-img", false)}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "image base") {
		t.Fatalf("an import over a stored image: %v, want a refusal naming the image", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "an image" {
		t.Fatalf("the image now holds %q", b)
	}
}

// Moving an orphan aside never replaces a file at the new name either.
func TestMoveOrphanAside_NeverReplacesAFile(t *testing.T) {
	at := time.Unix(1700000000, 0)
	orphanNow = func() time.Time { return at }
	t.Cleanup(func() { orphanNow = time.Now })
	p := filepath.Join(t.TempDir(), "d.qcow2")
	if err := os.WriteFile(p, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	there := p + ".orphan-1700000000"
	if err := os.WriteFile(there, []byte("already there"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := moveOrphanAside(p); err == nil {
		t.Fatal("moved an orphan over a file at its new name")
	}
	if b, _ := os.ReadFile(there); string(b) != "already there" {
		t.Fatalf("the file at the new name now holds %q", b)
	}
	if b, _ := os.ReadFile(p); string(b) != "orphan" {
		t.Fatalf("the orphan now holds %q", b)
	}
}

// plantOld writes body to p and dates it two importOrphanMinAge-s back.
func plantOld(t *testing.T, p, body string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
}

// refusedAndUntouched asserts the import was refused and left dst as it was.
func refusedAndUntouched(t *testing.T, s *Server, name, dst, body string) {
	t.Helper()
	err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, name, false)}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an import over a file another flow may still be creating: %v, want FailedPrecondition", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != body {
		t.Fatalf("the file now holds %q", b)
	}
	if aside, _ := filepath.Glob(dst + ".orphan-*"); len(aside) != 0 {
		t.Fatalf("the file was moved aside: %v", aside)
	}
}

func orphanFixture(t *testing.T, name string) (*Server, string) {
	t.Helper()
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	poolDir, err := s.importPoolDir(adminCtx(), "")
	if err != nil {
		t.Fatal(err)
	}
	return s, filepath.Join(poolDir, name+"-root.qcow2")
}

// CreateVM (and clone, restore) creates a VM's disk files while it holds the
// admission reservation it took through admitWithReservation, before it
// writes the VM's row: a file at that name is being created, not left over.
func TestImportVM_ADiskAVMCreateIsStillWritingIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	plantOld(t, dst, "being created")
	// The call CreateVM makes (vm.go), in the default configuration.
	lease, err := s.admitWithReservation(adminCtx(), "CreateVM", s.hostName, "default", "vm:web",
		1, 512, corrosion.QuotaAmount{VCPU: 1, MemMiB: 512, DiskGiB: 1}, intentVMResident)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.release(context.Background())
	refusedAndUntouched(t, s, "web", dst, "being created")
}

// A multi-disk flow leaves its first disks quiet while it writes the next:
// a fresh sibling of the file, or another host's conversion scratch file,
// means the flow is still running.
func TestImportVM_AFileWhoseSiblingIsStillBeingWrittenIsNotAnOrphan(t *testing.T) {
	for _, sibling := range []string{"web-data.qcow2", ".web-disk1.qcow2.convert-abc"} {
		t.Run(sibling, func(t *testing.T) {
			s, dst := orphanFixture(t, "web")
			plantOld(t, dst, "first disk")
			if err := os.WriteFile(filepath.Join(filepath.Dir(dst), sibling), []byte("writing"), 0o600); err != nil {
				t.Fatal(err)
			}
			refusedAndUntouched(t, s, "web", dst, "first disk")
		})
	}
}

// A live VM's replica at the file's name is claimed by its replica record
// (the pool's record of it), not by the VM's name prefixing the file's.
func TestImportVM_AFileNamedLikeALiveVMsDisksIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "web-x")
	plantOld(t, dst, "web's replica")
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "web", HostName: "other-host", Spec: "{}", State: "stopped", Project: "default",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.recordPoolReplica(context.Background(), "default", replicaKey{VM: "web", Disk: "x-root", Project: "default"}, dst); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "web-x", dst, "web's replica")
}

// A pool on a filesystem with neither hard links nor a rename that cannot
// replace (some FUSE filesystems) still takes imports, as it did with a plain
// rename: the disk is copied into a file created exclusively.
func TestImportVM_APoolWithoutLinkOrNoReplaceRenameTakesImports(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	s, dst := orphanFixture(t, "imp-fuse")
	if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-fuse", false)}}); err != nil {
		t.Fatalf("an import into a pool without link or RENAME_NOREPLACE: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("the disk was not placed: %v", err)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(dst), ".imp-fuse-*.convert-*")); len(left) != 0 {
		t.Fatalf("the scratch file was left: %v", left)
	}
}

// There too an orphan is moved aside without replacing anything.
func TestMoveOrphanAside_WithoutLinkOrNoReplaceRename(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	p := filepath.Join(t.TempDir(), "d.qcow2")
	if err := os.WriteFile(p, []byte("orphan"), 0o600); err != nil {
		t.Fatal(err)
	}
	aside, err := moveOrphanAside(p)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(aside); string(b) != "orphan" {
		t.Fatalf("moved aside as %q", b)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("the orphan's name is still taken: %v", err)
	}
	// And never over a file at the name it would take elsewhere: there it
	// takes a name no other flow can choose.
	if err := os.WriteFile(p, []byte("orphan 2"), 0o600); err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1700000000, 0)
	orphanNow = func() time.Time { return at }
	t.Cleanup(func() { orphanNow = time.Now })
	there := p + ".orphan-1700000000"
	if err := os.WriteFile(there, []byte("already there"), 0o600); err != nil {
		t.Fatal(err)
	}
	aside2, err := moveOrphanAside(p)
	if err != nil {
		t.Fatal(err)
	}
	if aside2 == there || aside2 == aside {
		t.Fatalf("moved aside as %s", aside2)
	}
	if b, _ := os.ReadFile(aside2); string(b) != "orphan 2" {
		t.Fatalf("moved aside as %q", b)
	}
	if b, _ := os.ReadFile(there); string(b) != "already there" {
		t.Fatalf("the file at the new name now holds %q", b)
	}
}

// A file that appears at the disk's name during the conversion is not
// replaced on such a filesystem either.
func TestImportVM_WithoutLinkADiskThatAppearsIsNotReplaced(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	s := concurrentImportServer(t, 10*oneDiskNeed())
	appearingQemuImg(t)
	err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-race", false)}})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a disk placed over a file that appeared meanwhile: %v, want FailedPrecondition", err)
	}
	poolDir, _ := s.importPoolDir(adminCtx(), "")
	if b, _ := os.ReadFile(filepath.Join(poolDir, "imp-race-root.qcow2")); string(b) != "theirs" {
		t.Fatalf("the file that appeared now holds %q", b)
	}
}

// noLinkNoRenameNoReplace makes link() and RENAME_NOREPLACE unsupported, as
// on a FUSE filesystem that has neither.
func noLinkNoRenameNoReplace(t *testing.T) {
	t.Helper()
	oldLink, oldRename := coldLink, coldRenameNoReplace
	coldLink = func(o, n string) error { return &os.LinkError{Op: "link", Old: o, New: n, Err: syscall.EPERM} }
	coldRenameNoReplace = func(o, n string) error { return &os.LinkError{Op: "renameat2", Old: o, New: n, Err: syscall.EINVAL} }
	t.Cleanup(func() { coldLink, coldRenameNoReplace = oldLink, oldRename })
}

// A file modified within importOrphanMinAge may be another host's import into
// a shared pool, or any flow that has not recorded it yet.
func TestImportVM_ARecentlyWrittenFileIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "imp-fresh")
	if err := os.WriteFile(dst, []byte("fresh"), 0o600); err != nil {
		t.Fatal(err)
	}
	minuteAgo := time.Now().Add(-time.Minute)
	if err := os.Chtimes(dst, minuteAgo, minuteAgo); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "imp-fresh", dst, "fresh")
}

// A hotplug attach journals the path it is about to publish before the disk
// row exists.
func TestImportVM_AFileAnOperationJournaledIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "imp-hot")
	plantOld(t, dst, "attaching")
	j, err := opjournal.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s.SetOpJournal(j)
	if err := j.Write(opjournal.Entry{OperationID: "op-1", ResourceID: "vm:other", Kind: "attach_disk", Stage: "claimed",
		Artifacts: map[string]string{"file_created_by_operation": dst}}); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "imp-hot", dst, "attaching")
}

// Disk names may hold '-': VM web's disk x-root and import web-x's disk root
// share web-x-root.qcow2. A same-host import of web in flight claims it.
func TestImportVM_AFileAnotherImportInFlightMayWriteIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "web-x")
	plantOld(t, dst, "web's")
	release, err := s.claimImportName("web")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	refusedAndUntouched(t, s, "web-x", dst, "web's")
}

// After an external snapshot a disk row names the overlay, and only the
// overlay's header names the base at the disk's plain name.
func TestImportVM_AKeptSnapshotsBaseIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "imp-snap")
	plantOld(t, dst, "base")
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if err := s.db.Execute(context.Background(),
		`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, storage_type, updated_at, deleted_at)
		 VALUES ('imp-snap', 'root', 'test-host', ?, 'local', ?, ?)`, strings.TrimSuffix(dst, ".qcow2")+".snap1", now, now); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "imp-snap", dst, "base")
}

// A row that names the file through a symlinked directory still names it.
func TestImportVM_AFileARowNamesThroughASymlinkIsNotAnOrphan(t *testing.T) {
	s, dst := orphanFixture(t, "imp-link")
	plantOld(t, dst, "linked")
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(dst), alias); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(context.Background(),
		`INSERT INTO vm_disks (vm_name, disk_name, host_name, path, storage_type, updated_at)
		 VALUES ('other', 'root', 'test-host', ?, 'local', ?)`, filepath.Join(alias, filepath.Base(dst)), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "imp-link", dst, "linked")
}

// --inspect writes nothing: it does not take, or wait on, the name's claim.
func TestImportVM_InspectDoesNotNeedTheNamesClaim(t *testing.T) {
	s, _ := orphanFixture(t, "imp-i")
	release, err := s.claimImportName("imp-i")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-i", true)}}); err != nil {
		t.Fatalf("an inspect beside an import of the same name: %v", err)
	}
}
