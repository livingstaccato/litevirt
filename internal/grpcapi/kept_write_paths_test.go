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
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// writePathsDirPool records a dir pool of this host at target, in its row and
// in memory, as `lv pool create` leaves it.
func writePathsDirPool(t *testing.T, s *Server, name, target string) {
	t.Helper()
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: name, Driver: "dir", Target: target})
	s.addStoragePoolRef(name, StoragePoolRef{Driver: "dir", Target: target})
}

// writePathsNFSPool records an nfs pool of this host whose export is mounted
// (the mount table says so) at a new directory, which it returns.
func writePathsNFSPool(t *testing.T, s *Server, name string) string {
	t.Helper()
	mnt := t.TempDir()
	if err := os.Chmod(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	overrideMounts(t, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", nfsMountLine(mnt, "nas:/vm"))
	t.Cleanup(storage.OverrideNFSMountCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		return nil, nil
	}))
	ref := StoragePoolRef{Driver: "nfs", Source: "nas:/vm", Target: mnt}
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: name, Driver: ref.Driver, Source: ref.Source, Target: ref.Target})
	s.addStoragePoolRef(name, ref)
	return mnt
}

// symlinkToDisks makes a directory that is a symlink to this host's disk
// directory, and returns it.
func symlinkToDisks(t *testing.T, s *Server) string {
	t.Helper()
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(disks, alias); err != nil {
		t.Fatal(err)
	}
	return alias
}

func wantMissingBaseRefusal(t *testing.T, what string, err error, top, base string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), base) {
		t.Fatalf("%s = %v; want FailedPrecondition naming the overlay %s and its missing base %s", what, err, top, base)
	}
	if exists(base) {
		t.Fatalf("a refused %s wrote the kept overlay's missing base %s", what, base)
	}
}

func poolCreateRequest(name, pool string) *pb.CreateVMRequest {
	req := disklessCreateRequest(name)
	req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M", Storage: pool}}
	return req
}

// A create writes a disk on a pool where that pool's driver puts it, not in
// the disk directory: a kept overlay naming that file as its missing base
// refuses it, as one naming a disk-directory file does.
//
// Red on 3cd2efd0a: "dir pool" and "nfs pool" (the create goes ahead and
// writes the base). Mutation: build the create's write set from the disk
// directory alone (createKeptWrites skips pool disks): both red.
func TestCreateVM_AKeptOverlayMissingItsBaseOnAPoolRefusesIt(t *testing.T) {
	t.Run("dir pool", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "ssd")
		writePathsDirPool(t, s, "ssd", dir)
		base := filepath.Join(dir, "web-root.qcow2")
		top := registryKeep(t, s, "web", base)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd"))
		wantMissingBaseRefusal(t, "create on a dir pool", err, top, base)
	})
	t.Run("nfs pool", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		mnt := writePathsNFSPool(t, s, "share")
		base := filepath.Join(mnt, "web-root.qcow2")
		top := registryKeep(t, s, "web", base)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "share"))
		wantMissingBaseRefusal(t, "create on an nfs pool", err, top, base)
	})
	t.Run("a pool whose paths no kept overlay names goes ahead", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		dir := filepath.Join(t.TempDir(), "ssd")
		writePathsDirPool(t, s, "ssd", dir)
		registryKeep(t, s, "old", filepath.Join(dir, "old-root.qcow2"))
		registryKeep(t, s, "web", filepath.Join(s.dataDir, "disks", "web-root.qcow2"))
		if _, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "ssd")); err != nil {
			t.Fatalf("create on a pool no kept overlay's missing base is in: %v", err)
		}
		if !exists(filepath.Join(dir, "web-root.qcow2")) {
			t.Fatal("the create did not write its disk in the pool: this proves nothing")
		}
	})
}

// The same file reached through another spelling of its directory is the
// same file: a pool whose target is a symlink to the disk directory writes
// the disk-directory file a kept overlay names, and the other way round.
//
// Mutation: drop the symlink resolution (keptResolveDir returns dir as
// written): every subtest red.
func TestKeptCreateChecks_AnotherSpellingOfTheDirectoryIsTheSameFile(t *testing.T) {
	t.Run("create on a pool symlinked to disks/, overlay names disks/", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		alias := symlinkToDisks(t, s)
		writePathsDirPool(t, s, "alias", alias)
		base := filepath.Join(s.dataDir, "disks", "web-root.qcow2")
		top := registryKeep(t, s, "web", base)
		_, err := s.CreateVM(adminCtx(), poolCreateRequest("web", "alias"))
		wantMissingBaseRefusal(t, "create on a pool symlinked to the disk directory", err, top, base)
	})
	t.Run("create in disks/, overlay names it through a symlink", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		alias := symlinkToDisks(t, s)
		base := filepath.Join(alias, "web-root.qcow2")
		top := registryKeep(t, s, "web", base)
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
		_, err := s.CreateVM(adminCtx(), req)
		wantMissingBaseRefusal(t, "create in the disk directory", err, top, base)
	})
	t.Run("attach", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		seedDiskVM(t, s, "vm1", "stopped")
		alias := symlinkToDisks(t, s)
		real, err := lv.SafeDiskPath(s.dataDir, "vm1", "data1")
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(alias, filepath.Base(real))
		top := registryKeep(t, s, "old", base)
		_, err = s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{
			VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "1G", Bus: "virtio"},
		})
		wantMissingBaseRefusal(t, "attach", err, top, base)
	})
	t.Run("restore to a named target", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		alias := symlinkToDisks(t, s)
		base := filepath.Join(alias, "web-root.qcow2")
		top := registryKeep(t, s, "old", base)
		err := s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
			RepoPath: "no-such-repo", VmName: "web", DiskName: "root", Timestamp: "2026-10-06T13:00:00Z", TargetPath: "web-root.qcow2",
		}, &progressStream[pb.RestoreFromBackupProgress]{ctx: adminCtx()})
		wantMissingBaseRefusal(t, "restore", err, top, base)
	})
	t.Run("import", func(t *testing.T) {
		s, dst := orphanFixture(t, "web")
		alias := filepath.Join(t.TempDir(), "alias")
		if err := os.Symlink(filepath.Dir(dst), alias); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(alias, filepath.Base(dst))
		top := registryKeep(t, s, "old", base)
		err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "web", false)}})
		if err == nil || !strings.Contains(err.Error(), top) {
			t.Fatalf("import = %v; want a refusal naming the overlay %s", err, top)
		}
		if exists(dst) {
			t.Fatal("a refused import wrote the kept overlay's missing base")
		}
	})
}

// A clone into a shared pool elsewhere is not held while kept-disks.json
// cannot be read (TestCloneVM_AnUnknownKeptChainHoldsOnlyClonesThatWriteHere),
// but a kept overlay there that names its disk as its missing base still
// refuses it.
//
// Red on 3cd2efd0a (the clone into the nfs pool was not checked at all).
// Mutation: skip the check for a clone into a shared pool elsewhere: red.
func TestCloneVM_AKeptOverlayMissingItsBaseInAnNFSPoolRefusesIt(t *testing.T) {
	s := cloneTargetServer(t)
	mnt := writePathsNFSPool(t, s, "share")
	base := filepath.Join(mnt, "c1-root.qcow2")
	top := registryKeep(t, s, "old", base)
	_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1", TargetPool: "share"})
	wantMissingBaseRefusal(t, "clone into an nfs pool", err, top, base)
}

// moveVolumeFixture is a stopped VM vm1 of this host whose disk root is a
// qcow2 in a directory of its own, in pool "hot", and a dir pool "ssd" to
// move it into. It returns the server, the disk file and the pool directory.
func moveVolumeFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	s := testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	srcFile := filepath.Join(t.TempDir(), "vm1-root.qcow2")
	if err := qcow2.Create(srcFile, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(srcFile)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "ssd")
	writePathsDirPool(t, s, "ssd", dir)
	if err := corrosion.InsertVM(adminCtx(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: s.hostName, Path: srcFile,
			SizeBytes: fi.Size(), StorageType: "local", StorageVolume: "hot"}},
	); err != nil {
		t.Fatal(err)
	}
	return s, srcFile, dir
}

// A volume move writes <pool>/<vm>-<disk>.qcow2, a new file as a create's
// disk is: a kept overlay naming it as its missing base refuses the move,
// before anything is copied, and leaves the source as it was.
//
// Red on 083d7afca: the move goes ahead and writes the base, and goes ahead
// while kept-disks.json cannot be read. Mutations: drop the keptPathRefusal
// from moveOneVolume: both red; take every pool as shared storage elsewhere
// (local false): the unreadable-registry case red.
func TestMoveVolume_AKeptOverlayMissingItsBaseRefusesIt(t *testing.T) {
	t.Run("the destination is the missing base", func(t *testing.T) {
		s, srcFile, dir := moveVolumeFixture(t)
		was, err := os.ReadFile(srcFile)
		if err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(dir, "vm1-root.qcow2")
		top := registryKeep(t, s, "vm1", base)
		err = s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "ssd", DeleteSource: true},
			&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
		wantMissingBaseRefusal(t, "volume move", err, top, base)
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Fatalf("a refused move wrote into the pool: %v", ents)
		}
		sameBytes(t, "the source", srcFile, was)
		disks, err := corrosion.GetVMDisks(adminCtx(), s.db, "vm1")
		if err != nil || len(disks) != 1 || disks[0].Path != srcFile || disks[0].StorageVolume != "hot" {
			t.Fatalf("a refused move changed the disk row: %+v (err=%v)", disks, err)
		}
	})
	t.Run("an unreadable kept-disks.json holds a move into a local pool", func(t *testing.T) {
		s, srcFile, dir := moveVolumeFixture(t)
		// With kept-disks.json unreadable the disk files on this host decide
		// (keptCollisionOnDisk): an overlay there backs on the move's copy.
		overlayOn(t, filepath.Join(s.dataDir, "disks", "db-snap1.qcow2"), filepath.Join(dir, "vm1-root.qcow2"))
		named := keptUnknown(t, s, "registry")
		err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "ssd"},
			&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) {
			t.Fatalf("move while %s cannot be read = %v; want FailedPrecondition naming it", named, err)
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 || !exists(srcFile) {
			t.Fatalf("a refused move wrote into the pool (%v) or lost its source", ents)
		}
	})
	t.Run("an unreadable kept-disks.json with nothing on this host naming the copy goes ahead", func(t *testing.T) {
		s, _, dir := moveVolumeFixture(t)
		keptUnknown(t, s, "registry")
		if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "ssd"},
			&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
			t.Fatalf("move while kept-disks.json cannot be read, with no file on this host naming the copy: %v", err)
		}
		if !exists(filepath.Join(dir, "vm1-root.qcow2")) {
			t.Fatal("the move did not write its copy in the pool: this proves nothing")
		}
	})
	t.Run("a destination no kept overlay names goes ahead", func(t *testing.T) {
		s, _, dir := moveVolumeFixture(t)
		registryKeep(t, s, "old", filepath.Join(dir, "old-root.qcow2"))
		if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "ssd"},
			&streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}); err != nil {
			t.Fatalf("move into a pool no kept overlay's missing base is at: %v", err)
		}
		if !exists(filepath.Join(dir, "vm1-root.qcow2")) {
			t.Fatal("the move did not write its copy in the pool: this proves nothing")
		}
	})
}
