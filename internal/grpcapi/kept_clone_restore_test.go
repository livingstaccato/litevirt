package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// A clone writes a new disk file at <disks>/<target>-<disk>.qcow2, as a
// create does: one at the path a kept overlay names as its missing base
// would become that base. It gets the create's check.
//
// Mutation: drop the keptPathRefusal call from cloneVMOnSource: every
// subtest red (the clone goes ahead and writes the base).
func TestCloneVM_GetsTheKeptCreateChecks(t *testing.T) {
	t.Run("a kept overlay names the clone's disk as its missing base", func(t *testing.T) {
		s := cloneTargetServer(t)
		base := s.images.DiskPath("c1", "root")
		top := registryKeep(t, s, "old", base)
		_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1"})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("clone = %v; want FailedPrecondition naming the overlay %s", err, top)
		}
		if exists(base) {
			t.Fatal("a refused clone wrote the kept overlay's missing base")
		}
	})
	t.Run("into a local pool, at its missing base there", func(t *testing.T) {
		s := cloneTargetServer(t)
		dir := addDirPool(t, s, "ssd")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		base := filepath.Join(dir, "c1-root.qcow2")
		registryKeep(t, s, "old", base)
		_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1", TargetPool: "ssd"})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("clone into ssd = %v; want FailedPrecondition", err)
		}
		if exists(base) {
			t.Fatal("a refused clone wrote the kept overlay's missing base in the pool")
		}
	})
	for _, how := range []string{"registry", "chain"} {
		t.Run("kept state unreadable: "+how, func(t *testing.T) {
			s := cloneTargetServer(t)
			named := keptUnknown(t, s, how)
			_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1"})
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) {
				t.Fatalf("clone = %v; want FailedPrecondition naming %s", err, named)
			}
			if exists(s.images.DiskPath("c1", "root")) {
				t.Fatal("a refused clone wrote its disk")
			}
		})
	}
	t.Run("a clone no kept overlay names goes ahead", func(t *testing.T) {
		s := cloneTargetServer(t)
		registryKeep(t, s, "old", filepath.Join(t.TempDir(), "elsewhere.raw"))
		if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1"}); err != nil {
			t.Fatalf("clone: %v", err)
		}
	})
}

// A backup restore to a target path you name writes a file that does not
// exist yet: it can be a kept overlay's missing base. Checked before the
// repository is opened, so these requests name none that exists.
//
// Mutations: drop the keptPathRefusal call from RestoreFromBackup, or from
// RestoreLive: that subtest red (the request goes on to the repository).
func TestRestore_ToANamedTargetGetsTheKeptCreateChecks(t *testing.T) {
	restoreFrom := func(s *Server, target string) error {
		return s.RestoreFromBackup(&pb.RestoreFromBackupRequest{
			RepoPath: "no-such-repo", VmName: "web", DiskName: "root", Timestamp: "2026-10-06T13:00:00Z", TargetPath: target,
		}, &progressStream[pb.RestoreFromBackupProgress]{ctx: adminCtx()})
	}
	restoreLive := func(s *Server, target string) error {
		return s.RestoreLive(&pb.RestoreLiveRequest{
			RepoPath: "no-such-repo", VmName: "web", DiskName: "root", Timestamp: "2026-10-06T13:00:00Z", TargetPath: target,
		}, &progressStream[pb.RestoreLiveProgress]{ctx: adminCtx()})
	}
	for name, restore := range map[string]func(*Server, string) error{"restore-from": restoreFrom, "restore-live": restoreLive} {
		t.Run(name+"/at a kept overlay's missing base", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			base := s.images.DiskPath("web", "root")
			top := registryKeep(t, s, "old", base)
			err := restore(s, filepath.Base(base))
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
				t.Fatalf("restore = %v; want FailedPrecondition naming the overlay %s", err, top)
			}
			if exists(base) {
				t.Fatal("a refused restore wrote the base")
			}
		})
		t.Run(name+"/kept state unreadable", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			named := keptUnknown(t, s, "registry")
			err := restore(s, "web-root.qcow2")
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) {
				t.Fatalf("restore = %v; want FailedPrecondition naming %s", err, named)
			}
		})
		t.Run(name+"/a target no kept overlay names passes the check", func(t *testing.T) {
			s, _ := provableCreateServer(t)
			registryKeep(t, s, "old", filepath.Join(t.TempDir(), "elsewhere.raw"))
			if err := restore(s, "web-root.qcow2"); err != nil && strings.Contains(err.Error(), "kept") {
				t.Fatalf("restore refused by the kept check: %v", err)
			}
		})
	}
}

// A disk attach writes a new file at <disks>/<vm>-<disk>.qcow2, as a create
// does, and gets the same check.
//
// Mutation: drop the keptPathRefusal call from AttachDevice: both subtests
// red.
func TestAttachDevice_GetsTheKeptCreateChecks(t *testing.T) {
	attach := func(s *Server) error {
		_, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{
			VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "1G", Bus: "virtio"},
		})
		return err
	}
	t.Run("a kept overlay names the new disk as its missing base", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		seedDiskVM(t, s, "vm1", "stopped")
		base, err := lv.SafeDiskPath(s.dataDir, "vm1", "data1")
		if err != nil {
			t.Fatal(err)
		}
		top := registryKeep(t, s, "old", base)
		if err := attach(s); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("attach = %v; want FailedPrecondition naming the overlay %s", err, top)
		}
		if exists(base) {
			t.Fatal("a refused attach wrote the kept overlay's missing base")
		}
	})
	t.Run("kept state unreadable", func(t *testing.T) {
		s := hotplugDiskServer(t)
		enableHardwareV2(t, s)
		seedDiskVM(t, s, "vm1", "stopped")
		named := keptUnknown(t, s, "registry")
		if err := attach(s); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), named) {
			t.Fatalf("attach = %v; want FailedPrecondition naming %s", err, named)
		}
	})
}

// While what kept overlays back on cannot be read, a clone that writes no
// disk file on this host's own storage goes ahead, as such a create does: a
// ceph-only clone (copied inside its pool), and a clone into an nfs pool
// mounted outside the disk directory.
//
// Mutation: drop the clone exemption (check every clone, `if true`): the
// nfs subtests red. A ceph-only clone has no file to check either way.
func TestCloneVM_AnUnknownKeptChainHoldsOnlyClonesThatWriteHere(t *testing.T) {
	for _, how := range []string{"registry", "chain"} {
		t.Run(how+"/into an nfs pool elsewhere", func(t *testing.T) {
			s := cloneTargetServer(t)
			named := keptUnknown(t, s, how)
			mnt := t.TempDir()
			if err := os.Chmod(mnt, 0o755); err != nil {
				t.Fatal(err)
			}
			overrideMounts(t, "22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw", nfsMountLine(mnt, "nas:/vm"))
			// The export is "mounted" already (the mount table above); no
			// mount command runs.
			t.Cleanup(storage.OverrideNFSMountCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
				return nil, nil
			}))
			ref := StoragePoolRef{Driver: "nfs", Source: "nas:/vm", Target: mnt}
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "share", Driver: ref.Driver, Source: ref.Source, Target: ref.Target})
			s.addStoragePoolRef("share", ref)
			if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1", TargetPool: "share"}); err != nil {
				t.Fatalf("clone into an nfs pool elsewhere while %s cannot be read: %v", named, err)
			}
			if !exists(filepath.Join(mnt, "c1-root.qcow2")) {
				t.Fatal("the clone's disk is not in the nfs pool")
			}
		})
		t.Run(how+"/ceph only", func(t *testing.T) {
			f := newCephPoolFixture(t)
			named := keptUnknown(t, f.s, how)
			src := "rbd:lv/tpl-root:id=litevirt:keyring=" + f.keyring + ":lvpool=ceph"
			f.world.images["lv/tpl-root"] = map[string]bool{}
			spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256})
			if err := corrosion.InsertVM(adminCtx(), f.s.db, corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", Spec: string(spec)},
				nil, []corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: src, SizeBytes: 1 << 30, StorageType: "ceph", StorageVolume: "ceph"}}); err != nil {
				t.Fatal(err)
			}
			if _, err := f.s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "copy"}); err != nil {
				t.Fatalf("a ceph-only clone while %s cannot be read: %v", named, err)
			}
		})
	}
}
