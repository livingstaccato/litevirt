package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// BuildImage and the full clone flatten a VM's disk with ConvertConfined.
// Its top layer is opened as the cold migration's flatten opens it
// (heldConvertSource + NoFollowSource): beneath the disk's directory held
// open by descriptor, with no link followed at the file itself.
// (Re-review 5b, O-1.)
//
// Mutations:
//   - drop NoFollowSource at a call site: its "link at the disk" test is red
//     (the conversion follows the link and succeeds);
//   - convert from the disk's name in place of heldConvertSource's: its
//     "directory swapped" test is red (the read follows the swapped directory
//     to a file that is not an image).

// convertSourceServer is cloneTargetServer with the template's disk in a
// directory of its own under the disk directory (<disks>/tpl/root.qcow2), so
// that directory can be swapped while the disk root stays put. It returns the
// disk's path.
func convertSourceServer(t *testing.T) (*Server, string) {
	t.Helper()
	s := cloneTargetServer(t)
	old := s.images.DiskPath("tpl", "root")
	p := filepath.Join(filepath.Dir(old), "tpl", "root.qcow2")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(old, p); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(context.Background(), "UPDATE vm_disks SET path = ? WHERE vm_name = 'tpl'", p); err != nil {
		t.Fatal(err)
	}
	if d := cloneDisk(t, s, "tpl"); d.Path != p {
		t.Fatalf("fixture: disk path %q, want %q", d.Path, p)
	}
	return s, p
}

// linkTheDisk replaces the disk at p with a link to another tenant's image.
func linkTheDisk(t *testing.T, p string) {
	t.Helper()
	other := filepath.Join(t.TempDir(), "other.qcow2")
	if err := qcow2.Create(other, 3<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(p, p+".saved"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, p); err != nil {
		t.Fatal(err)
	}
}

// swapTheDiskDirAtConvert swaps the directory of the disk at p for a link to
// a directory whose file of the same name is not an image, once the caller's
// checks are done and just before the conversion reads it.
func swapTheDiskDirAtConvert(t *testing.T, p string) *bool {
	t.Helper()
	dir := filepath.Dir(p)
	other := t.TempDir()
	if err := os.WriteFile(filepath.Join(other, filepath.Base(p)), []byte("OTHER-TENANT-NOT-AN-IMAGE"), 0o600); err != nil {
		t.Fatal(err)
	}
	swapped := false
	convertSourceHook = func(string) {
		if swapped {
			return
		}
		swapped = true
		if err := os.Rename(dir, dir+".saved"); err != nil {
			t.Error(err)
			return
		}
		if err := os.Symlink(other, dir); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { convertSourceHook = nil })
	return &swapped
}

func TestCloneVM_FullCloneRefusesALinkAtTheSourceDisk(t *testing.T) {
	s, p := convertSourceServer(t)
	linkTheDisk(t, p)
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1", Mode: "full"}); err == nil {
		t.Fatal("a full clone of a disk that is a link to another file succeeded")
	}
}

func TestCloneVM_FullCloneReadsTheHeldDirectory(t *testing.T) {
	s, p := convertSourceServer(t)
	swapped := swapTheDiskDirAtConvert(t, p)
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1", Mode: "full"}); err != nil {
		t.Fatalf("a full clone whose source directory was swapped after its checks read the swapped one: %v", err)
	}
	if !*swapped {
		t.Fatal("fixture: the hook did not run")
	}
	d := cloneDisk(t, s, "c1")
	info, err := qcow2.Info(d.Path)
	if err != nil || info.VirtualSize != 64<<20 {
		t.Fatalf("the clone's disk is not the template's image: %+v, %v", info, err)
	}
}

func TestBuildImage_RefusesALinkAtTheSourceDisk(t *testing.T) {
	s, p := convertSourceServer(t)
	linkTheDisk(t, p)
	if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "tpl", ImageName: "golden"}); err == nil {
		t.Fatal("an image build from a disk that is a link to another file succeeded")
	}
}

func TestBuildImage_ReadsTheHeldDirectory(t *testing.T) {
	s, p := convertSourceServer(t)
	swapped := swapTheDiskDirAtConvert(t, p)
	if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "tpl", ImageName: "golden"}); err != nil {
		t.Fatalf("an image build whose source directory was swapped after its checks read the swapped one: %v", err)
	}
	if !*swapped {
		t.Fatal("fixture: the hook did not run")
	}
	if info, err := qcow2.Info(s.images.ImagePath("golden")); err != nil || info.VirtualSize != 64<<20 {
		t.Fatalf("the image is not the VM's disk: %+v, %v", info, err)
	}
}
