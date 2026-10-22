package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// requireInodeReuse skips unless the filesystem under dir gives a freed inode
// to a file made after it: only there can an inode comparison be fooled.
func requireInodeReuse(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o711); err != nil {
		t.Fatal(err)
	}
	ctl := filepath.Join(dir, "control")
	if err := os.WriteFile(ctl, []byte("control"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(ctl)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
	if !takeFreedInode(t, ctl, fi, "control", 1024) {
		t.Skip("this filesystem does not reuse a freed inode, so it cannot fool an inode comparison")
	}
	if err := os.Remove(ctl); err != nil {
		t.Fatal(err)
	}
}

// replaceOnItsInode removes the file at p and puts another there that is
// given p's very inode where the filesystem allows it (reported), or merely
// another file otherwise.
func replaceOnItsInode(t *testing.T, p, content string) bool {
	t.Helper()
	old, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if takeFreedInode(t, p, old, content, 1024) {
		return true
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return false
}

// A failed create removes a disk it made only while the file at the path is
// still that one. Here another's disk replaces it and is given the made
// disk's very inode, so it reads the same by device and inode; birth time
// cannot tell them apart where the filesystem keeps none (NFS) or stamps both
// in one tick. The create holds each disk it made open until it returns, so
// the inode stays that file's and the other can never take it.
//
// Mutation: release each disk's pin right after pinning — the other disk
// takes the inode, and the failed create removes it, red.
func TestCreateVM_AFailedCreateLeavesADiskOnTheReusedInode(t *testing.T) {
	stageGenisoimage(t)
	s, fake, _ := isoServer(t)
	const name = "dpin"
	disk := s.images.DiskPath(name, "root")
	requireInodeReuse(t, filepath.Dir(disk))

	var reused, replaced bool
	fake.FailStartDomain = func(string) error {
		replaced = true
		reused = replaceOnItsInode(t, disk, "another's disk")
		return errors.New("start failed")
	}
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if !replaced {
		t.Fatal("setup: the create never reached its start, so no disk was replaced")
	}
	t.Logf("the other disk took the made disk's inode: %v", reused)
	if b, err := os.ReadFile(disk); err != nil || string(b) != "another's disk" {
		t.Errorf("the failed create removed a disk it did not make (it had the made disk's inode: %v): %q %v", reused, b, err)
	}
}

// A failed clone removes a copy it wrote only while the file at the path is
// still that one: the same as a create's disks, with the replacement given
// the copy's very inode.
//
// Mutation: release each copy's pin right after pinning — the other file
// takes the inode, and the failed clone removes it, red.
func TestCloneVM_AFailedCloneLeavesADiskOnTheReusedInode(t *testing.T) {
	for _, mode := range []string{"linked", "full"} {
		t.Run(mode, func(t *testing.T) {
			s := cloneTargetServer(t)
			fake := s.virt.(*libvirtfake.Fake)
			target := "cpin-" + mode
			disk := s.images.DiskPath(target, "root")
			requireInodeReuse(t, filepath.Dir(disk))

			var reused, replaced bool
			fake.FailDefineDomain = func(string) error {
				replaced = true
				reused = replaceOnItsInode(t, disk, "another's disk")
				return errors.New("define failed")
			}
			if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: target, Mode: mode}); err == nil {
				t.Fatal("the clone was meant to fail")
			}
			if !replaced {
				t.Fatal("setup: the clone never reached its define, so no disk was replaced")
			}
			t.Logf("the other disk took the copy's inode: %v", reused)
			if b, err := os.ReadFile(disk); err != nil || string(b) != "another's disk" {
				t.Errorf("the failed clone removed a disk it did not write (it had the copy's inode: %v): %q %v", reused, b, err)
			}
		})
	}
}

// The plain case still cleans up: a failed clone removes the copy it wrote
// when nothing replaced it.
func TestCloneVM_AFailedCloneRemovesItsOwnDisk(t *testing.T) {
	s := cloneTargetServer(t)
	fake := s.virt.(*libvirtfake.Fake)
	disk := s.images.DiskPath("cown", "root")
	fake.FailDefineDomain = func(string) error {
		if _, err := os.Stat(disk); err != nil {
			t.Errorf("setup: the copy is not there at the define: %v", err)
		}
		return errors.New("define failed")
	}
	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "cown", Mode: "full"}); err == nil {
		t.Fatal("the clone was meant to fail")
	}
	if _, err := os.Lstat(disk); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a failed clone left the copy it wrote: %v", err)
	}
}
