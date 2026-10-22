//go:build linux

package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

// btrfsPoolServer is a create server with a btrfs pool "bt" on a test
// directory: subvolumes are plain directories (a btrfs stand-in on PATH whose
// "subvolume create" refuses a name that exists, as btrfs does).
func btrfsPoolServer(t *testing.T) (*Server, *libvirtfake.Fake, string) {
	t.Helper()
	stageGenisoimage(t)
	bin := t.TempDir()
	script := "#!/bin/sh\ncase \"$1 $2\" in\n" +
		"\"subvolume create\") exec mkdir -m 0755 \"$4\";;\n" +
		"\"subvolume delete\") exec rm -rf \"$4\";;\n" +
		"\"subvolume show\") [ -d \"$4\" ] && exit 0; exit 1;;\nesac\nexit 1\n"
	if err := os.WriteFile(filepath.Join(bin, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Cleanup(storage.OverrideBtrfsFilesystemForTest())
	s, fake, _ := isoServer(t)
	root := filepath.Join(t.TempDir(), "bt")
	s.addStoragePoolRef("bt", StoragePoolRef{Driver: "btrfs", Source: root})
	return s, fake, root
}

func btrfsCreateRequest(t *testing.T, s *Server, name string) *pb.CreateVMRequest {
	req := seedCreateRequest(t, s, name, "")
	req.Spec.Disks = append(req.Spec.Disks, &pb.DiskSpec{Name: "data", Size: "1M", Storage: "bt"})
	return req
}

// A failed create on a btrfs pool removes the subvolume its disk was made in,
// not only the disk file: a subvolume left behind made a retry of the same
// VM and disk name fail at `btrfs subvolume create`.
//
// Mutation: drop the subvolume removal from the create's cleanup — the
// subvolume stays and the retry fails creating it, red.
func TestCreateVM_AFailedCreateOnABtrfsPoolRemovesItsSubvolume(t *testing.T) {
	s, fake, root := btrfsPoolServer(t)
	const name = "bsv"
	subvol := filepath.Join(root, name+"-data")
	fake.FailStartDomain = func(string) error {
		if _, err := os.Stat(filepath.Join(subvol, name+"-data.qcow2")); err != nil {
			t.Errorf("setup: the disk is not in its subvolume at the start: %v", err)
		}
		return errors.New("start failed")
	}
	if _, err := s.CreateVM(adminCtx(), btrfsCreateRequest(t, s, name)); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if _, err := os.Lstat(subvol); !os.IsNotExist(err) {
		t.Errorf("the failed create left its subvolume %s: %v", subvol, err)
	}
	_, err := s.CreateVM(adminCtx(), btrfsCreateRequest(t, s, name))
	if err == nil || !strings.Contains(err.Error(), "start failed") {
		t.Errorf("a retry of the name = %v, want it to reach its start again", err)
	}
}

// The subvolume is removed only while it is empty: a file someone put in it
// meanwhile is never deleted with it, and the subvolume stays, named in the
// create's error.
//
// Mutation: remove the subvolume with everything in it — the other file goes,
// red.
func TestCreateVM_AFailedCreateLeavesASubvolumeThatHoldsAnotherFile(t *testing.T) {
	s, fake, root := btrfsPoolServer(t)
	const name = "bsvo"
	subvol := filepath.Join(root, name+"-data")
	other := filepath.Join(subvol, "another.qcow2")
	fake.FailStartDomain = func(string) error {
		if err := os.WriteFile(other, []byte("another's"), 0o600); err != nil {
			t.Errorf("setup: %v", err)
		}
		return errors.New("start failed")
	}
	_, err := s.CreateVM(adminCtx(), btrfsCreateRequest(t, s, name))
	if err == nil {
		t.Fatal("the create was meant to fail")
	}
	if b, rerr := os.ReadFile(other); rerr != nil || string(b) != "another's" {
		t.Fatalf("the failed create removed a file it did not make: %q %v", b, rerr)
	}
	if _, serr := os.Lstat(filepath.Join(subvol, name+"-data.qcow2")); !os.IsNotExist(serr) {
		t.Errorf("the failed create left its own disk: %v", serr)
	}
	if !strings.Contains(err.Error(), subvol) {
		t.Errorf("the create's error does not name the subvolume it left: %v", err)
	}
}
