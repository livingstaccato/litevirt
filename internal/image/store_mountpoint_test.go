package image

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/storage"
)

// F-1: Init leaves alone a store directory the mount table has as a mount
// point — the image store mounted from an NFS server, as lab 2 did — making
// no system call on it: a stat there blocks the daemon's start for as long
// as the server does not answer. The other directory is still created.
//
// Mutation "no mount-point skip" — Init makes the mount point's directory
// (here, absent, so the MkdirAll shows): red.
func TestStore_InitLeavesAMountPointAlone(t *testing.T) {
	data := t.TempDir()
	images := filepath.Join(data, "images")
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) {
		return []byte(fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"+
			"40 1 0:60 / %s rw,nosuid,nodev,noexec - nfs4 nas:/images rw\n", images)), nil
	}))
	s := NewStore(data)
	if err := s.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(images); !os.IsNotExist(err) {
		t.Fatalf("Init touched the mount point %s (stat err=%v)", images, err)
	}
	if fi, err := os.Stat(filepath.Join(data, "disks")); err != nil || !fi.IsDir() {
		t.Fatalf("the disk directory was not created: %v", err)
	}
}
