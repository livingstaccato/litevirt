//go:build unix

package qcow2

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// Every image this package makes — an empty disk, an overlay on a base, a
// converted copy — is the owner's alone (0600): it is a guest's data, and the
// one other process that opens it, qemu, does so as its owner after libvirt's
// label. Before, the create was 0644 and any local user could read the guest.
// The umask is the daemon's usual 022, so it hides nothing.
//
// Mutation: create the temp at 0o644 again (createImage) — every case goes red.
func TestCreate_NewImagesAreOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	overlay := filepath.Join(dir, "overlay.qcow2")
	flat := filepath.Join(dir, "flat.qcow2")
	if err := Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := CreateWithBacking(overlay, base, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := Convert(context.Background(), overlay, flat, nil); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{base, overlay, flat} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o600 {
			t.Errorf("%s is %04o, want 0600 (owner only)", filepath.Base(p), got)
		}
	}
}
