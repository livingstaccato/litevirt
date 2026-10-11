//go:build linux

package libvirt

import (
	"bytes"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/diskmode"
	"github.com/litevirt/litevirt/internal/qcow2"
)

func refuseChmod(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	t.Cleanup(diskmode.SetFchmodForTest(func(*os.File, fs.FileMode) error { return syscall.EPERM }))
	return &buf
}

// M2: a revert whose new overlay cannot be narrowed still succeeds (the old
// overlay is already gone; failing here would report a valid revert as
// failed), and says so.
//
// Mutation: resetOverlay returns the Narrow error again — this goes red.
func TestResetOverlay_ARefusedChmodNeverFailsTheRevert(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "base.s1")
	log := refuseChmod(t)
	// A narrowing is attempted only on a mode wider than the owner's: make
	// qemu-img's file wide by handing it one (the pre-create is 0600, so stand
	// in a umask-free tool that widens it).
	bin := t.TempDir()
	real, _ := exec.LookPath("qemu-img")
	script := "#!/bin/sh\nfor a; do out=$a; done\n" + real + " \"$@\" && chmod 0644 \"$out\"\n"
	if err := os.WriteFile(filepath.Join(bin, "qemu-img"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := resetOverlay(overlay, base); err != nil {
		t.Fatalf("the revert failed on a refused chmod: %v", err)
	}
	if !strings.Contains(log.String(), overlay) || !strings.Contains(log.String(), "operation not permitted") {
		t.Errorf("no warning naming %s:\n%s", overlay, log.String())
	}
}

// M4: real qemu-img create writes into the overlay file it is handed — same
// inode, still 0600 — with no narrowing to mask it (chmod refused). A wrapper
// records the inode qemu-img was handed, then runs the real one.
//
// Mutation: drop the 0600 pre-create in resetOverlay — the wrapper sees no
// file and the mode is qemu-img's 0644: red.
func TestResetOverlay_RealQemuImgKeepsThePreMadeInode(t *testing.T) {
	real, err := exec.LookPath("qemu-img")
	if err != nil {
		t.Skip("qemu-img not installed")
	}
	umask022(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	refuseChmod(t)
	bin := t.TempDir()
	seen := filepath.Join(bin, "seen")
	script := "#!/bin/sh\nfor a; do out=$a; done\nstat -c %i \"$out\" > " + seen + " 2>/dev/null || echo absent > " + seen + "\nexec " + real + " \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "qemu-img"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	overlay := filepath.Join(dir, "base.s1")
	if err := resetOverlay(overlay, base); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(overlay)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(seen)
	if want := strings.TrimSpace(string(got)); want != strconv.FormatUint(fi.Sys().(*syscall.Stat_t).Ino, 10) {
		t.Errorf("qemu-img was handed inode %q, the overlay is inode %d", want, fi.Sys().(*syscall.Stat_t).Ino)
	}
	wantMode(t, overlay, 0o600)
	if info, err := qcow2.Info(overlay); err != nil || info.BackingFile != base {
		t.Fatalf("not a qcow2 over its base: %+v %v", info, err)
	}
}

// M6: the overlays a disk snapshot makes are narrowed through the code
// CreateSnapshot and CreateLiveSnapshot share — the model makes them with real
// qemu-img (0644) — and the disk the domain was on before is not touched.
//
// Mutation: snapshotDisksNarrowed drops its narrowing — this goes red.
func TestSnapshotDisksNarrowed_NarrowsOnlyTheNewOverlays(t *testing.T) {
	umask022(t)
	m := newLibvirt10(t)
	root := m.dom.disks["vda"]
	if err := os.Chmod(root, 0o644); err != nil {
		t.Fatal(err)
	}
	x, err := snapshotCreateXML(m, golibvirt.Domain{Name: "vm"}, "s1")
	if err != nil {
		t.Fatal(err)
	}
	if err := snapshotDisksNarrowed(m, golibvirt.Domain{Name: "vm"}, x,
		uint32(golibvirt.DomainSnapshotCreateDiskOnly|golibvirt.DomainSnapshotCreateAtomic)); err != nil {
		t.Fatal(err)
	}
	ov := m.dom.disks["vda"]
	if ov == root {
		t.Fatal("the snapshot made no overlay")
	}
	wantMode(t, ov, 0o600)
	wantMode(t, root, 0o644) // no backfill
}
