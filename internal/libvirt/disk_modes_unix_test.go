//go:build unix

package libvirt

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"

	"github.com/litevirt/litevirt/internal/qcow2"
)

func umask022(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

func wantMode(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s is %04o, want %04o", p, got, want)
	}
}

// A snapshot revert's fresh overlay takes the guest's writes from then on, so
// it is owner-only from the moment it exists — made 0600 before qemu-img
// writes into it, never qemu-img's own 0644. Needs a real qemu-img.
//
// Mutation: drop the exclusive 0600 create before qemu-img (resetOverlay) —
// this goes red.
func TestResetOverlay_TheNewOverlayIsOwnerOnly(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	umask022(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "base.s1")
	if err := os.WriteFile(overlay, []byte("old overlay"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := resetOverlay(overlay, base); err != nil {
		t.Fatal(err)
	}
	wantMode(t, overlay, 0o600)
	if info, err := qcow2.Info(overlay); err != nil || info.BackingFile != base {
		t.Fatalf("the reset overlay is not a qcow2 over its base: %+v %v", info, err)
	}
}

// A point-in-time snapshot's overlay is made by libvirt; once the snapshot
// succeeds it is narrowed to its owner (qemu, by libvirt's label), so the
// guest's writes during the copy are not world-readable whatever mode libvirt
// gave it.
//
// Mutation: drop the narrowing in snapshotDiskExternal — this goes red.
func TestPITSnapshot_TheOverlayIsNarrowed(t *testing.T) {
	m := newPITModel()
	overlay := filepath.Join(t.TempDir(), ".web-root.qcow2.lv-pit")
	if err := os.WriteFile(overlay, nil, 0o644); err != nil { // as libvirt might leave it
		t.Fatal(err)
	}
	if err := os.Chmod(overlay, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := snapshotDiskExternal(m, "web", "/pool/web-root.qcow2", overlay); err != nil {
		t.Fatal(err)
	}
	wantMode(t, overlay, 0o600)
}

// A restored UEFI VM's NVRAM directory, when the restore makes it, is 0711.
//
// Mutation: ReadFirmwareBundle's nvram MkdirAll at 0o755 — this goes red.
func TestReadFirmwareBundle_ANewNvramDirIsSearchableOnly(t *testing.T) {
	base := testSwtpmBase(t)
	umask022(t)
	src := storeAt(base, t.TempDir())
	seedFirmware(t, src, "src", "uuid-src", true, false)
	var buf bytes.Buffer
	if _, err := src.WriteFirmwareBundle("src", "uuid-src", &buf); err != nil {
		t.Fatal(err)
	}
	dst := storeAt(base, t.TempDir())
	if err := dst.ReadFirmwareBundle(&buf, "dst", "uuid-dst"); err != nil {
		t.Fatal(err)
	}
	wantMode(t, filepath.Dir(dst.NvramPath("dst")), 0o711)
	wantMode(t, dst.NvramPath("dst"), 0o600)
}

// The retained-firmware marker's directory is the NVRAM directory; when the
// marker makes it, it is 0711 like the restore's.
//
// Mutation: WriteRetainedFirmwareMarker's MkdirAll at 0o755 — this goes red.
func TestWriteRetainedFirmwareMarker_ANewNvramDirIsSearchableOnly(t *testing.T) {
	umask022(t)
	dataDir := t.TempDir()
	if err := storeAt(testSwtpmBase(t), dataDir).WriteRetainedFirmwareMarker("vm", "uuid-keep"); err != nil {
		t.Fatal(err)
	}
	wantMode(t, filepath.Join(dataDir, "nvram"), 0o711)
}

// The reset overlay is never at a wider mode, not even while qemu-img writes
// it: qemu-img is handed an existing 0600 file. A stand-in qemu-img on PATH
// records the mode of the file it is told to create.
//
// Mutation: drop the 0600 create before qemu-img (the narrowing after it still
// runs) — this goes red.
func TestResetOverlay_QemuImgWritesAnOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the stand-in tool uses GNU stat")
	}
	umask022(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	seen := filepath.Join(bin, "seen")
	script := "#!/bin/sh\nfor a; do out=$a; done\n" +
		"if [ -e \"$out\" ]; then stat -c %a \"$out\" > " + seen + "; else echo absent > " + seen + "; fi\n: > \"$out\"\n"
	if err := os.WriteFile(filepath.Join(bin, "qemu-img"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	overlay := filepath.Join(dir, "base.s1")
	if err := resetOverlay(overlay, base); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(seen)
	if s := string(got); s != "600\n" {
		t.Errorf("qemu-img wrote into a file that was %q, want an existing 600", s)
	}
}
