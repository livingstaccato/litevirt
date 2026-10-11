//go:build linux

package cloudinit

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
	"time"

	"github.com/litevirt/litevirt/internal/diskmode"
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

// standIn puts a genisoimage on PATH that runs body with $out set to its
// -output argument.
func standIn(t *testing.T, body string) string {
	t.Helper()
	bin := t.TempDir()
	script := "#!/bin/sh\nfor a; do [ \"$prev\" = -output ] && out=$a; prev=$a; done\n" + body
	if err := os.WriteFile(filepath.Join(bin, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	return bin
}

// M2: a seed whose narrowing is refused is still placed, and that is logged.
//
// Mutation: GenerateISO fails on the narrowing again — this goes red.
func TestGenerateISO_ARefusedChmodNeverFailsTheSeed(t *testing.T) {
	standIn(t, ": > \"$out\"; chmod 0644 \"$out\"\n")
	log := refuseChmod(t)
	out := filepath.Join(t.TempDir(), "vm1.iso")
	if err := GenerateISO(Config{InstanceID: "vm1", LocalHostname: "vm1"}, out); err != nil {
		t.Fatalf("the seed failed on a refused chmod: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "operation not permitted") {
		t.Errorf("no warning:\n%s", log.String())
	}
}

// M4: the real genisoimage writes into the 0600 file it is handed — same
// inode, still 0600 — with no narrowing to mask it (chmod refused).
//
// Mutation: drop the 0600 pre-create — genisoimage's own file is 0644: red.
func TestGenerateISO_RealGenisoimageKeepsThePreMadeInode(t *testing.T) {
	real, err := exec.LookPath("genisoimage")
	if err != nil {
		t.Skip("genisoimage not installed")
	}
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	refuseChmod(t)
	bin := standIn(t, "stat -c %i \"$out\" > \"$(dirname \"$0\")/seen\" 2>/dev/null || echo absent > \"$(dirname \"$0\")/seen\"\nexec "+real+" \"$@\"\n")
	out := filepath.Join(t.TempDir(), "vm1.iso")
	if err := GenerateISO(Config{InstanceID: "vm1", LocalHostname: "vm1"}, out); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(filepath.Join(bin, "seen"))
	if s := strings.TrimSpace(string(got)); s != strconv.FormatUint(fi.Sys().(*syscall.Stat_t).Ino, 10) {
		t.Errorf("genisoimage was handed inode %q, the seed is inode %d", s, fi.Sys().(*syscall.Stat_t).Ino)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("seed is %04o, want 0600", fi.Mode().Perm())
	}
}

// M6: a crashed run's seed temp — it holds the user-data — is removed by the
// next generation of that seed once it is an hour old; a fresh one (a
// concurrent run's) is kept.
//
// Mutation: drop the sweep — the stale temp stays: red.
func TestGenerateISO_SweepsAStaleSeedTemp(t *testing.T) {
	standIn(t, ": > \"$out\"\n")
	dir := t.TempDir()
	out := filepath.Join(dir, "vm1.iso")
	stale := filepath.Join(dir, ".vm1.iso.0123456789abcdef.tmp")
	fresh := filepath.Join(dir, ".vm1.iso.fedcba9876543210.tmp")
	other := filepath.Join(dir, ".vm2.iso.0123456789abcdef.tmp")
	for _, p := range []string{stale, fresh, other} {
		if err := os.WriteFile(p, []byte("password: x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{stale, other} {
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := GenerateISO(Config{InstanceID: "vm1", LocalHostname: "vm1"}, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !os.IsNotExist(err) {
		t.Error("the stale seed temp was left")
	}
	for _, p := range []string{fresh, other} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was removed: %v", filepath.Base(p), err)
		}
	}
}
