//go:build unix

package cloudinit

import (
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
)

// The NoCloud seed carries the VM's user-data — passwords, keys, tokens — and
// is attached to the guest as a disk, so it is owner-only like one: made 0600
// before genisoimage writes into it. Its directory, when made here, is 0711
// (qemu opens the seed through it after libvirt's label). Without genisoimage
// the Go writer stands in, which writes into the same pre-made file.
//
// Mutations: drop the 0600 create before genisoimage — the seed goes red; the
// output MkdirAll at 0755 — the directory goes red.
func TestGenerateISO_TheSeedIsOwnerOnly(t *testing.T) {
	UseGoISOWithoutGenisoimage(t)
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	out := filepath.Join(t.TempDir(), "cloudinit", "vm1.iso")
	if err := GenerateISO(Config{InstanceID: "vm1", LocalHostname: "vm1", UserData: "#cloud-config\npassword: hunter2\n"}, out); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]os.FileMode{out: 0o600, filepath.Dir(out): 0o711} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s is %04o, want %04o", p, got, want)
		}
	}
}

// The seed is never at a wider mode, not even while genisoimage writes it: the
// file genisoimage is handed already exists and is 0600 (a chmod afterwards
// would leave a window in which another user could open it and keep the
// descriptor). A stand-in genisoimage on PATH records the mode of the file it
// is told to write.
//
// Mutation: drop the 0600 create before genisoimage (the narrowing after it
// still runs) — this goes red.
func TestGenerateISO_GenisoimageWritesAnOwnerOnlyFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the stand-in tool uses GNU stat")
	}
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	bin := t.TempDir()
	seen := filepath.Join(bin, "seen")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -output ] && out=$2; shift; done\n" +
		"if [ -e \"$out\" ]; then stat -c %a \"$out\" > " + seen + "; else echo absent > " + seen + "; fi\n: > \"$out\"\n"
	if err := os.WriteFile(filepath.Join(bin, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	out := filepath.Join(t.TempDir(), "vm1.iso")
	if err := GenerateISO(Config{InstanceID: "vm1", LocalHostname: "vm1"}, out); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(seen)
	if s := string(got); s != "600\n" {
		t.Errorf("genisoimage wrote into a file that was %q, want an existing 600", s)
	}
}
