package fencessh

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Round 1, finding 4: InstallScript runs `sshd -T` and `sshd -t` itself, and
// after a reboot under socket-activated sshd a root run of it met the same
// "Missing privilege separation directory: /run/sshd" as the daemon did. It
// creates the directory first, as ssh.service would, and refuses one that is
// not held as sshd needs, changing nothing. FENCE_SSH_PRIVSEP_DIR and
// FENCE_SSH_PRIVSEP_OWNER (the uid it must run as and the directory must be
// owned by; 0 in production) let an unprivileged test drive it.

func privsepEnv(dir string) []string {
	return []string{"FENCE_SSH_PRIVSEP_DIR=" + dir, fmt.Sprintf("FENCE_SSH_PRIVSEP_OWNER=%d", os.Getuid())}
}

func TestInstallScript_CreatesThePrivsepDir(t *testing.T) {
	w := newInstallWorld(t, "")
	p := filepath.Join(t.TempDir(), "sshd")
	// Under a umask that would narrow it.
	cmd := exec.Command("bash", "-c", InstallScript+"\numask 077\nlv_fence_ssh_install")
	cmd.Env = append(os.Environ(), append(privsepEnv(p),
		"FENCE_SSH_SSHD_CONFIG="+w.cfg, "FENCE_SSH_DROPIN_DIR="+w.ddir, "FENCE_SSH_DIR="+w.dir,
		"FENCE_SSH_SSHD="+SSHDPath(), "FENCE_SSH_RELOAD=true", "FENCE_SSH_PEERS=10.77.0.3")...)
	outb, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install script: %v\n%s", err, outb)
	}
	out := string(outb)
	fi, err := os.Lstat(p)
	if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o755 {
		t.Fatalf("privsep dir = %v %v, want a 0755 directory\n%s", fi, err, out)
	}
	if w.dropIn(t) == "" {
		t.Errorf("nothing installed: %s", out)
	}
}

func TestInstallScript_RefusesAWrongPrivsepDir(t *testing.T) {
	base := t.TempDir()
	for _, tc := range []struct {
		name  string
		setup func(p string) error
		want  string
	}{
		{"group-writable", func(p string) error { return mkdirMode(p, 0o775) }, "writable"},
		{"world-writable", func(p string) error { return mkdirMode(p, 0o757) }, "writable"},
		{"a file", func(p string) error { return os.WriteFile(p, nil, 0o644) }, "not a directory"},
		{"a symlink", func(p string) error { return os.Symlink(base, p) }, "not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newInstallWorld(t, "")
			p := filepath.Join(base, strings.ReplaceAll(tc.name, " ", "-"))
			if err := tc.setup(p); err != nil {
				t.Fatal(err)
			}
			before, _ := os.Lstat(p)
			out := w.run(t, append(privsepEnv(p), "FENCE_SSH_PEERS=10.77.0.3")...)
			if w.dropIn(t) != "" || !strings.Contains(out, p) || !strings.Contains(out, tc.want) {
				t.Errorf("drop-in %q, output %q; want nothing installed and %s named as %q", w.dropIn(t), out, p, tc.want)
			}
			if after, _ := os.Lstat(p); after.Mode() != before.Mode() {
				t.Errorf("mode changed from %v to %v", before.Mode(), after.Mode())
			}
		})
	}
	t.Run("another owner", func(t *testing.T) {
		w := newInstallWorld(t, "")
		p := filepath.Join(base, "other-owner")
		if err := mkdirMode(p, 0o755); err != nil {
			t.Fatal(err)
		}
		// Run as uid X only where the directory is not X's: the test runs as
		// its own uid, so the script is told to expect another owner by
		// faking id.
		bin := t.TempDir()
		if err := os.WriteFile(filepath.Join(bin, "id"), []byte("#!/bin/sh\necho 4242\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		out := w.run(t, "FENCE_SSH_PRIVSEP_DIR="+p, "FENCE_SSH_PRIVSEP_OWNER=4242",
			"PATH="+bin+":"+os.Getenv("PATH"), "FENCE_SSH_PEERS=10.77.0.3")
		if w.dropIn(t) != "" || !strings.Contains(out, "owned by uid") {
			t.Errorf("drop-in %q, output %q; want another owner refused", w.dropIn(t), out)
		}
	})
}

// Run by anyone but its owner (root in production), it creates nothing.
func TestInstallScript_AnUnprivilegedRunCreatesNoPrivsepDir(t *testing.T) {
	w := newInstallWorld(t, "")
	p := filepath.Join(t.TempDir(), "sshd")
	w.run(t, "FENCE_SSH_PRIVSEP_DIR="+p, fmt.Sprintf("FENCE_SSH_PRIVSEP_OWNER=%d", os.Getuid()+1), "FENCE_SSH_PEERS=10.77.0.3")
	if _, err := os.Lstat(p); err == nil {
		t.Error("an unprivileged run created the privsep dir")
	}
}

// lv_fence_ssh_reload runs `sshd -t` on its own (an install that removes the
// drop-in, `lv host init`'s setup): it ensures the directory too.
func TestInstallScriptReload_CreatesThePrivsepDir(t *testing.T) {
	cfg := sshdConfig(t, "")
	p := filepath.Join(t.TempDir(), "sshd")
	cmd := exec.Command("bash", "-c", InstallScript+"\nlv_fence_ssh_reload; true")
	cmd.Env = append(os.Environ(), append(privsepEnv(p),
		"FENCE_SSH_SSHD="+SSHDPath(), "FENCE_SSH_SSHD_CONFIG="+cfg, "FENCE_SSH_RELOAD=true")...)
	out, _ := cmd.CombinedOutput()
	if fi, err := os.Lstat(p); err != nil || !fi.IsDir() {
		t.Fatalf("lv_fence_ssh_reload did not create %s: %v\n%s", p, err, out)
	}
}
