package fencessh

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Lab 2 drill F2: with socket-activated sshd (Ubuntu 26.04), nothing creates
// /run/sshd after a reboot until ssh.service starts, and a root `sshd -T`
// fails "Missing privilege separation directory: /run/sshd". The evaluation
// creates it first, as ssh.service's RuntimeDirectory would.

func TestEnsurePrivsepDir_CreatesAMissingOne(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sshd")
	old := syscall.Umask(0o077) // a umask that would narrow the mode
	t.Cleanup(func() { syscall.Umask(old) })
	if err := ensurePrivsepDirAs(dir, os.Getuid()); err != nil {
		t.Fatalf("ensurePrivsepDirAs: %v", err)
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !fi.IsDir() || fi.Mode().Perm() != 0o755 {
		t.Errorf("created %s as %v, want a 0755 directory", dir, fi.Mode())
	}
	// Idempotent.
	if err := ensurePrivsepDirAs(dir, os.Getuid()); err != nil {
		t.Errorf("second call: %v", err)
	}
}

func TestEnsurePrivsepDir_KeepsACorrectOne(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o711, 0o700} {
		dir := filepath.Join(t.TempDir(), "sshd")
		if err := os.Mkdir(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := ensurePrivsepDirAs(dir, os.Getuid()); err != nil {
			t.Errorf("mode %v: %v", mode, err)
		}
		if fi, _ := os.Lstat(dir); fi.Mode().Perm() != mode {
			t.Errorf("mode %v changed to %v", mode, fi.Mode().Perm())
		}
	}
}

// One that exists the wrong way is refused, and left as it is.
func TestEnsurePrivsepDir_RefusesAndLeavesAWrongOne(t *testing.T) {
	base := t.TempDir()
	for _, tc := range []struct {
		name  string
		setup func(p string) error
		owner int
		want  string
		mode  os.FileMode
	}{
		{name: "group-writable", setup: func(p string) error { return mkdirMode(p, 0o775) },
			owner: os.Getuid(), want: "writable", mode: 0o775},
		{name: "world-writable", setup: func(p string) error { return mkdirMode(p, 0o757) },
			owner: os.Getuid(), want: "writable", mode: 0o757},
		{name: "another owner", setup: func(p string) error { return mkdirMode(p, 0o755) },
			owner: os.Getuid() + 1, want: "owned by uid", mode: 0o755},
		{name: "a file", setup: func(p string) error { return os.WriteFile(p, nil, 0o644) },
			owner: os.Getuid(), want: "not a directory", mode: 0o644},
		{name: "a symlink", setup: func(p string) error { return os.Symlink(base, p) },
			owner: os.Getuid(), want: "not a directory"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(base, strings.ReplaceAll(tc.name, " ", "-"))
			if err := tc.setup(p); err != nil {
				t.Fatal(err)
			}
			err := ensurePrivsepDirAs(p, tc.owner)
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), p) {
				t.Fatalf("ensurePrivsepDirAs = %v, want a refusal naming %s and %q", err, p, tc.want)
			}
			if tc.mode != 0 {
				if fi, _ := os.Lstat(p); fi.Mode().Perm() != tc.mode {
					t.Errorf("mode changed from %v to %v", tc.mode, fi.Mode().Perm())
				}
			}
		})
	}
}

func mkdirMode(p string, mode os.FileMode) error {
	if err := os.Mkdir(p, mode); err != nil {
		return err
	}
	return os.Chmod(p, mode)
}

// SSHDAccepting ensures the directory before it runs sshd -T, and a refusal
// is an evaluation failure (the caller keeps what it last published), never
// an answer.
func TestSSHDAccepting_EnsuresThePrivsepDirFirst(t *testing.T) {
	old := ensurePrivsep
	t.Cleanup(func() { ensurePrivsep = old })
	calls := 0
	ensurePrivsep = func() error { calls++; return nil }
	missing := filepath.Join(t.TempDir(), "no-sshd")
	_, _, _ = SSHDAccepting(missing, "", "/etc/litevirt/ssh")(context.Background(), []string{"10.77.0.3"})
	if calls != 1 {
		t.Errorf("ensurePrivsep ran %d times, want 1", calls)
	}
	boom := errors.New("/run/sshd is owned by uid 1000")
	ensurePrivsep = func() error { return boom }
	ok, why, err := SSHDAccepting(missing, "", "/etc/litevirt/ssh")(context.Background(), []string{"10.77.0.3"})
	if ok || why != "" || !errors.Is(err, boom) {
		t.Errorf("= %v %q %v, want the refusal as an evaluation error", ok, why, err)
	}
}
