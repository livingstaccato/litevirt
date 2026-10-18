package ssh

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// WriteFile ran `cat > path && chmod mode path`, so the file existed with its
// full contents at the remote umask — 0644 in a directory created 0755 — for
// the whole transfer, and permanently if the connection dropped between the
// two.
//
// The payload is host.key. CopyFileMode exists precisely because host.key was
// shipping 0644, and this is the same exposure one layer down.
//
// A plain `chmod` first does not fix it either: redirecting into an EXISTING
// file truncates it and keeps its old mode, so a re-provision over a loose file
// writes the new key at the old permissions. The content has to land somewhere
// private and be moved into place.
func TestWriteFileCmd_NeverExposesContentAtTheWrongMode(t *testing.T) {
	const path = "/etc/litevirt/pki/host.key"
	cmd := writeFileCmd(path, 0600)

	if strings.Contains(cmd, "cat > "+path) || strings.Contains(cmd, "cat >"+path) {
		t.Errorf("content is redirected straight at the destination, which exists "+
			"at the remote umask until the chmod lands:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "mktemp") {
		t.Errorf("no private temporary file in:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "mv") {
		t.Errorf("the staged file is never moved into place:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "600") {
		t.Errorf("the requested mode never appears in:\n  %s", cmd)
	}

	// The chmod must happen before the move, or the destination is briefly
	// correct-content-wrong-mode all over again.
	chmodAt, mvAt := strings.Index(cmd, "chmod"), strings.LastIndex(cmd, "mv")
	if chmodAt < 0 || mvAt < 0 || chmodAt > mvAt {
		t.Errorf("chmod does not precede the move:\n  %s", cmd)
	}
}

// A path with a space must not split into two arguments.
func TestWriteFileCmd_QuotesThePath(t *testing.T) {
	cmd := writeFileCmd("/etc/lite virt/host.key", 0600)
	if strings.Contains(cmd, "/etc/lite virt/host.key") &&
		!strings.Contains(cmd, "'/etc/lite virt/host.key'") {
		t.Errorf("unquoted path with a space:\n  %s", cmd)
	}
}

// `mv src dest` where dest is a DIRECTORY moves src INSIDE it rather than
// failing. Process command lines are world-readable on a default Linux, so a
// local user on the target can read the destination path out of the running
// command, mkdir it first, let the staged file land inside, then rename their
// directory away and leave their own file at the path root is about to read.
//
// Randomising the destination name does not help: the attacker does not have
// to guess it, they can see it. -T makes the directory case an error.
func TestWriteFileCmd_RefusesToMoveIntoADirectory(t *testing.T) {
	cmd := writeFileCmd("/etc/litevirt/pki/host.key", 0600)

	if !strings.Contains(cmd, "mv -fT") && !strings.Contains(cmd, "mv -Tf") {
		t.Errorf("mv is not given -T, so a pre-created directory at the destination "+
			"silently captures the staged file:\n  %s", cmd)
	}
	if !strings.Contains(cmd, "--") {
		t.Errorf("mv is not given --, so a destination starting with '-' parses as options:\n  %s", cmd)
	}
}

// A3: `lv host add` pushes /usr/local/bin/litevirt while the machine's daemon
// may be running from it. Writing into a running executable fails with
// ETXTBSY ("Text file busy"), which stopped an add on the lab; the staged
// write replaces it by rename, which the running process does not prevent.
//
// Mutation: write with `cat > path` — the push fails with ETXTBSY.
func TestWriteFileCmd_ReplacesARunningExecutable(t *testing.T) {
	src, err := exec.LookPath("sleep")
	if err != nil {
		t.Skip("no sleep binary")
	}
	exe := filepath.Join(t.TempDir(), "litevirt")
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(exe, b, 0o755); err != nil {
		t.Fatal(err)
	}
	running := exec.Command(exe, "30")
	if err := running.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = running.Process.Kill(); _ = running.Wait() })

	push := exec.Command("sh", "-c", writeFileCmd(exe, 0o755))
	push.Stdin = strings.NewReader("new build")
	if out, err := push.CombinedOutput(); err != nil {
		t.Fatalf("pushing over a running executable: %v\n%s", err, out)
	}
	if got, _ := os.ReadFile(exe); string(got) != "new build" {
		t.Errorf("the running executable was not replaced (it holds %d bytes, not the pushed build)", len(got))
	}
}

// fd review m3: without a sync before the rename, a power loss soon after a
// push can leave the destination renamed over but empty (XFS has no
// replace-by-rename flush). The staged file is synced before the move and the
// directory after it.
//
// Mutation: drop either sync — the order check fails.
func TestWriteFileCmd_SyncsAroundTheRename(t *testing.T) {
	cmd := writeFileCmd("/etc/litevirt/pki/host.key", 0o600)
	mv := strings.Index(cmd, "mv -fT")
	before := strings.Index(cmd, "sync -- \"$t\"")
	after := strings.Index(cmd, "sync -- \"$d\"")
	if before < 0 || before > mv || after < mv {
		t.Errorf("the staged file is not synced before the move and its directory after:\n  %s", cmd)
	}
}

// fd re-review N-m1: a failed sync of the staged file (EIO) was swallowed by
// a fallback to a global `sync`, which reports success whatever happened (and
// blocks on a hung mount), and the rename then put a file whose writeback
// failed over a good one. A sync failure now fails the write, and the
// destination is left as it was.
//
// Mutation: restore the `|| sync` fallback — the write succeeds.
func TestWriteFileCmd_AFailedSyncDoesNotRename(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "sync"), []byte("#!/bin/sh\n# fails a file sync (EIO); a global sync succeeds\n[ $# -gt 0 ] && exit 1\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "host.key")
	if err := os.WriteFile(dst, []byte("good"), 0o600); err != nil {
		t.Fatal(err)
	}
	push := exec.Command("sh", "-c", writeFileCmd(dst, 0o600))
	push.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	push.Stdin = strings.NewReader("new")
	if err := push.Run(); err == nil {
		t.Error("a write whose sync failed reported success")
	}
	if got, _ := os.ReadFile(dst); string(got) != "good" {
		t.Errorf("the destination was replaced after a failed sync: %q", got)
	}
}
