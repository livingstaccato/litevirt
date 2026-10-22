package fencessh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installWorld is an sshd configuration in a temp dir that Includes a temp
// drop-in directory, as /etc/ssh/sshd_config includes sshd_config.d/*.conf.
type installWorld struct {
	cfg, ddir, dir string
}

func newInstallWorld(t *testing.T, main string) *installWorld {
	t.Helper()
	root := t.TempDir()
	w := &installWorld{ddir: filepath.Join(root, "sshd_config.d"), dir: filepath.Join(root, "litevirt-ssh")}
	if err := os.MkdirAll(w.ddir, 0o755); err != nil {
		t.Fatal(err)
	}
	w.cfg = sshdConfig(t, "Include "+w.ddir+"/*.conf\n"+main)
	return w
}

func (w *installWorld) run(t *testing.T, env ...string) string {
	t.Helper()
	cmd := exec.Command("bash", "-c", InstallScript+"\nlv_fence_ssh_install")
	cmd.Env = append(os.Environ(), append([]string{
		"FENCE_SSH_SSHD_CONFIG=" + w.cfg, "FENCE_SSH_DROPIN_DIR=" + w.ddir, "FENCE_SSH_DIR=" + w.dir,
		"FENCE_SSH_SSHD=" + SSHDPath(), "FENCE_SSH_RELOAD=true",
	}, env...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("install script: %v\n%s", err, out)
	}
	return string(out)
}

func (w *installWorld) dropIn(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(w.ddir, "60-litevirt-fence.conf"))
	if err != nil {
		return ""
	}
	return string(b)
}

func (w *installWorld) accepting(t *testing.T, peers ...string) (bool, string) {
	t.Helper()
	return SSHDAccepting(SSHDPath(), w.cfg, w.dir)(context.Background(), peers)
}

// TestInstallScript_KeepsRootsListAndIsIdempotent: the drop-in adds the
// rendered file to the list sshd already had for root, sshd then accepts the
// fence key from every peer, and a re-run writes the same drop-in rather than
// adding the file twice.
func TestInstallScript_KeepsRootsListAndIsIdempotent(t *testing.T) {
	w := newInstallWorld(t, "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u\n")
	if ok, _ := w.accepting(t, "10.77.0.2"); ok {
		t.Fatal("accepting before the drop-in")
	}
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.2 10.77.0.3", "FENCE_SSH_SELF=10.77.0.4")
	d := w.dropIn(t)
	want := "    AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u " + filepath.Join(w.dir, "authorized_keys") + "\n"
	if !strings.Contains(d, "Match User root\n"+want) || !strings.Contains(out, "installed") {
		t.Fatalf("drop-in =\n%s\noutput:\n%s", d, out)
	}
	if ok, why := w.accepting(t, "10.77.0.2", "10.77.0.3"); !ok {
		t.Fatalf("not accepting after the drop-in: %s", why)
	}
	w.run(t, "FENCE_SSH_PEERS=10.77.0.2 10.77.0.3", "FENCE_SSH_SELF=10.77.0.4")
	if again := w.dropIn(t); again != d {
		t.Fatalf("a re-run changed the drop-in:\n%s\nto\n%s", d, again)
	}
}

// TestInstallScript_KeepsAPerAddressList: a Match Address block later in the
// main config gives root another list for 10/8. The drop-in comes first, so a
// single Match User root block would override it; per-address blocks keep it.
func TestInstallScript_KeepsAPerAddressList(t *testing.T) {
	w := newInstallWorld(t, "AuthorizedKeysFile .ssh/authorized_keys\nMatch Address 10.0.0.0/8\n    AuthorizedKeysFile /etc/ssh/ten/%u\n")
	w.run(t, "FENCE_SSH_PEERS=10.77.0.3 192.168.7.2")
	d := w.dropIn(t)
	ak := filepath.Join(w.dir, "authorized_keys")
	if !strings.Contains(d, "Match User root Address 10.77.0.3\n    AuthorizedKeysFile /etc/ssh/ten/%u "+ak) ||
		!strings.Contains(d, "Match User root Address 192.168.7.2\n    AuthorizedKeysFile .ssh/authorized_keys "+ak) {
		t.Fatalf("drop-in =\n%s", d)
	}
	if ok, why := w.accepting(t, "10.77.0.3", "192.168.7.2"); !ok {
		t.Fatalf("not accepting: %s", why)
	}
}

// TestInstallScript_RollsBackWhatSSHDRefuses: an sshd that refuses the result
// (`sshd -t` fails) gets its previous drop-in back, unchanged.
func TestInstallScript_RollsBackWhatSSHDRefuses(t *testing.T) {
	w := newInstallWorld(t, "")
	prev := "# the operator's earlier drop-in\n"
	if err := os.WriteFile(filepath.Join(w.ddir, "60-litevirt-fence.conf"), []byte(prev), 0o644); err != nil {
		t.Fatal(err)
	}
	refusing := filepath.Join(t.TempDir(), "sshd")
	if err := os.WriteFile(refusing, []byte("#!/bin/sh\nfor a; do [ \"$a\" = -t ] && { echo 'refused for the test' >&2; exit 1; }; done\nexec "+
		SSHDPath()+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3", "FENCE_SSH_SSHD="+refusing)
	if got := w.dropIn(t); got != prev || !strings.Contains(out, "rolled back") {
		t.Fatalf("drop-in after a refusal = %q (output %q), want the previous one back", got, out)
	}
	if left, _ := filepath.Glob(filepath.Join(w.ddir, ".litevirt-fence.prev.*")); len(left) != 0 {
		t.Fatalf("left behind %v", left)
	}
}

// TestInstallScript_PermitRootLoginNo: never overridden, and said.
func TestInstallScript_PermitRootLoginNo(t *testing.T) {
	w := newInstallWorld(t, "PermitRootLogin no\n")
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
	if !strings.Contains(out, "PermitRootLogin is no") || strings.Contains(w.dropIn(t), "    PermitRootLogin") {
		t.Fatalf("output %q, drop-in %q", out, w.dropIn(t))
	}
	if ok, _ := w.accepting(t, "10.77.0.3"); ok {
		t.Fatal("accepting with PermitRootLogin no")
	}
}

// TestInstallScript_Remove takes the drop-in out.
func TestInstallScript_Remove(t *testing.T) {
	w := newInstallWorld(t, "")
	w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
	if w.dropIn(t) == "" {
		t.Fatal("no drop-in")
	}
	w.run(t, "FENCE_SSH_REMOVE=1")
	if w.dropIn(t) != "" {
		t.Fatal("the drop-in is still there")
	}
}

func TestPeerAddresses(t *testing.T) {
	if got := PeerAddresses(`["10.77.0.2:7946","10.77.0.3:7946","10.77.0.2:7946"]`); got != "10.77.0.2 10.77.0.3" {
		t.Fatalf("PeerAddresses = %q", got)
	}
}

// TestInstallScript_ReRunPicksUpAChangedGlobalList: the drop-in freezes
// root's list, so after an operator edits the global AuthorizedKeysFile a
// re-run must read the new list — with its own earlier drop-in set aside, not
// the frozen list it wrote.
func TestInstallScript_ReRunPicksUpAChangedGlobalList(t *testing.T) {
	w := newInstallWorld(t, "AuthorizedKeysFile .ssh/authorized_keys\n")
	w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
	main, err := os.ReadFile(w.cfg)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(main), "AuthorizedKeysFile .ssh/authorized_keys\n", "AuthorizedKeysFile /etc/ssh/keys/%u\n", 1)
	if err := os.WriteFile(w.cfg, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
	if d := w.dropIn(t); !strings.Contains(d, "AuthorizedKeysFile /etc/ssh/keys/%u "+filepath.Join(w.dir, "authorized_keys")+"\n") {
		t.Fatalf("drop-in after the edit =\n%s", d)
	}
}

// TestInstallScript_NeverListsTheFileTwice: an operator who already added the
// rendered file to the global list by hand gets it once.
func TestInstallScript_NeverListsTheFileTwice(t *testing.T) {
	root := t.TempDir()
	ak := filepath.Join(root, "litevirt-ssh", "authorized_keys")
	w := newInstallWorld(t, "AuthorizedKeysFile .ssh/authorized_keys "+ak+"\n")
	w.dir = filepath.Dir(ak)
	w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
	if d := w.dropIn(t); strings.Count(d, ak) != 2 { // once in the header comment, once in the list
		t.Fatalf("drop-in lists %s %d times:\n%s", ak, strings.Count(d, ak)-1, d)
	}
}
