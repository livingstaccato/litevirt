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
	ok, why, err := SSHDAccepting(SSHDPath(), w.cfg, w.dir)(context.Background(), peers)
	if err != nil {
		t.Fatalf("sshd evaluation: %v", err)
	}
	return ok, why
}

// rootList is root's effective AuthorizedKeysFile for a connection from addr.
func (w *installWorld) rootList(t *testing.T, addr string) string {
	t.Helper()
	out, err := exec.Command(SSHDPath(), "-T", "-f", w.cfg, "-C", "user=root,host=,addr="+addr).Output()
	if err != nil {
		t.Fatalf("sshd -T: %v", err)
	}
	return parseSSHDT(out)["authorizedkeysfile"]
}

// rootAKC is root's effective AuthorizedKeysCommand for a connection from addr.
func (w *installWorld) rootAKC(t *testing.T, addr string) string {
	t.Helper()
	out, err := exec.Command(SSHDPath(), "-T", "-f", w.cfg, "-C", "user=root,host=,addr="+addr).Output()
	if err != nil {
		t.Fatalf("sshd -T: %v", err)
	}
	return parseSSHDT(out)["authorizedkeyscommand"]
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

// TestInstallScript_OperatorKeysStillReadFromEveryAddress: the drop-in never
// changes which files sshd reads for root, from any address — including one
// the installer was never told about, under a Match rule of the operator's
// that comes after the Included drop-in. An unscoped AuthorizedKeysFile there
// would have taken root's admin keys away from the admin network.
func TestInstallScript_OperatorKeysStillReadFromEveryAddress(t *testing.T) {
	w := newInstallWorld(t, "AuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%u\n"+
		"Match Address 192.168.50.0/24\n    AuthorizedKeysFile /etc/ssh/admin/%u\n")
	before := map[string]string{}
	for _, a := range []string{"192.168.50.5", "10.77.0.2", "172.16.0.1"} {
		before[a] = w.rootList(t, a)
	}
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.2 10.77.0.3", "FENCE_SSH_SELF=10.77.0.4")
	if !strings.Contains(out, "installed") {
		t.Fatalf("output:\n%s", out)
	}
	for a, want := range before {
		if got := w.rootList(t, a); got != want {
			t.Errorf("root's AuthorizedKeysFile from %s = %q after the drop-in, was %q", a, got, want)
		}
	}
	if got := w.rootList(t, "192.168.50.5"); got != "/etc/ssh/admin/%u" {
		t.Errorf("the admin network's list for root = %q", got)
	}
	if ok, why := w.accepting(t, "10.77.0.2", "10.77.0.3"); !ok {
		t.Fatalf("not accepting after the drop-in: %s", why)
	}
	d := w.dropIn(t)
	w.run(t, "FENCE_SSH_PEERS=10.77.0.2 10.77.0.3", "FENCE_SSH_SELF=10.77.0.4")
	if again := w.dropIn(t); again != d {
		t.Fatalf("a re-run changed the drop-in:\n%s\nto\n%s", d, again)
	}
}

// TestInstallScript_AcceptsAPeerAddedLater: a host added after the install,
// at an address the installer never saw — even one a Match rule gives root
// another list for — is accepted from, so `lv host add` cannot stop an
// existing host accepting the managed key.
func TestInstallScript_AcceptsAPeerAddedLater(t *testing.T) {
	w := newInstallWorld(t, "AuthorizedKeysFile .ssh/authorized_keys\nMatch Address 10.0.0.0/8\n    AuthorizedKeysFile /etc/ssh/ten/%u\n")
	w.run(t, "FENCE_SSH_PEERS=10.0.0.2 192.168.1.2")
	if ok, why := w.accepting(t, "10.0.0.2", "192.168.1.2", "10.0.0.9", "172.20.0.4"); !ok {
		t.Fatalf("not accepting from a peer added later: %s", why)
	}
}

// TestInstallScript_NeverOverridesTheOperatorsAuthorizedKeysCommand: sshd
// takes the first AuthorizedKeysCommand, so a drop-in would take the
// operator's own away; none is written, and the operator is told what to do.
func TestInstallScript_NeverOverridesTheOperatorsAuthorizedKeysCommand(t *testing.T) {
	w := newInstallWorld(t, "AuthorizedKeysCommand /usr/bin/true %u\nAuthorizedKeysCommandUser nobody\n")
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
	if w.dropIn(t) != "" || !strings.Contains(out, "already has an AuthorizedKeysCommand") {
		t.Fatalf("drop-in %q, output %q", w.dropIn(t), out)
	}
}

// TestInstallScript_SaysWhenSSHDCannotBeReloaded: a failed reload is loud,
// not "installed" and nothing else.
func TestInstallScript_SaysWhenSSHDCannotBeReloaded(t *testing.T) {
	w := newInstallWorld(t, "")
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3", "FENCE_SSH_RELOAD=false")
	if !strings.Contains(out, "WARNING: sshd could not be reloaded") {
		t.Fatalf("output %q", out)
	}
}

// TestInstallScript_NeverOverridesAnAuthorizedKeysCommandAnywhere: an
// operator's AuthorizedKeysCommand for root in a file Included from outside
// the drop-in directory, or spelled Keyword=value in any case, is found too,
// and nothing is written: root's LDAP or sss keys would otherwise stop working.
func TestInstallScript_NeverOverridesAnAuthorizedKeysCommandAnywhere(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"included from elsewhere", "AuthorizedKeysCommand /usr/bin/true %u"},
		{"Keyword=value, any case", "authorizedKeysCommand=/usr/bin/true %u"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ldap := filepath.Join(t.TempDir(), "ldap.conf")
			if err := os.WriteFile(ldap, []byte(tc.line+"\nAuthorizedKeysCommandUser nobody\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			w := newInstallWorld(t, "Include "+ldap+"\n")
			out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
			if w.dropIn(t) != "" || !strings.Contains(out, "already has an AuthorizedKeysCommand") {
				t.Fatalf("drop-in %q, output %q", w.dropIn(t), out)
			}
			cmd, err := exec.Command(SSHDPath(), "-T", "-f", w.cfg, "-C", "user=root,host=,addr=10.77.0.3").Output()
			if err != nil {
				t.Fatal(err)
			}
			if got := parseSSHDT(cmd)["authorizedkeyscommand"]; got != "/usr/bin/true %u" {
				t.Fatalf("root's AuthorizedKeysCommand after the install = %q, want the operator's", got)
			}
		})
	}
}

// TestInstallScript_RefusesWithoutAnAbsoluteCat: sshd runs an
// AuthorizedKeysCommand by absolute path; with no cat there the drop-in would
// have sshd exec the keys file. Nothing is written, and it says why.
func TestInstallScript_RefusesWithoutAnAbsoluteCat(t *testing.T) {
	for _, cat := range []string{"cat", "/nonexistent/cat"} {
		w := newInstallWorld(t, "")
		out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3", "FENCE_SSH_CAT="+cat)
		if w.dropIn(t) != "" || !strings.Contains(out, "no cat binary at an absolute path") {
			t.Fatalf("FENCE_SSH_CAT=%s: drop-in %q, output %q", cat, w.dropIn(t), out)
		}
	}
}

// TestInstallScript_FindsAnAuthorizedKeysCommandUnderAnyMatch: one the
// operator sets for root only from an admin network, an address the installer
// never evaluates, is found in the files sshd reads, and nothing is written.
func TestInstallScript_FindsAnAuthorizedKeysCommandUnderAnyMatch(t *testing.T) {
	for _, line := range []string{
		"AuthorizedKeysCommand /usr/bin/true %u",
		"authorizedkeyscommand=/usr/bin/true %u",
		`"AuthorizedKeysCommand" /usr/bin/true %u`,
		"=AuthorizedKeysCommand /usr/bin/true %u",
		"= AuthorizedKeysCommand /usr/bin/true %u",
		`""AuthorizedKeysCommand /usr/bin/true %u`,
		// sshd reads a carriage return as a blank, before the keyword and
		// between it and its value.
		"\rAuthorizedKeysCommand /usr/bin/true %u",
		"AuthorizedKeysCommand\r/usr/bin/true %u",
	} {
		t.Run(line, func(t *testing.T) {
			inc := filepath.Join(t.TempDir(), "admin.conf")
			if err := os.WriteFile(inc, []byte("Match Address 192.168.50.0/24\n    "+line+"\n    AuthorizedKeysCommandUser nobody\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			w := newInstallWorld(t, "Include "+inc+"\n")
			if got := w.rootAKC(t, "192.168.50.5"); got != "/usr/bin/true %u" {
				t.Fatalf("%q: sshd does not read it as root's AuthorizedKeysCommand (%q)", line, got)
			}
			out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
			if w.dropIn(t) != "" || !strings.Contains(out, "already has an AuthorizedKeysCommand") {
				t.Fatalf("%q: drop-in %q, output %q", line, w.dropIn(t), out)
			}
		})
	}
}

// TestInstallScript_ABlindScanInstallsNothing: when sshd -ddd -T does not
// name the files it reads (another debug format, a failing run), an
// AuthorizedKeysCommand in one of them cannot be ruled out, so nothing is
// installed. An Include path with a space is read whole.
func TestInstallScript_ABlindScanInstallsNothing(t *testing.T) {
	blind := filepath.Join(t.TempDir(), "sshd")
	if err := os.WriteFile(blind, []byte("#!/bin/sh\nfor a; do if [ \"$a\" = -ddd ]; then \""+SSHDPath()+
		"\" \"$@\" 2>&1 | grep -v load_server_config; exit 0; fi; done\nexec \""+SSHDPath()+"\" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	w := newInstallWorld(t, "")
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3", "FENCE_SSH_SSHD="+blind)
	if w.dropIn(t) != "" || !strings.Contains(out, "could not list the files sshd reads") {
		t.Fatalf("drop-in %q, output %q", w.dropIn(t), out)
	}

	spaced := filepath.Join(t.TempDir(), "with space")
	if err := os.MkdirAll(spaced, 0o755); err != nil {
		t.Fatal(err)
	}
	inc := filepath.Join(spaced, "admin.conf")
	if err := os.WriteFile(inc, []byte("Match Address 192.168.50.0/24\n    AuthorizedKeysCommand /usr/bin/true %u\n    AuthorizedKeysCommandUser nobody\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	w = newInstallWorld(t, "Include \""+inc+"\"\n")
	if out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3"); w.dropIn(t) != "" || !strings.Contains(out, "already has an AuthorizedKeysCommand") ||
		!strings.Contains(out, inc) || !strings.Contains(out, "/usr/bin/true") {
		t.Fatalf("an Include path with a space: drop-in %q, output %q", w.dropIn(t), out)
	}
}
