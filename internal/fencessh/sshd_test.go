package fencessh

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// sshdConfig writes an sshd_config of body, with a host key so `sshd -T`
// can load it unprivileged.
func sshdConfig(t *testing.T, body string) string {
	t.Helper()
	if _, err := os.Stat(SSHDPath()); err != nil {
		if os.Getenv("LITEVIRT_REQUIRE_SSHD") == "1" {
			t.Fatalf("LITEVIRT_REQUIRE_SSHD=1: no sshd at %s", SSHDPath())
		}
		t.Skipf("no sshd at %s: evaluating sshd configuration needs OpenSSH's server (set LITEVIRT_REQUIRE_SSHD=1 to fail instead)", SSHDPath())
	}
	dir := t.TempDir()
	hk := filepath.Join(dir, "hk")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", hk).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	cfg := filepath.Join(dir, "sshd_config")
	if err := os.WriteFile(cfg, []byte("HostKey "+hk+"\nPidFile none\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// TestSSHDAccepting_EvaluatesEachPeerAddress: an earlier Match Address block
// that gives root its own AuthorizedKeysFile wins for that address (sshd takes
// the first obtained value), so the rendered file is not read for a fence from
// there. Evaluated at 127.0.0.1 alone, it would read as accepting.
func TestSSHDAccepting_EvaluatesEachPeerAddress(t *testing.T) {
	dir := "/etc/litevirt/ssh"
	cfg := sshdConfig(t, `Match User root Address 10.0.0.0/8
    AuthorizedKeysFile .ssh/authorized_keys
Match User root
    AuthorizedKeysFile .ssh/authorized_keys /etc/litevirt/ssh/authorized_keys
Match all
`)
	acc := SSHDAccepting(SSHDPath(), cfg, dir)
	if ok, why, err := acc(context.Background(), []string{"192.168.7.2", "127.0.0.1"}); !ok || err != nil {
		t.Fatalf("peers outside 10/8: not accepting (%s)", why)
	}
	ok, why, err := acc(context.Background(), []string{"192.168.7.2", "10.77.0.3"})
	if ok || err != nil || !strings.Contains(why, "10.77.0.3") {
		t.Fatalf("a peer in 10/8 = %v %q, want not accepting, naming 10.77.0.3", ok, why)
	}
}

// TestSSHDAccepting_PermitRootLoginNoIsNotOverridden: litevirt never
// overrides PermitRootLogin no; the host reports not accepting and why.
func TestSSHDAccepting_PermitRootLoginNoIsNotOverridden(t *testing.T) {
	cfg := sshdConfig(t, "PermitRootLogin no\nAuthorizedKeysFile .ssh/authorized_keys /etc/litevirt/ssh/authorized_keys\n")
	ok, why, err := SSHDAccepting(SSHDPath(), cfg, "/etc/litevirt/ssh")(context.Background(), []string{"10.77.0.3"})
	if ok || err != nil || !strings.Contains(why, "PermitRootLogin no") {
		t.Fatalf("= %v %q, want not accepting for PermitRootLogin no", ok, why)
	}
}

// TestSSHDAccepting_AFailedEvaluationIsNoAnswer: an sshd -T that cannot run
// is an error, never "not accepting".
func TestSSHDAccepting_AFailedEvaluationIsNoAnswer(t *testing.T) {
	cfg := sshdConfig(t, "")
	ok, why, err := SSHDAccepting(SSHDPath(), cfg+".missing", "/etc/litevirt/ssh")(context.Background(), []string{"10.77.0.3"})
	if ok || why != "" || err == nil {
		t.Fatalf("= %v %q %v, want an evaluation error", ok, why, err)
	}
}

// TestAuthorizedKeys_RenderedFromTheParsedKeyAndTheCertificateAddress:
// every line is restricted, accepted only from the peer's certificate
// address, runs only the forced command, and is re-rendered from the parsed
// key.
func TestAuthorizedKeys_RenderedFromTheParsedKeyAndTheCertificateAddress(t *testing.T) {
	ca := newTestCA(t)
	certPEM, signer := ca.host("node-2", []byte{10, 77, 0, 2})
	v, err := Verify(signedRow(t, "node-2", certPEM, signer), ca.trust())
	if err != nil {
		t.Fatal(err)
	}
	ak := string(AuthorizedKeys("/etc/litevirt/ssh", []*Verified{v}))
	want := `restrict,from="10.77.0.2",command="/etc/litevirt/ssh/fence-command" ` + KeyLine(v.FenceKeys[0]) +
		" litevirt-fence:" + HexName("node-2") + ":g1\n"
	if !strings.HasSuffix(ak, want) || strings.Count(ak, "\n") != 2 {
		t.Fatalf("authorized_keys =\n%s\nwant it to end with\n%s", ak, want)
	}
	kh := string(KnownHosts([]*Verified{v}))
	if !strings.Contains(kh, Alias("node-2")+" "+KeyLine(v.HostKeys[0])+"\n") {
		t.Fatalf("known_hosts =\n%s", kh)
	}
}

// TestForcedCommand_ArmsOnlyForItsOwnName runs the forced command under sh
// with a fake systemctl: a poweroff naming the host arms; one naming another
// host, a check, a shell command and an empty request do not.
func TestForcedCommand_ArmsOnlyForItsOwnName(t *testing.T) {
	dir := t.TempDir()
	cmd := filepath.Join(dir, CommandName)
	if err := os.WriteFile(cmd, ForcedCommand("node-x"), 0o755); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(dir, "state")
	bin := filepath.Join(dir, "bin")
	os.MkdirAll(bin, 0o755)
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte("#!/bin/sh\necho \"$*\" >> "+state+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(req string) (string, int) {
		c := exec.Command("/bin/sh", "-c", cmd)
		c.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "SSH_ORIGINAL_COMMAND=" + req, "SSH_CLIENT=10.77.0.2 5555 22"}
		out, err := c.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return string(out), code
	}
	for _, req := range []string{PoweroffRequest("node-y"), "id", "", CheckRequest("node-y"), PoweroffRequest("node-x") + "; id"} {
		out, code := run(req)
		if code != 3 || strings.Contains(out, "litevirt-fence-armed") {
			t.Fatalf("request %q: exit %d %q, want refused (3) and unarmed", req, code, out)
		}
	}
	if out, code := run(CheckRequest("node-x")); code != 0 || strings.TrimSpace(out) != CheckOK {
		t.Fatalf("check: exit %d %q", code, out)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("a refused request or a check powered the host off")
	}
	if out, code := run(PoweroffRequest("node-x")); code != 0 || !strings.Contains(out, "litevirt-fence-armed") {
		t.Fatalf("poweroff: exit %d %q", code, out)
	}
	if raw, _ := os.ReadFile(state); !strings.Contains(string(raw), "poweroff --force --force") {
		t.Fatalf("poweroff did not run: %q", raw)
	}
}
