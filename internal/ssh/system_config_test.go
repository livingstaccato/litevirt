package ssh

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"
)

// /etc/ssh/ssh_config is read after ~/.ssh/config, as ssh reads it: a fleet's
// RevokedHostKeys, KnownHostsCommand or GlobalKnownHostsFile usually lives
// there, and must be enforced (or refused) exactly as if the operator had set
// it. Tests point systemSSHConfig at a file of their own (TestMain).

func writeSystemSSHConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "ssh_config")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	old := systemSSHConfig
	systemSSHConfig = p
	t.Cleanup(func() { systemSSHConfig = old })
	return p
}

func TestNewClient_SystemConfigKnownHostsCommandRefused(t *testing.T) {
	configServer(t, "", ed25519Signer(t))
	writeSystemSSHConfig(t, "Host *\n  KnownHostsCommand /bin/true\n")
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "KnownHostsCommand") {
		t.Fatalf("err = %v, want a refusal naming KnownHostsCommand from the system config", err)
	}
}

func TestNewClient_SystemConfigRevokedHostKeysEnforced(t *testing.T) {
	ed := ed25519Signer(t)
	home, addr := configServer(t, "", ed)
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	rev := filepath.Join(home, "fleet_revoked")
	writeFile(t, rev, pubLine(ed.PublicKey()))
	writeSystemSSHConfig(t, "Host *\n  RevokedHostKeys "+rev+"\n")
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("err = %v, want the system config's RevokedHostKeys enforced", err)
	}
}

func TestNewClient_SystemConfigGlobalKnownHostsEnforced(t *testing.T) {
	home, addr := configServer(t, "", ed25519Signer(t))
	g := filepath.Join(home, "fleet_kh")
	writeFile(t, g, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	writeSystemSSHConfig(t, "Host *\n  GlobalKnownHostsFile "+g+"\n")
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Fatalf("err = %v, want the system config's GlobalKnownHostsFile pin enforced", err)
	}
}

// The system config applies with no ~/.ssh/config at all, and the user's
// config beats it (ssh keeps the first value obtained).
func TestResolveConfig_SystemConfigOrder(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	writeSystemSSHConfig(t, "Host h\n  Port 2201\n  User sysuser\n")
	r, err := resolveConfig("h", "", "22", false, false, 0)
	if err != nil || r == nil || r.Port != "2201" || r.User != "sysuser" {
		t.Fatalf("no user config: r=%+v err=%v, want the system config's Port and User", r, err)
	}
	writeSSHConfig(t, home, "Host h\n  Port 2202\n")
	if r, err = resolveConfig("h", "", "22", false, false, 0); err != nil || r.Port != "2202" || r.User != "sysuser" {
		t.Fatalf("user config: r=%+v err=%v, want the user's Port over the system's, the system's User", r, err)
	}
}

// With only a system config present, an ssh -G failure refuses rather than
// dropping what it pins.
func TestNewClient_SystemConfigSSHGFailureFailsClosed(t *testing.T) {
	configServer(t, "", ed25519Signer(t))
	os.Remove(filepath.Join(os.Getenv("HOME"), ".ssh", "config"))
	sys := writeSystemSSHConfig(t, "Host *\n  RevokedHostKeys /nonexistent\n")
	old := sshG
	sshG = func(time.Duration, ...string) ([]byte, error) { return nil, fmt.Errorf("simulated failure") }
	t.Cleanup(func() { sshG = old })
	c, err := NewClient("deploy@127.0.0.1:1")
	if err == nil {
		c.Close()
		t.Fatal("ssh -G failure with a system config present fell back to the defaults")
	}
	if !strings.Contains(err.Error(), "ssh -G") || !strings.Contains(err.Error(), sys) {
		t.Fatalf("err = %v, want a refusal naming ssh -G and %s", err, sys)
	}
}
