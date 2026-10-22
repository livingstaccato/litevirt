package ssh

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh/knownhosts"
)

// GlobalKnownHostsFile -- by default /etc/ssh/ssh_known_hosts, where config
// management often distributes a fleet's host keys -- is checked as ssh
// checks it, and only ever read.

// Reviewer probe (sshcfg I2): a configured GlobalKnownHostsFile records a
// different key for the host; the operator's own known_hosts has no entry.
func TestNewClient_GlobalKnownHostsFilePinEnforced(t *testing.T) {
	home, addr := configServer(t, "  GlobalKnownHostsFile %H/global_kh\n", ed25519Signer(t))
	g := filepath.Join(home, "global_kh")
	writeFile(t, g, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	before, _ := os.ReadFile(g)
	err := dialLabnode(t)
	if err == nil || !strings.Contains(err.Error(), "CHANGED") || !strings.Contains(err.Error(), g) {
		t.Fatalf("err = %v, want a CHANGED refusal naming %s", err, g)
	}
	if after, _ := os.ReadFile(g); !bytes.Equal(before, after) {
		t.Fatal("the global known_hosts file was modified")
	}
}

// With no GlobalKnownHostsFile in the config, OpenSSH's default is checked.
func TestResolveConfig_GlobalKnownHostsDefault(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	writeSSHConfig(t, home, "Host h\n  Port 2200\n")
	r, err := resolveConfig("h", "", "22", false, false, 0)
	if err != nil || r == nil {
		t.Fatalf("r=%v err=%v", r, err)
	}
	if !slices.Equal(r.GlobalKnownHosts, defaultGlobalKnownHosts) {
		t.Fatalf("GlobalKnownHosts = %v, want OpenSSH's default %v", r.GlobalKnownHosts, defaultGlobalKnownHosts)
	}

	// An ssh whose -G output has no globalknownhostsfile line: the default.
	oldG := sshG
	sshG = func(time.Duration, ...string) ([]byte, error) { return []byte("hostname h\nport 22\n"), nil }
	r, err = resolveConfig("h", "", "22", false, false, 0)
	sshG = oldG
	if err != nil || !slices.Equal(r.GlobalKnownHosts, defaultGlobalKnownHosts) {
		t.Fatalf("no globalknownhostsfile from ssh -G: r=%+v err=%v, want the default", r, err)
	}

	writeSSHConfig(t, home, "Host h\n  GlobalKnownHostsFile none\n")
	if r, err = resolveConfig("h", "", "22", false, false, 0); err != nil || len(r.GlobalKnownHosts) != 0 {
		t.Fatalf("GlobalKnownHostsFile none: r=%+v err=%v", r, err)
	}
}

// Without an ssh -G answer (no config, no ssh binary) the default global
// file is still checked, and one that cannot be parsed refuses.
func TestNewClient_GlobalKnownHostsDefaultWithoutSSHG(t *testing.T) {
	home, addr := configServer(t, "", ed25519Signer(t))
	os.Remove(filepath.Join(home, ".ssh", "config"))
	g := filepath.Join(home, "etc_ssh_known_hosts")
	old := defaultGlobalKnownHosts
	defaultGlobalKnownHosts = []string{g}
	t.Cleanup(func() { defaultGlobalKnownHosts = old })
	oldG := sshG
	sshG = func(time.Duration, ...string) ([]byte, error) { return nil, fmt.Errorf("no ssh binary") }
	t.Cleanup(func() { sshG = oldG })

	writeFile(t, g, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	c, err := NewClient("deploy@" + addr)
	if err == nil {
		c.Close()
		t.Fatal("a key differing from the one in the global known_hosts was accepted")
	}
	if !strings.Contains(err.Error(), "CHANGED") {
		t.Fatalf("err = %v, want CHANGED", err)
	}

	writeFile(t, g, "this is not a known_hosts line")
	c, err = NewClient("deploy@" + addr)
	if err == nil {
		c.Close()
		t.Fatal("an unparseable global known_hosts was ignored")
	}
	if !strings.Contains(err.Error(), g) {
		t.Fatalf("err = %v, want it to name %s", err, g)
	}
}

// A global file that exists but cannot be read refuses, like any other.
func TestNewClient_GlobalKnownHostsUnreadableFailsClosed(t *testing.T) {
	home, _ := configServer(t, "  GlobalKnownHostsFile %H/global_kh\n", ed25519Signer(t))
	g := filepath.Join(home, "global_kh")
	if err := os.Mkdir(g, 0o700); err != nil { // a directory: exists, unreadable as a file
		t.Fatal(err)
	}
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), g) {
		t.Fatalf("err = %v, want a refusal naming %s", err, g)
	}
}

// ~/.ssh/known_hosts2, which ssh also reads by default, is checked too, even
// when the config names its own UserKnownHostsFile.
func TestNewClient_KnownHosts2PinEnforced(t *testing.T) {
	home, addr := configServer(t, "  UserKnownHostsFile /dev/null\n", ed25519Signer(t))
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts2"),
		knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Fatalf("err = %v, want the known_hosts2 pin enforced", err)
	}
}

// x/crypto parses known_hosts more strictly than OpenSSH: a line ssh skips
// (an unsupported key type, say) fails the whole file. lv keeps failing
// closed on it -- in a global file too -- and names the file and line.
func TestNewClient_MalformedKnownHostsLineNamesFileAndLine(t *testing.T) {
	for _, kind := range []string{"UserKnownHostsFile", "GlobalKnownHostsFile"} {
		t.Run(kind, func(t *testing.T) {
			ed := ed25519Signer(t)
			home, addr := configServer(t, "  "+kind+" %H/kh\n", ed)
			kh := filepath.Join(home, "kh")
			writeFile(t, kh,
				knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()),
				"other.example ssh-xmss@openssh.com AAAAFHNzaC14bXNzQG9wZW5zc2guY29t")
			err := dialLabnode(t)
			if err == nil || !strings.Contains(err.Error(), kh+":2") {
				t.Fatalf("err = %v, want a refusal naming %s:2", err, kh)
			}
		})
	}
}
