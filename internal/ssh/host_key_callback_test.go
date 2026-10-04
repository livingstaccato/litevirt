package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func testHostKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("ssh public key: %v", err)
	}
	return k
}

// TestDefaultHostKeyCallback_AppliesTheVerdict pins hostKeyVerdict at its call
// site. TestHostKeyVerdict proves the decision on hand-built KeyErrors; this
// drives the callback NewClient actually installs, over a real known_hosts
// file, so it notices if that callback stops consulting the verdict and hands
// back knownhosts' raw answer (which refuses first contact) or ignores it
// (which waves a changed key through).
func TestDefaultHostKeyCallback_AppliesTheVerdict(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatalf("mkdir .ssh: %v", err)
	}

	known := testHostKey(t)
	const knownHost = "10.0.0.5:22"
	line := knownhosts.Line([]string{knownHost}, known) + "\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(line), 0o600); err != nil {
		t.Fatalf("write known_hosts: %v", err)
	}

	cb, err := defaultHostKeyCallback()
	if err != nil {
		t.Fatalf("defaultHostKeyCallback: %v", err)
	}
	remote := &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 22}

	t.Run("known and matching is accepted", func(t *testing.T) {
		if err := cb(knownHost, remote, known); err != nil {
			t.Fatalf("the recorded key was refused: %v", err)
		}
	})

	t.Run("unknown host is accepted on first contact", func(t *testing.T) {
		other := &net.TCPAddr{IP: net.ParseIP("10.0.0.6"), Port: 22}
		if err := cb("10.0.0.6:22", other, testHostKey(t)); err != nil {
			t.Fatalf("first contact with a new host was refused, so `lv host add` cannot "+
				"provision any machine not already in known_hosts: %v", err)
		}
	})

	t.Run("changed key is REFUSED", func(t *testing.T) {
		if err := cb(knownHost, remote, testHostKey(t)); err == nil {
			t.Fatal("a CHANGED host key was accepted by the callback NewClient installs; " +
				"this connection carries the cluster CA-signed host key")
		}
	})
}
