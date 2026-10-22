package ssh

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// testServer is a real sshd-side handshake on loopback, offering every host key
// it is given, the way OpenSSH offers ed25519 AND ecdsa (AND rsa) at once.
func testServer(t *testing.T, hostKeys ...ssh.Signer) string {
	t.Helper()
	cfg := &ssh.ServerConfig{NoClientAuth: true}
	for _, k := range hostKeys {
		cfg.AddHostKey(k)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for ch := range chans {
					_ = ch.Reject(ssh.Prohibited, "test server")
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func ed25519Signer(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ecdsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func writeKnownHosts(t *testing.T, lines ...string) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	data := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// dialTest dials addr with exactly the ClientConfig NewClient builds.
func dialTest(t *testing.T, addr string) error {
	t.Helper()
	host, _, _ := net.SplitHostPort(addr)
	cfg := clientConfig("root", nil, host, addr)
	cfg.Timeout = 10 * time.Second
	c, err := ssh.Dial("tcp", addr, cfg)
	if err == nil {
		c.Close()
	}
	return err
}

// TestHostKeyAlgorithms_PresentedKeyMatchesKnownHosts is the lab reproduction
// (2026-10-22, labs 4 and 5): OpenSSH with accept-new recorded the node's
// ED25519 key, the node offers ED25519 AND ECDSA, and x/crypto's default
// host-key preference puts ECDSA first. Without asking for the recorded type,
// the server presents its ECDSA key, knownhosts finds an entry for the host
// with a different key, and the verdict reads that as CHANGED -- on a node
// whose key never changed.
func TestHostKeyAlgorithms_PresentedKeyMatchesKnownHosts(t *testing.T) {
	ed, ec := ed25519Signer(t), ecdsaSigner(t)
	addr := testServer(t, ec, ed)

	t.Run("recorded ed25519, server also offers ecdsa: accepted", func(t *testing.T) {
		writeKnownHosts(t, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
		if err := dialTest(t, addr); err != nil {
			t.Fatalf("a valid known_hosts entry for the host's real ed25519 key was refused: %v", err)
		}
	})

	t.Run("recorded ed25519 under a hashed hostname: accepted", func(t *testing.T) {
		writeKnownHosts(t, knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(addr))}, ed.PublicKey()))
		if err := dialTest(t, addr); err != nil {
			t.Fatalf("a hashed known_hosts entry for the host's real key was refused: %v", err)
		}
	})

	t.Run("recorded ecdsa only: accepted", func(t *testing.T) {
		writeKnownHosts(t, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ec.PublicKey()))
		if err := dialTest(t, addr); err != nil {
			t.Fatalf("a valid ecdsa known_hosts entry was refused: %v", err)
		}
	})

	t.Run("unknown host: accepted on first contact", func(t *testing.T) {
		writeKnownHosts(t, knownhosts.Line([]string{"10.9.9.9"}, ed25519Signer(t).PublicKey()))
		if err := dialTest(t, addr); err != nil {
			t.Fatalf("first contact was refused: %v", err)
		}
	})

	t.Run("recorded ed25519 is a DIFFERENT key: refused", func(t *testing.T) {
		writeKnownHosts(t, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
		err := dialTest(t, addr)
		if err == nil || !strings.Contains(err.Error(), "CHANGED") {
			t.Fatalf("a genuinely changed ed25519 key was not refused as CHANGED: %v", err)
		}
	})

	t.Run("recorded ed25519 AND ecdsa, both DIFFERENT: refused", func(t *testing.T) {
		writeKnownHosts(t,
			knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()),
			knownhosts.Line([]string{knownhosts.Normalize(addr)}, ecdsaSigner(t).PublicKey()))
		if err := dialTest(t, addr); err == nil {
			t.Fatal("a host whose every recorded key changed was accepted")
		}
	})
}

// TestHostKeyAlgorithms_NoTypeDowngrade pins that asking for the recorded type
// is not an opening: a server that cannot present a key of a recorded type
// (an impostor holding only some other key) is refused, never treated as an
// unknown host.
//
// This pins the NARROWING layer: the impostor fails at negotiation, before the
// verdict runs. The verdict layer (a key of an unrecorded type is refused, not
// taken as first contact) is pinned separately by
// TestHostKeyVerdict_DifferentTypeSaysSo; neither makes the other redundant.
func TestHostKeyAlgorithms_NoTypeDowngrade(t *testing.T) {
	ed := ed25519Signer(t)
	addr := testServer(t, ecdsaSigner(t)) // impostor: ecdsa only
	writeKnownHosts(t, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("a server presenting only a key type the host never recorded was accepted")
	}
}

// TestHostKeyVerdict_DifferentTypeSaysSo: when the presented key's type is not
// among the recorded ones the refusal stands, but it says what happened rather
// than claiming the recorded key changed.
func TestHostKeyVerdict_DifferentTypeSaysSo(t *testing.T) {
	want := []knownhosts.KnownKey{{Key: ed25519Signer(t).PublicKey(), Filename: "known_hosts", Line: 3}}
	err := hostKeyVerdictFor("node-1", ecdsaSigner(t).PublicKey(), &knownhosts.KeyError{Want: want})
	if err == nil {
		t.Fatal("a key of an unrecorded type was accepted")
	}
	if !strings.Contains(err.Error(), "ssh-ed25519") || !strings.Contains(err.Error(), "ecdsa-sha2-nistp256") {
		t.Fatalf("refusal does not name the recorded and presented types: %v", err)
	}
}

func TestKnownHostKeyAlgorithms(t *testing.T) {
	ed, ec := ed25519Signer(t), ecdsaSigner(t)
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	writeKnownHosts(t,
		knownhosts.Line([]string{"10.0.0.5"}, ec.PublicKey()),
		knownhosts.Line([]string{"10.0.0.5"}, ed.PublicKey()),
		knownhosts.Line([]string{"[10.0.0.6]:2222"}, ec.PublicKey()),
		knownhosts.Line([]string{"10.0.0.7"}, rs.PublicKey()))
	raw, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	got := knownHostKeyAlgorithms(raw, "10.0.0.5:22")
	if strings.Join(got, ",") != "ssh-ed25519,ecdsa-sha2-nistp256" {
		t.Fatalf("10.0.0.5:22 algorithms = %v", got)
	}
	if got := knownHostKeyAlgorithms(raw, "10.0.0.6:2222"); strings.Join(got, ",") != "ecdsa-sha2-nistp256" {
		t.Fatalf("[10.0.0.6]:2222 algorithms = %v", got)
	}
	// ssh-rsa is asked for with SHA-2 signatures only, never SHA-1.
	if got := knownHostKeyAlgorithms(raw, "10.0.0.7:22"); strings.Join(got, ",") != "rsa-sha2-512,rsa-sha2-256" {
		t.Fatalf("10.0.0.7:22 algorithms = %v", got)
	}
	// Unknown: every plain type, SHA-2 only, no certificates.
	if got := strings.Join(knownHostKeyAlgorithms(raw, "10.0.0.6:22"), ","); got !=
		"ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-512,rsa-sha2-256" {
		t.Fatalf("10.0.0.6:22 is unknown, want the first-contact list, got %v", got)
	}
}

// TestAuthMethods_NamesTheKeyFilesItLookedFor: with no agent and no key file,
// the error must say which files were looked for. It used to list only the
// agent line, which read as "litevirt takes keys from an agent only" (lab 5,
// 2026-10-22) although ~/.ssh/id_ed25519, id_ecdsa and id_rsa are all tried.
func TestAuthMethods_NamesTheKeyFilesItLookedFor(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	t.Setenv("HOME", t.TempDir())
	_, err := authMethods()
	if err == nil {
		t.Fatal("expected an error with no agent and no key files")
	}
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		if !strings.Contains(err.Error(), name) {
			t.Errorf("error does not name %s: %v", name, err)
		}
	}
}
