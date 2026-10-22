package ssh

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// ssh_config options that make ssh refuse a host key must not be dropped:
// KnownHostsCommand (a pin source lv does not run) refuses the connection;
// RevokedHostKeys is enforced when it is a plain key list and refuses when it
// is anything lv cannot read.

func pubLine(k ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) }

// Re-review probe R1: KnownHostsCommand is never run, and never ignored.
func TestNewClient_KnownHostsCommandRefused(t *testing.T) {
	home, addr := configServer(t, "  KnownHostsCommand /bin/cat %H/khc\n", ed25519Signer(t))
	writeFile(t, filepath.Join(home, "khc"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{"other.example"}, ed25519Signer(t).PublicKey()))
	err := dialLabnode(t)
	if err == nil || !strings.Contains(err.Error(), "KnownHostsCommand") {
		t.Fatalf("err = %v, want a refusal naming KnownHostsCommand", err)
	}

	// Also with no known_hosts at all: not the first-contact path.
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), "")
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "KnownHostsCommand") {
		t.Fatalf("no known_hosts: err = %v, want a refusal naming KnownHostsCommand", err)
	}

	// KnownHostsCommand none is no command.
	configServer(t, "  KnownHostsCommand none\n", ed25519Signer(t))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("KnownHostsCommand none: %v", err)
	}
}

// Re-review probe R2, and the rest of RevokedHostKeys as a plain key list:
// a revoked plain key, a valid certificate over a revoked key, and a
// certificate signed by a revoked CA key are refused; anything else in the
// list's presence is unaffected.
func TestNewClient_RevokedHostKeysEnforced(t *testing.T) {
	t.Run("cert over a revoked host key", func(t *testing.T) {
		ca, ed := ed25519Signer(t), ed25519Signer(t)
		home, addr := configServer(t, "  RevokedHostKeys %H/revoked\n", hostCert(t, ca, ed, "127.0.0.1"), ed)
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), caLine(addr, ca.PublicKey()))
		writeFile(t, filepath.Join(home, "revoked"), "# leaked 2026-10", pubLine(ed.PublicKey()))
		if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("err = %v, want a revocation refusal", err)
		}
	})
	t.Run("cert signed by a revoked CA", func(t *testing.T) {
		ca, ed := ed25519Signer(t), ed25519Signer(t)
		home, addr := configServer(t, "  RevokedHostKeys %H/revoked\n", hostCert(t, ca, ed, "127.0.0.1"))
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), caLine(addr, ca.PublicKey()))
		writeFile(t, filepath.Join(home, "revoked"), pubLine(ca.PublicKey()))
		if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("err = %v, want a revocation refusal", err)
		}
	})
	t.Run("pinned plain key revoked", func(t *testing.T) {
		ed := ed25519Signer(t)
		home, addr := configServer(t, "  RevokedHostKeys %H/revoked\n", ed)
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
		writeFile(t, filepath.Join(home, "revoked"), pubLine(ed.PublicKey()))
		if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("err = %v, want a revocation refusal", err)
		}
	})
	t.Run("unknown host with no known_hosts, key revoked", func(t *testing.T) {
		ed := ed25519Signer(t)
		home, _ := configServer(t, "  RevokedHostKeys %H/revoked\n", ed)
		writeFile(t, filepath.Join(home, "revoked"), pubLine(ed.PublicKey()))
		if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "revoked") {
			t.Fatalf("err = %v, want a revocation refusal on first contact", err)
		}
	})
	t.Run("key not in the list is accepted", func(t *testing.T) {
		ed := ed25519Signer(t)
		home, addr := configServer(t, "  RevokedHostKeys %H/revoked\n", ed)
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
		writeFile(t, filepath.Join(home, "revoked"), pubLine(ed25519Signer(t).PublicKey()), "")
		if err := dialLabnode(t); err != nil {
			t.Fatalf("a key absent from RevokedHostKeys was refused: %v", err)
		}
	})
}

// A RevokedHostKeys lv cannot read -- a binary KRL, a line that is not a
// public key, a missing file (ssh refuses that too) -- refuses the connection.
func TestNewClient_RevokedHostKeysUnreadableRefused(t *testing.T) {
	for name, content := range map[string]string{
		"krl":     "SSHKRL\n\x00\x00\x00\x00\x01",
		"garbage": "this is not a public key",
		"missing": "",
	} {
		t.Run(name, func(t *testing.T) {
			ed := ed25519Signer(t)
			home, addr := configServer(t, "  RevokedHostKeys %H/revoked\n", ed)
			writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
			rev := filepath.Join(home, "revoked")
			if name != "missing" {
				writeFile(t, rev, content)
			}
			err := dialLabnode(t)
			if err == nil || !strings.Contains(err.Error(), "RevokedHostKeys") || !strings.Contains(err.Error(), rev) {
				t.Fatalf("err = %v, want a refusal naming RevokedHostKeys %s", err, rev)
			}
			if name == "krl" && !strings.Contains(err.Error(), "KRL") {
				t.Fatalf("err = %v, want it to say the file is a KRL", err)
			}
		})
	}
}

// Re-review probe R8 (m1): a host certificate whose CA signed it with SHA-1
// ssh-rsa is refused, as OpenSSH's default CASignatureAlgorithms refuses it.
// The same CA signing with rsa-sha2-512 is accepted.
func TestHostKeyCA_SHA1CASignatureRefused(t *testing.T) {
	rsaCA, ed := rsaSigner(t), ed25519Signer(t)
	sha1CA, err := ssh.NewSignerWithAlgorithms(rsaCA.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	addr := testServer(t, hostCert(t, sha1CA, ed, "127.0.0.1"))
	writeKnownHosts(t, caLine(addr, rsaCA.PublicKey()))
	if err := dialTest(t, addr); err == nil || !strings.Contains(err.Error(), "SHA-1") {
		t.Fatalf("err = %v, want a refusal of the SHA-1 CA signature", err)
	}

	sha2CA, err := ssh.NewSignerWithAlgorithms(rsaCA.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSASHA512})
	if err != nil {
		t.Fatal(err)
	}
	addr = testServer(t, hostCert(t, sha2CA, ed, "127.0.0.1"))
	writeKnownHosts(t, caLine(addr, rsaCA.PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("a certificate with an rsa-sha2-512 CA signature was refused: %v", err)
	}
}
