package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// countingSSHD authorises one key for user deploy, counts distinct key
// offers, and enforces MaxAuthTries like OpenSSH (default 6).
type countingSSHD struct {
	ln     net.Listener
	mu     sync.Mutex
	offers []string
}

func startCountingSSHD(t *testing.T, authorized ssh.PublicKey, maxTries int) *countingSSHD {
	t.Helper()
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	hs, _ := ssh.NewSignerFromKey(hk)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &countingSSHD{ln: ln}
	cfg := &ssh.ServerConfig{MaxAuthTries: maxTries, PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		s.mu.Lock()
		s.offers = append(s.offers, ssh.FingerprintSHA256(k))
		s.mu.Unlock()
		if authorized != nil && c.User() == "deploy" && string(k.Marshal()) == string(authorized.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(hs)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					c.Close()
					return
				}
				go ssh.DiscardRequests(reqs)
				go func() {
					for ch := range chans {
						ch.Reject(ssh.Prohibited, "no")
					}
				}()
				_ = sc
			}()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *countingSSHD) port() string { _, p, _ := net.SplitHostPort(s.ln.Addr().String()); return p }
func (s *countingSSHD) n() int       { s.mu.Lock(); defer s.mu.Unlock(); return len(s.offers) }
func (s *countingSSHD) dups() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	d := 0
	for _, o := range s.offers {
		if seen[o] {
			d++
		}
		seen[o] = true
	}
	return d
}

func edKeys(n int) []any {
	var out []any
	for i := 0; i < n; i++ {
		_, sk, _ := ed25519.GenerateKey(rand.Reader)
		out = append(out, sk)
	}
	return out
}

// Offer counts. Logged, plus hard asserts on what must hold.
func TestNewClient_OfferOrder(t *testing.T) {
	// No config, agent with 3 unrelated keys, default file authorised: 4 offers.
	t.Run("noconfig-3agent-defaultfile", func(t *testing.T) {
		_, pub := sshHome(t, "id_ed25519")
		startAgent(t, edKeys(3)...)
		srv := startCountingSSHD(t, pub, 6)
		c, err := NewClient("deploy@127.0.0.1:" + srv.port())
		t.Logf("offers=%d dups=%d err=%v", srv.n(), srv.dups(), err)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
	})
	// No config: authorised key 6th in agent + unrelated default file. Base succeeds (agent order); head must too.
	t.Run("noconfig-authorised-6th-in-agent", func(t *testing.T) {
		sshHome(t, "id_ed25519") // unrelated default file
		ks := edKeys(6)
		startAgent(t, ks...)
		pub, _ := ssh.NewPublicKey(ks[5].(ed25519.PrivateKey).Public())
		srv := startCountingSSHD(t, pub, 6)
		c, err := NewClient("deploy@127.0.0.1:" + srv.port())
		t.Logf("offers=%d dups=%d err=%v", srv.n(), srv.dups(), err)
		if err != nil {
			t.Fatalf("REGRESSION: authorised 6th agent key no longer reached: %v", err)
		}
		c.Close()
	})
	// Agent also holds the file key: offered once.
	t.Run("dedup-agent-holds-file-key", func(t *testing.T) {
		home, _ := sshHome(t, "deploy")
		data, _ := os.ReadFile(filepath.Join(home, ".ssh", "deploy"))
		k, _ := ssh.ParseRawPrivateKey(data)
		ks := append(edKeys(2), k)
		startAgent(t, ks...)
		srv := startCountingSSHD(t, nil, 50)
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentityFile "+filepath.Join(home, ".ssh", "deploy")+"\n")
		_, err := NewClient("deploy@127.0.0.1:" + srv.port())
		t.Logf("offers=%d dups=%d err=%v", srv.n(), srv.dups(), err)
		if srv.dups() != 0 || srv.n() != 3 {
			t.Fatalf("offers=%d dups=%d, want 3 distinct", srv.n(), srv.dups())
		}
	})
	// IdentitiesOnly yes, 10 agent keys, private IdentityFile: exactly 1 offer.
	t.Run("identitiesonly-10agent", func(t *testing.T) {
		home, pub := sshHome(t, "deploy")
		startAgent(t, edKeys(10)...)
		srv := startCountingSSHD(t, pub, 6)
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentitiesOnly yes\n  IdentityFile ~/.ssh/deploy\n")
		c, err := NewClient("deploy@127.0.0.1:" + srv.port())
		t.Logf("offers=%d dups=%d err=%v", srv.n(), srv.dups(), err)
		if err != nil || srv.n() != 1 {
			t.Fatalf("offers=%d err=%v, want 1 offer + success", srv.n(), err)
		}
		c.Close()
	})
	// IdentitiesOnly no, k unrelated agent keys + private IdentityFile, MaxAuthTries 6.
	for _, k := range []int{5, 6} {
		t.Run(fmt.Sprintf("identityfile-after-%d-agent-keys", k), func(t *testing.T) {
			home, pub := sshHome(t, "deploy")
			startAgent(t, edKeys(k)...)
			srv := startCountingSSHD(t, pub, 6)
			writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentityFile "+filepath.Join(home, ".ssh", "deploy")+"\n")
			c, err := NewClient("deploy@127.0.0.1:" + srv.port())
			t.Logf("k=%d offers=%d err=%v", k, srv.n(), err)
			if err != nil {
				t.Fatalf("the configured IdentityFile was not reached behind %d unrelated agent keys (MaxAuthTries 6): %v", k, err)
			}
			c.Close()
		})
	}
	// IdentityFile key ALSO in the agent, behind 6 other agent keys (IdentitiesOnly no).
	t.Run("identityfile-in-agent-behind-6", func(t *testing.T) {
		home, pub := sshHome(t, "deploy")
		data, _ := os.ReadFile(filepath.Join(home, ".ssh", "deploy"))
		k, _ := ssh.ParseRawPrivateKey(data)
		startAgent(t, append(edKeys(6), k)...)
		srv := startCountingSSHD(t, pub, 6)
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentityFile "+filepath.Join(home, ".ssh", "deploy")+"\n")
		c, err := NewClient("deploy@127.0.0.1:" + srv.port())
		if err != nil || srv.n() != 1 {
			t.Fatalf("offers=%d err=%v, want the configured key (held by the agent) offered first, once", srv.n(), err)
		}
		c.Close()
	})
}

// Dedup measured by MaxAuthTries: default id_ed25519 (A) is in the agent with
// 4 other keys; id_ecdsa (F) is authorised. Dedup: A,B,C,D,E,F = 6 → ok.
// Without dedup A is re-offered → F is the 7th → disconnect.
func TestNewClient_DedupUnderMaxAuthTries(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	data, _ := os.ReadFile(filepath.Join(home, ".ssh", "id_ed25519"))
	a, _ := ssh.ParseRawPrivateKey(data)
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(sk, "")
	os.WriteFile(filepath.Join(home, ".ssh", "id_ecdsa"), pem.EncodeToMemory(blk), 0o600)
	pub, _ := ssh.NewPublicKey(pk)
	startAgent(t, append([]any{a}, edKeys(4)...)...)
	srv := startCountingSSHD(t, pub, 6)
	c, err := NewClient("deploy@127.0.0.1:" + srv.port())
	if err != nil {
		t.Fatalf("FINDING: duplicate offer used up MaxAuthTries: %v", err)
	}
	c.Close()
}

// Reviewer probe (sshcfg I3): the configured IdentityFile's private key does
// not load -- passphrase-protected (with and without a .pub sibling: an
// OpenSSH key carries its public half in the clear), or only the .pub is on
// disk (hardware token) -- and the key is in the agent behind six unrelated
// ones, IdentitiesOnly no, MaxAuthTries 6. The agent's copy of the configured
// key must still be offered first, and the first offer must be that key.
func TestNewClient_UnloadableIdentityFileAgentCopyFirst(t *testing.T) {
	for _, variant := range []string{"encrypted+pub", "encrypted-no-pub", "pub-only"} {
		t.Run(variant, func(t *testing.T) {
			home, _ := sshHome(t, "unused")
			pk, sk, _ := ed25519.GenerateKey(rand.Reader)
			pub, _ := ssh.NewPublicKey(pk)
			key := filepath.Join(home, ".ssh", "deploy")
			if variant != "pub-only" {
				blk, err := ssh.MarshalPrivateKeyWithPassphrase(sk, "", []byte("pw"))
				if err != nil {
					t.Fatal(err)
				}
				os.WriteFile(key, pem.EncodeToMemory(blk), 0o600)
			}
			if variant != "encrypted-no-pub" {
				os.WriteFile(key+".pub", ssh.MarshalAuthorizedKey(pub), 0o644)
			}
			startAgent(t, append(edKeys(6), sk)...)
			srv := startCountingSSHD(t, pub, 6)
			writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentityFile ~/.ssh/deploy\n")
			c, err := NewClient("deploy@127.0.0.1:" + srv.port())
			if err != nil {
				t.Fatalf("configured IdentityFile (key in agent) not offered first: %d offers, %v", srv.n(), err)
			}
			c.Close()
			if srv.n() != 1 {
				t.Fatalf("%d offers, want the configured key first and alone", srv.n())
			}
		})
	}
}

// IdentityAgent is honoured (reviewer probe sshcfg M1): "none" uses no agent,
// a path uses that socket even with SSH_AUTH_SOCK unset, and SSH_AUTH_SOCK or
// unset keeps the environment's agent.
func TestNewClient_IdentityAgent(t *testing.T) {
	t.Run("none", func(t *testing.T) {
		home, _ := sshHome(t, "unused")
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(pk)
		startAgent(t, sk)
		srv := startFakeSSHD(t, pub)
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentityAgent none\n")
		if c, err := NewClient("deploy@127.0.0.1:" + srv.port()); err == nil {
			c.Close()
			t.Fatal("IdentityAgent none: the agent's key was used")
		}
	})
	t.Run("path", func(t *testing.T) {
		home, _ := sshHome(t, "unused")
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(pk)
		startAgent(t, sk)
		sock := os.Getenv("SSH_AUTH_SOCK")
		t.Setenv("SSH_AUTH_SOCK", "")
		srv := startFakeSSHD(t, pub)
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentityAgent "+sock+"\n")
		c, err := NewClient("deploy@127.0.0.1:" + srv.port())
		if err != nil {
			t.Fatalf("IdentityAgent <socket> with SSH_AUTH_SOCK unset: %v", err)
		}
		c.Close()
	})
	t.Run("SSH_AUTH_SOCK", func(t *testing.T) {
		home, _ := sshHome(t, "unused")
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(pk)
		startAgent(t, sk)
		srv := startFakeSSHD(t, pub)
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentityAgent SSH_AUTH_SOCK\n")
		c, err := NewClient("deploy@127.0.0.1:" + srv.port())
		if err != nil {
			t.Fatalf("IdentityAgent SSH_AUTH_SOCK: %v", err)
		}
		c.Close()
	})
}
