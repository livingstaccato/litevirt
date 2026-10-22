package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// fakeSSHD is an in-process server that accepts one public key and records the
// user each attempt named.
type fakeSSHD struct {
	ln    net.Listener
	hostK ssh.Signer
	mu    sync.Mutex
	users []string
}

func startFakeSSHD(t *testing.T, authorized ssh.PublicKey) *fakeSSHD {
	t.Helper()
	_, hk, _ := ed25519.GenerateKey(rand.Reader)
	hsigner, err := ssh.NewSignerFromKey(hk)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSSHD{ln: ln, hostK: hsigner}
	cfg := &ssh.ServerConfig{PublicKeyCallback: func(c ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
		s.mu.Lock()
		s.users = append(s.users, c.User())
		s.mu.Unlock()
		if c.User() == "deploy" && string(k.Marshal()) == string(authorized.Marshal()) {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(hsigner)
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

func (s *fakeSSHD) port() string {
	_, p, _ := net.SplitHostPort(s.ln.Addr().String())
	return p
}

func (s *fakeSSHD) lastUser() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.users) == 0 {
		return ""
	}
	return s.users[len(s.users)-1]
}

// sshHome makes a HOME with ~/.ssh, no agent, and writes a key at name.
func sshHome(t *testing.T, keyName string) (home string, pub ssh.PublicKey) {
	t.Helper()
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("system ssh not installed")
	}
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKey(sk, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", keyName), pem.EncodeToMemory(blk), 0o600); err != nil {
		t.Fatal(err)
	}
	pub, _ = ssh.NewPublicKey(pk)
	return home, pub
}

func writeSSHConfig(t *testing.T, home, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// The alias works in `ssh <alias>`; it must work for lv too: HostName, User,
// Port and IdentityFile all come from the config.
func TestNewClient_HonoursSSHConfigAlias(t *testing.T) {
	home, pub := sshHome(t, "lab_key")
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
  IdentityFile ~/.ssh/lab_key
`, srv.port()))

	c, err := NewClient("labnode")
	if err != nil {
		t.Fatalf("NewClient(alias) = %v; last user %q", err, srv.lastUser())
	}
	c.Close()
	if got := srv.lastUser(); got != "deploy" {
		t.Fatalf("authenticated as %q, want the config User deploy", got)
	}
}

// root@alias names the user explicitly; the config's User must not replace it,
// but HostName, Port and the key still resolve.
func TestNewClient_CommandLineUserBeatsConfig(t *testing.T) {
	home, pub := sshHome(t, "lab_key")
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
  IdentityFile ~/.ssh/lab_key
`, srv.port()))

	if _, err := NewClient("other@labnode"); err == nil {
		t.Fatal("other@labnode authenticated; the fake only admits deploy")
	}
	if got := srv.lastUser(); got != "other" {
		t.Fatalf("authenticated as %q, want the command-line user other", got)
	}
}

// An explicit port beats the config's Port.
func TestNewClient_CommandLinePortBeatsConfig(t *testing.T) {
	home, pub := sshHome(t, "lab_key")
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, `Host labnode
  HostName 127.0.0.1
  User deploy
  Port 1
  IdentityFile ~/.ssh/lab_key
`)
	c, err := NewClient("labnode:" + srv.port())
	if err != nil {
		t.Fatalf("NewClient(alias:port) = %v", err)
	}
	c.Close()
}

// Include is resolved (OpenSSH does it).
func TestNewClient_ConfigInclude(t *testing.T) {
	home, pub := sshHome(t, "lab_key")
	srv := startFakeSSHD(t, pub)
	inc := filepath.Join(home, "extra.conf")
	if err := os.WriteFile(inc, []byte(fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
  IdentityFile ~/.ssh/lab_key
`, srv.port())), 0o600); err != nil {
		t.Fatal(err)
	}
	writeSSHConfig(t, home, "Include "+inc+"\n")
	c, err := NewClient("labnode")
	if err != nil {
		t.Fatalf("NewClient via Include = %v", err)
	}
	c.Close()
}

// No config at all: unchanged behaviour (user root, default key, given host).
func TestNewClient_NoConfigKeepsDefaults(t *testing.T) {
	_, pub := sshHome(t, "id_ed25519")
	srv := startFakeSSHD(t, pub)
	if _, err := NewClient("127.0.0.1:" + srv.port()); err == nil {
		t.Fatal("authenticated as root; the fake only admits deploy")
	}
	if got := srv.lastUser(); got != "root" {
		t.Fatalf("user = %q, want the default root", got)
	}
	c, err := NewClient("deploy@127.0.0.1:" + srv.port())
	if err != nil {
		t.Fatalf("default key not used: %v", err)
	}
	c.Close()
}

// A ProxyJump the pure-Go client cannot follow is a loud refusal, not a
// silent direct dial.
func TestNewClient_ProxyJumpIsRefused(t *testing.T) {
	home, _ := sshHome(t, "lab_key")
	writeSSHConfig(t, home, `Host behind
  HostName 127.0.0.1
  ProxyJump bastion.example.com
`)
	_, err := NewClient("behind")
	if err == nil || !strings.Contains(err.Error(), "ProxyJump") {
		t.Fatalf("err = %v, want a refusal naming ProxyJump", err)
	}
}

// The config can only tighten host-key checking. StrictHostKeyChecking yes
// refuses an unknown host; StrictHostKeyChecking no must NOT accept a changed
// key.
func TestNewClient_HostKeyCheckingNeverWeaker(t *testing.T) {
	home, pub := sshHome(t, "lab_key")
	srv := startFakeSSHD(t, pub)
	base := fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
  IdentityFile ~/.ssh/lab_key
`, srv.port())

	t.Run("yes refuses an unknown host", func(t *testing.T) {
		writeSSHConfig(t, home, base+"  StrictHostKeyChecking yes\n")
		kh := filepath.Join(home, ".ssh", "known_hosts")
		other, _ := ssh.NewPublicKey(mustEd25519(t))
		line := knownhosts.Line([]string{"other.example.com"}, other)
		if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewClient("labnode"); err == nil {
			t.Fatal("unknown host accepted under StrictHostKeyChecking yes")
		}
	})

	t.Run("no does not accept a changed key", func(t *testing.T) {
		writeSSHConfig(t, home, base+"  StrictHostKeyChecking no\n")
		kh := filepath.Join(home, ".ssh", "known_hosts")
		wrong, _ := ssh.NewPublicKey(mustEd25519(t))
		line := knownhosts.Line([]string{net.JoinHostPort("127.0.0.1", srv.port())}, wrong)
		if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewClient("labnode"); err == nil {
			t.Fatal("changed host key accepted under StrictHostKeyChecking no")
		}
	})
}

func mustEd25519(t *testing.T) ed25519.PublicKey {
	t.Helper()
	p, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
