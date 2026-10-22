package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
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
	home, pub := sshHome(t, "id_ed25519")
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
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

// A configured IdentityFile is used (no default key exists here), with %d and
// %h expanded.
func TestNewClient_ConfigIdentityFile(t *testing.T) {
	home, pub := sshHome(t, "k_127.0.0.1")
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
  IdentityFile %%d/.ssh/k_%%h
`, srv.port()))
	c, err := NewClient("labnode")
	if err != nil {
		t.Fatalf("NewClient = %v", err)
	}
	c.Close()
}

// root@alias names the user explicitly; the config's User must not replace it,
// but HostName, Port and the key still resolve.
func TestNewClient_CommandLineUserBeatsConfig(t *testing.T) {
	home, pub := sshHome(t, "id_ed25519")
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
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
	home, pub := sshHome(t, "id_ed25519")
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, `Host labnode
  HostName 127.0.0.1
  User deploy
  Port 1
`)
	c, err := NewClient("labnode:" + srv.port())
	if err != nil {
		t.Fatalf("NewClient(alias:port) = %v", err)
	}
	c.Close()
}

// Include is resolved (OpenSSH does it).
func TestNewClient_ConfigInclude(t *testing.T) {
	home, pub := sshHome(t, "id_ed25519")
	srv := startFakeSSHD(t, pub)
	inc := filepath.Join(home, "extra.conf")
	if err := os.WriteFile(inc, []byte(fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
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

// ProxyJump and ProxyCommand are unsupported but not refused: lv dials the
// address directly, as it always did, and says so.
func TestNewClient_ProxyDirectivesWarnAndDialDirectly(t *testing.T) {
	for _, directive := range []string{"ProxyJump bastion.example.com", "ProxyCommand false"} {
		t.Run(strings.Fields(directive)[0], func(t *testing.T) {
			home, pub := sshHome(t, "id_ed25519")
			srv := startFakeSSHD(t, pub)
			var warned []string
			old := warnf
			warnf = func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) }
			t.Cleanup(func() { warnf = old })
			writeSSHConfig(t, home, fmt.Sprintf(`Host behind
  HostName 127.0.0.1
  User deploy
  Port %s
  %s
`, srv.port(), directive))
			c, err := NewClient("behind")
			if err != nil {
				t.Fatalf("NewClient = %v, want a direct dial", err)
			}
			c.Close()
			if len(warned) == 0 || !strings.Contains(strings.Join(warned, "\n"), strings.Fields(directive)[0]) {
				t.Fatalf("warnings %v, want one naming %s", warned, strings.Fields(directive)[0])
			}
		})
	}
}

// The config can only tighten host-key checking. StrictHostKeyChecking yes
// refuses an unknown host; StrictHostKeyChecking no must NOT accept a changed
// key.
func TestNewClient_HostKeyCheckingNeverWeaker(t *testing.T) {
	home, pub := sshHome(t, "id_ed25519")
	srv := startFakeSSHD(t, pub)
	base := fmt.Sprintf(`Host labnode
  HostName 127.0.0.1
  User deploy
  Port %s
`, srv.port())

	t.Run("yes refuses an unknown host", func(t *testing.T) {
		writeSSHConfig(t, home, base+"  StrictHostKeyChecking yes\n")
		kh := filepath.Join(home, ".ssh", "known_hosts")
		other, _ := ssh.NewPublicKey(mustEd25519(t))
		line := knownhosts.Line([]string{"other.example.com"}, other)
		if err := os.WriteFile(kh, []byte(line+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewClient("labnode"); err == nil || !strings.Contains(err.Error(), "StrictHostKeyChecking") {
			t.Fatalf("err = %v, want an unknown-host refusal naming StrictHostKeyChecking", err)
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
		if _, err := NewClient("labnode"); err == nil || !strings.Contains(err.Error(), "CHANGED") {
			t.Fatalf("err = %v, want a CHANGED host key refusal", err)
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

// An unusable known_hosts input fails closed, naming the file: it must never
// fall to the accept-any-key path, or a config could switch off the check for
// a changed key.
func TestNewClient_UnusableKnownHostsFailsClosed(t *testing.T) {
	for _, mode := range []string{"extra-garbage", "extra-dir", "default-garbage"} {
		t.Run(mode, func(t *testing.T) {
			home, pub := sshHome(t, "id_ed25519")
			srv := startFakeSSHD(t, pub)
			bad := filepath.Join(home, "bad_kh")
			cfg := fmt.Sprintf("Host labnode\n  HostName 127.0.0.1\n  User deploy\n  Port %s\n", srv.port())
			wrong, _ := ssh.NewPublicKey(mustEd25519(t))
			line := knownhosts.Line([]string{net.JoinHostPort("127.0.0.1", srv.port())}, wrong) + "\n"
			def := filepath.Join(home, ".ssh", "known_hosts")
			switch mode {
			case "extra-garbage":
				os.WriteFile(bad, []byte("this is not a known_hosts line\n"), 0o600)
				cfg += "  UserKnownHostsFile " + bad + "\n"
				os.WriteFile(def, []byte(line), 0o600)
			case "extra-dir":
				os.Mkdir(bad, 0o700)
				cfg += "  UserKnownHostsFile " + bad + "\n"
				os.WriteFile(def, []byte(line), 0o600)
			case "default-garbage":
				bad = def
				os.WriteFile(def, []byte("this is not a known_hosts line\n"), 0o600)
			}
			writeSSHConfig(t, home, cfg)
			c, err := NewClient("labnode")
			if err == nil {
				c.Close()
				t.Fatal("connection accepted with an unusable known_hosts input")
			}
			if !strings.Contains(err.Error(), bad) {
				t.Fatalf("err = %v, want it to name %s", err, bad)
			}
		})
	}
}

// ssh -G is bounded even when a Match exec grandchild holds its pipes open,
// and the NewClientDeadline bound covers the config lookup.
func TestResolveConfig_TimeoutBoundsMatchExec(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	writeSSHConfig(t, home, "Match exec \"sleep 25\"\n  User x\n")
	start := time.Now()
	r, err := resolveConfig("labnode", "", "22", false, false, time.Second)
	if el := time.Since(start); el > 6*time.Second {
		t.Fatalf("resolveConfig took %v against a 1s bound", el)
	}
	if err == nil || r != nil || !strings.Contains(err.Error(), "ssh -G") {
		t.Fatalf("r=%v err=%v, want a refusal naming ssh -G (the config could not be read)", r, err)
	}
	start = time.Now()
	_, _ = NewClientDeadline("labnode", time.Second)
	if el := time.Since(start); el > 6*time.Second {
		t.Fatalf("NewClientDeadline took %v against a 1s bound", el)
	}
}

// A config User equal to the local login is still a configured User.
func TestResolveConfig_UserEqualToLocalLogin(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	cur, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	writeSSHConfig(t, home, "Host same\n  User "+cur.Username+"\nHost none\n  Port 2200\n")
	r, err := resolveConfig("same", "", "22", false, false, 0)
	if err != nil || r == nil || r.User != cur.Username {
		t.Fatalf("r=%+v err=%v, want User %s", r, err, cur.Username)
	}
	r, err = resolveConfig("none", "", "22", false, false, 0)
	if err != nil || r == nil || r.User != "" || r.Port != "2200" {
		t.Fatalf("r=%+v err=%v, want User unset and port 2200", r, err)
	}
}

func TestResolveConfig_IdentityTokensAndIdentitiesOnly(t *testing.T) {
	home, _ := sshHome(t, "unused_key")
	var warned []string
	old := warnf
	warnf = func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { warnf = old })
	writeSSHConfig(t, home, "Host h\n  HostName real.example\n  IdentitiesOnly yes\n  IdentityFile %d/.ssh/k_%h\n  IdentityFile ~/.ssh/odd_%L\n")
	r, err := resolveConfig("h", "", "22", false, false, 0)
	if err != nil || r == nil {
		t.Fatalf("r=%v err=%v", r, err)
	}
	want := filepath.Join(home, ".ssh", "k_real.example")
	if len(r.IdentityFiles) != 1 || r.IdentityFiles[0] != want {
		t.Fatalf("IdentityFiles = %v, want [%s]", r.IdentityFiles, want)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "odd_%L") {
		t.Fatalf("warnings %v, want one naming the unexpanded IdentityFile", warned)
	}
	if !r.IdentitiesOnly {
		t.Fatal("IdentitiesOnly not read")
	}
}

func TestResolveHostName(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	writeSSHConfig(t, home, "Host labnode\n  HostName 10.1.2.3\n")
	for target, want := range map[string]string{
		"labnode": "10.1.2.3", "root@labnode": "10.1.2.3", "labnode:2222": "10.1.2.3",
		"other": "other", "10.9.9.9": "10.9.9.9",
	} {
		if got, err := ResolveHostName(target); err != nil || got != want {
			t.Errorf("ResolveHostName(%q) = %q, %v; want %q", target, got, err, want)
		}
	}
}

// When ssh -G fails and a config exists, what the config pins must not be
// silently dropped: refuse, naming ssh -G. With no config the defaults hold.
func TestNewClient_SSHGFailureFailsClosed(t *testing.T) {
	home, pub := sshHome(t, "id_ed25519")
	srv := startFakeSSHD(t, pub)
	pin := filepath.Join(home, "pinned_kh")
	wrong, _ := ssh.NewPublicKey(mustEd25519(t))
	os.WriteFile(pin, []byte(knownhosts.Line([]string{net.JoinHostPort("127.0.0.1", srv.port())}, wrong)+"\n"), 0o600)
	old := sshG
	sshG = func(time.Duration, ...string) ([]byte, error) { return nil, fmt.Errorf("simulated failure") }
	t.Cleanup(func() { sshG = old })
	target := "deploy@127.0.0.1:" + srv.port()

	writeSSHConfig(t, home, "Host 127.0.0.1\n  UserKnownHostsFile "+pin+"\n  StrictHostKeyChecking yes\n")
	if c, err := NewClient(target); err == nil || !strings.Contains(err.Error(), "ssh -G") {
		if c != nil {
			c.Close()
		}
		t.Fatalf("err = %v, want a refusal naming ssh -G", err)
	}

	os.Remove(filepath.Join(home, ".ssh", "config"))
	c, err := NewClient(target)
	if err != nil {
		t.Fatalf("with no config the defaults must hold: %v", err)
	}
	c.Close()
}

// ssh -G time comes out of the NewClientDeadline bound.
func TestNewClientDeadline_CountsConfigLookup(t *testing.T) {
	sshHome(t, "id_ed25519")
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() { // accept, never speak
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	old := sshG
	sshG = func(time.Duration, ...string) ([]byte, error) {
		time.Sleep(800 * time.Millisecond)
		return []byte("hostname 127.0.0.1\nport " + port + "\nuser __lv_unset__\n"), nil
	}
	t.Cleanup(func() { sshG = old })
	start := time.Now()
	_, err := NewClientDeadline("silent", time.Second)
	if el := time.Since(start); err == nil || el > 1400*time.Millisecond {
		t.Fatalf("NewClientDeadline(1s) took %v, err %v: ssh -G time not counted against the bound", el, err)
	}
}

// The default known_hosts is the one under $HOME, never the passwd home's.
func TestResolveConfig_DefaultKnownHostsIsHOME(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	writeSSHConfig(t, home, "Host h\n  Port 2200\n")
	r, err := resolveConfig("h", "", "22", false, false, 0)
	if err != nil || r == nil {
		t.Fatalf("r=%v err=%v", r, err)
	}
	if len(r.KnownHosts) != 0 {
		t.Fatalf("KnownHosts = %v, want none: the real user's known_hosts leaked in", r.KnownHosts)
	}
}

// startAgent serves keys over a unix socket and exports it as SSH_AUTH_SOCK.
func startAgent(t *testing.T, keys ...any) {
	t.Helper()
	kr := agent.NewKeyring()
	for _, k := range keys {
		if err := kr.Add(agent.AddedKey{PrivateKey: k}); err != nil {
			t.Fatal(err)
		}
	}
	sock := filepath.Join(os.Getenv("TMPDIR"), fmt.Sprintf("ag%d.sock", time.Now().UnixNano()%1000000))
	al, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })
	go func() {
		for {
			c, err := al.Accept()
			if err != nil {
				return
			}
			go agent.ServeAgent(kr, c)
		}
	}()
	t.Setenv("SSH_AUTH_SOCK", sock)
}

// IdentitiesOnly filters the agent to the configured identities; it does not
// drop the agent. Both setups work without the config and must with it.
func TestNewClient_IdentitiesOnlyKeepsTheAgent(t *testing.T) {
	t.Run("pub identity file, private key only in agent", func(t *testing.T) {
		home, _ := sshHome(t, "unused")
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(pk)
		os.WriteFile(filepath.Join(home, ".ssh", "agentkey.pub"), ssh.MarshalAuthorizedKey(pub), 0o644)
		startAgent(t, sk)
		srv := startFakeSSHD(t, pub)
		target := "deploy@127.0.0.1:" + srv.port()
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentitiesOnly yes\n  IdentityFile ~/.ssh/agentkey.pub\n")
		c, err := NewClient(target)
		if err != nil {
			t.Fatalf("IdentitiesOnly + .pub identity with the key in the agent: %v", err)
		}
		c.Close()
	})
	t.Run("passphrase default key held by the agent", func(t *testing.T) {
		home, _ := sshHome(t, "unused")
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(pk)
		blk, err := ssh.MarshalPrivateKeyWithPassphrase(sk, "", []byte("pw"))
		if err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), pem.EncodeToMemory(blk), 0o600)
		startAgent(t, sk)
		srv := startFakeSSHD(t, pub)
		writeSSHConfig(t, home, "Host *\n  IdentitiesOnly yes\n")
		c, err := NewClient("deploy@127.0.0.1:" + srv.port())
		if err != nil {
			t.Fatalf("Host * IdentitiesOnly with an encrypted default key in the agent: %v", err)
		}
		c.Close()
	})
	t.Run("agent keys outside the identities are not offered", func(t *testing.T) {
		home, _ := sshHome(t, "unused")
		pk, sk, _ := ed25519.GenerateKey(rand.Reader)
		pub, _ := ssh.NewPublicKey(pk)
		startAgent(t, sk) // authorized on the server, but not an identity
		srv := startFakeSSHD(t, pub)
		other, _, _ := ed25519.GenerateKey(rand.Reader)
		op, _ := ssh.NewPublicKey(other)
		os.WriteFile(filepath.Join(home, ".ssh", "other.pub"), ssh.MarshalAuthorizedKey(op), 0o644)
		writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentitiesOnly yes\n  IdentityFile ~/.ssh/other.pub\n")
		if c, err := NewClient("deploy@127.0.0.1:" + srv.port()); err == nil {
			c.Close()
			t.Fatal("an agent key that is not a configured identity was offered under IdentitiesOnly")
		}
	})
}

// A configured private IdentityFile is offered even when the agent holds only
// unrelated keys: the client tries "publickey" once, so the agent's keys and
// the files must go in one method.
func TestNewClient_IdentityFileWithBusyAgent(t *testing.T) {
	for _, io := range []bool{true, false} {
		name := "IdentitiesOnly-no"
		if io {
			name = "IdentitiesOnly-yes"
		}
		t.Run(name, func(t *testing.T) {
			home, pub := sshHome(t, "deploy")
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			startAgent(t, other)
			srv := startFakeSSHD(t, pub)
			cfg := "Host 127.0.0.1\n  IdentityFile ~/.ssh/deploy\n"
			if io {
				cfg += "  IdentitiesOnly yes\n"
			}
			writeSSHConfig(t, home, cfg)
			c, err := NewClient("deploy@127.0.0.1:" + srv.port())
			if err != nil {
				t.Fatalf("the IdentityFile was never offered: %v", err)
			}
			c.Close()
		})
	}
}

// No config: a default key file is still offered when the agent holds only
// unrelated keys.
func TestNewClient_DefaultKeyFileWithBusyAgent(t *testing.T) {
	_, pub := sshHome(t, "id_ed25519")
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	startAgent(t, other)
	srv := startFakeSSHD(t, pub)
	c, err := NewClient("deploy@127.0.0.1:" + srv.port())
	if err != nil {
		t.Fatalf("default key file shadowed by the agent: %v", err)
	}
	c.Close()
}

// IdentityFile k with only k.pub on disk and the private key in the agent
// (hardware token): the .pub sibling is what identifies the key.
func TestNewClient_PubSiblingNoPrivateFile(t *testing.T) {
	home, _ := sshHome(t, "unused")
	pk, sk, _ := ed25519.GenerateKey(rand.Reader)
	pub, _ := ssh.NewPublicKey(pk)
	os.WriteFile(filepath.Join(home, ".ssh", "k.pub"), ssh.MarshalAuthorizedKey(pub), 0o644)
	startAgent(t, sk)
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, "Host 127.0.0.1\n  IdentitiesOnly yes\n  IdentityFile ~/.ssh/k\n")
	c, err := NewClient("deploy@127.0.0.1:" + srv.port())
	if err != nil {
		t.Fatalf("IdentityFile k + k.pub with the key in the agent: %v", err)
	}
	c.Close()
}

// A passphrase-protected legacy PEM key has no clear public half: only its
// .pub sibling says which agent key it is.
func TestNewClient_PubSiblingLegacyEncryptedPEM(t *testing.T) {
	home, _ := sshHome(t, "unused")
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	//nolint:staticcheck
	blk, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rk), []byte("pw"), x509.PEMCipherAES256)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(home, ".ssh", "id_rsa"), pem.EncodeToMemory(blk), 0o600)
	pub, _ := ssh.NewPublicKey(&rk.PublicKey)
	os.WriteFile(filepath.Join(home, ".ssh", "id_rsa.pub"), ssh.MarshalAuthorizedKey(pub), 0o644)
	startAgent(t, rk)
	srv := startFakeSSHD(t, pub)
	writeSSHConfig(t, home, "Host *\n  IdentitiesOnly yes\n")
	c, err := NewClient("deploy@127.0.0.1:" + srv.port())
	if err != nil {
		t.Fatalf("Host * IdentitiesOnly, encrypted PEM id_rsa + .pub, key in the agent: %v", err)
	}
	c.Close()
}

// A config ssh refuses for its permissions says so and what to do.
func TestResolveConfig_BadPermissionsHint(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	writeSSHConfig(t, home, "Host h\n  Port 2200\n")
	os.Chmod(filepath.Join(home, ".ssh", "config"), 0o666)
	_, err := resolveConfig("h", "", "22", false, false, 0)
	if err == nil || !strings.Contains(err.Error(), "sudo -E") {
		t.Fatalf("err = %v, want the permissions refusal to say what to do", err)
	}
}
