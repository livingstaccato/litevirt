package fencessh_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/fencessh"
	"github.com/litevirt/litevirt/internal/pki"
)

// A world of hosts, each with a REAL OpenSSH sshd run unprivileged on its own
// loopback address (127.0.0.0/8 is all local on Linux), its own sshd host
// key, its own CA-issued certificate, its own fence key and its own forced
// command, whose systemctl is a fake that records a power-off in a state file
// instead of performing one. Every assertion about what sshd accepts or
// refuses is made against real OpenSSH semantics.
//
// It needs sshd and ssh on the machine. Without them it skips, saying why,
// unless LITEVIRT_REQUIRE_SSHD=1, under which it fails: a run that must prove
// these properties cannot pass by skipping them. With them, an sshd that
// exits or does not listen always fails.

type world struct {
	t    *testing.T
	root string
	ca   string
	db   *corrosion.Client
	user string
	// legacyKey is the hand-made key the lab drills put in every node's
	// /root/.ssh/authorized_keys as an unrestricted root key, and in root's
	// ssh config as its IdentityFile; legacySSH is the ssh wrapper standing
	// in for that config (fence.OverrideSSHBinaryForTest).
	legacyKey     string
	legacyKeyLine string
	legacySSH     string
}

type node struct {
	w       *world
	name    string
	ip      string
	pkiDir  string
	dir     string
	state   string
	port    int
	hostKey ssh.PublicKey
	hkPath  string
	// skipRendered starts n's sshd without the rendered authorized_keys:
	// its configuration on disk may say otherwise, the running sshd does not
	// read it.
	skipRendered bool
	fenceKy      ssh.PublicKey
	sshdLog      string
	// extraConfig is appended to n's sshd_config.
	extraConfig string
}

func requireOrSkip(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("LITEVIRT_REQUIRE_SSHD") == "1" {
		t.Fatalf("LITEVIRT_REQUIRE_SSHD=1: "+format, args...)
	}
	t.Skipf(format+" (set LITEVIRT_REQUIRE_SSHD=1 to fail instead)", args...)
}

func newWorld(t *testing.T) *world {
	t.Helper()
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	w := &world{t: t, root: root, ca: filepath.Join(root, "ca"), db: corrosion.NewTestClientT(t), user: u.Username}
	if err := corrosion.InitSchema(context.Background(), w.db); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(w.ca, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCA(filepath.Join(w.ca, "ca.crt"), filepath.Join(w.ca, "ca.key")); err != nil {
		t.Fatal(err)
	}
	// The hand-made legacy key and the wrapper that stands in for root's ssh
	// configuration: an IdentityFile and a known_hosts of its own. A managed
	// fence passes -F /dev/null, which the wrapper leaves alone.
	w.legacyKey = filepath.Join(root, "legacy_ed25519")
	pub := writeOpenSSHKey(t, w.legacyKey)
	w.legacyKeyLine = fencessh.KeyLine(pub)
	cfg := filepath.Join(root, "root_ssh_config")
	writeFile(t, cfg, fmt.Sprintf("IdentityFile %s\nIdentitiesOnly yes\nUserKnownHostsFile %s\n",
		w.legacyKey, filepath.Join(root, "root_known_hosts")), 0o600)
	w.legacySSH = filepath.Join(root, "ssh-as-root")
	writeFile(t, w.legacySSH, fmt.Sprintf(`#!/bin/sh
echo "$*" >> %s
case " $* " in *" -F /dev/null "*) exec ssh "$@" ;; esac
exec ssh -F %s "$@"
`, filepath.Join(root, "ssh-invocations"), cfg), 0o755)
	t.Cleanup(fence.OverrideSSHBinaryForTest(w.legacySSH))
	return w
}

// sshInvocations is every ssh command line a fence ran.
func (w *world) sshInvocations() []string {
	raw, _ := os.ReadFile(filepath.Join(w.root, "ssh-invocations"))
	var out []string
	for _, l := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

func writeFile(t *testing.T, path, data string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// writeOpenSSHKey writes a fresh ed25519 private key in OpenSSH form.
func writeOpenSSHKey(t *testing.T, path string) ssh.PublicKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, string(pem.EncodeToMemory(blk)), 0o600)
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sp
}

// node makes a host: certificate for ip, sshd host key, fence key, forced
// command and fake systemctl. Its sshd is not started (start).
func (w *world) node(name, ip string) *node {
	t := w.t
	t.Helper()
	n := &node{w: w, name: name, ip: ip}
	base := filepath.Join(w.root, name)
	n.pkiDir = filepath.Join(base, "pki")
	n.dir = filepath.Join(base, "ssh")
	n.state = filepath.Join(base, "power-state")
	n.sshdLog = filepath.Join(base, "sshd.log")
	for _, d := range []string{n.pkiDir, n.dir, filepath.Join(base, "bin")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	caCrt, _ := os.ReadFile(filepath.Join(w.ca, "ca.crt"))
	writeFile(t, filepath.Join(n.pkiDir, "ca.crt"), string(caCrt), 0o644)
	if err := pki.GenerateHostCert(filepath.Join(w.ca, "ca.crt"), filepath.Join(w.ca, "ca.key"),
		filepath.Join(n.pkiDir, "host.crt"), filepath.Join(n.pkiDir, "host.key"), name, parseIPOrNil(ip)); err != nil {
		t.Fatal(err)
	}
	n.hkPath = filepath.Join(base, "ssh_host_ed25519_key")
	n.hostKey = writeOpenSSHKey(t, n.hkPath)
	writeFile(t, n.hkPath+".pub", fencessh.KeyLine(n.hostKey)+"\n", 0o644)
	n.fenceKy = writeOpenSSHKey(t, filepath.Join(n.dir, fencessh.KeyName))
	writeFile(t, filepath.Join(n.dir, fencessh.CommandName), string(fencessh.ForcedCommand(name)), 0o755)
	writeFile(t, filepath.Join(base, "bin", "systemctl"),
		fmt.Sprintf("#!/bin/sh\necho \"systemctl $*\" >> %s\nexit 0\n", n.state), 0o755)
	return n
}

// poweredOff reports whether the node's fake systemctl was asked to power it
// off.
func (n *node) poweredOff() bool {
	raw, err := os.ReadFile(n.state)
	return err == nil && strings.Contains(string(raw), "poweroff")
}

// publish signs and writes n's row (with its own sshd host key unless
// hostKey says otherwise) and its hosts row, at address:port.
func (n *node) publish(accepting, ever bool, address string, port int) {
	t := n.w.t
	t.Helper()
	certPEM, err := os.ReadFile(filepath.Join(n.pkiDir, "host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := os.ReadFile(filepath.Join(n.pkiDir, "host.key"))
	blk, _ := pem.Decode(keyPEM)
	signer, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	row, err := fencessh.Sign(fencessh.Publication{
		HostName: n.name, Generation: 1, FencePubkeys: fencessh.KeyLine(n.fenceKy),
		SSHDHostkeys: fencessh.KeyLine(n.hostKey), Accepting: accepting, EverAccepting: ever, CertPEM: string(certPEM),
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := corrosion.PutHostFenceSSH(ctx, n.w.db, capabilities.GrantForTest(t, capabilities.FeatureFenceSSH), row); err != nil {
		t.Fatal(err)
	}
	n.hostRow(address, port)
}

// hostRow writes n's hosts row: where a fence of n dials.
func (n *node) hostRow(address string, port int) {
	t := n.w.t
	t.Helper()
	ctx := context.Background()
	if h, _ := corrosion.GetHost(ctx, n.w.db, n.name); h != nil {
		if _, err := n.w.db.DB().Exec(`UPDATE hosts SET address = ?, ssh_port = ? WHERE name = ?`, address, port, n.name); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := corrosion.InsertHost(ctx, n.w.db, corrosion.HostRecord{
		Name: n.name, Address: address, SSHUser: n.w.user, SSHPort: port, GRPCPort: 7443,
		State: "active", CertSerial: "01", FenceStrategy: "ssh",
	}); err != nil {
		t.Fatal(err)
	}
}

// verified is every published row but n's own, verified as n's agent would.
func (n *node) verifiedPeers() []*fencessh.Verified {
	t := n.w.t
	t.Helper()
	tr, err := fencessh.TrustFromPKIDir(n.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := corrosion.ListHostFenceSSH(context.Background(), n.w.db)
	if err != nil {
		t.Fatal(err)
	}
	var out []*fencessh.Verified
	for _, r := range rows {
		if r.HostName == n.name {
			continue
		}
		v, err := fencessh.Verify(r, tr)
		if err != nil {
			t.Fatalf("row of %s does not verify: %v", r.HostName, err)
		}
		out = append(out, v)
	}
	return out
}

// start runs n's sshd with an AuthorizedKeysFile list of the rendered
// authorized_keys (its verified peers) and, when legacy, a root
// authorized_keys holding the hand-made unrestricted legacy key. It skips
// only for a missing prerequisite (launch's prereqError); an sshd that is
// there but exits or never listens fails the test.
func (n *node) start(legacy bool) {
	t := n.w.t
	t.Helper()
	if err := n.launch(legacy); err != nil {
		var p *prereqError
		if errors.As(err, &p) {
			requireOrSkip(t, "%s", p.msg)
		}
		t.Fatal(err)
	}
}

// prereqError is a prerequisite of the real-sshd tests this machine lacks:
// the one kind of failure to start that start skips on.
type prereqError struct{ msg string }

func (e *prereqError) Error() string { return e.msg }

func prereq(format string, args ...any) error {
	return &prereqError{msg: fmt.Sprintf(format, args...)}
}

// sshdPrereqs reports a missing sshd or ssh client.
func sshdPrereqs() error {
	if _, err := os.Stat(fencessh.SSHDPath()); err != nil {
		return prereq("no sshd at %s: the real-sshd fence tests need OpenSSH's server", fencessh.SSHDPath())
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return prereq("no ssh client on PATH")
	}
	return nil
}

// launch is start, returning why n's sshd is not listening: a prereqError
// for a missing prerequisite, any other error (carrying sshd's log) for an
// sshd that exited or did not listen.
func (n *node) launch(legacy bool) error {
	t := n.w.t
	t.Helper()
	if err := sshdPrereqs(); err != nil {
		return err
	}
	ak := filepath.Join(n.dir, fencessh.AuthorizedKeysName)
	writeFile(t, ak, string(fencessh.AuthorizedKeys(n.dir, n.verifiedPeers())), 0o644)
	rootAK := filepath.Join(filepath.Dir(n.dir), "root_authorized_keys")
	rootLines := ""
	if legacy {
		rootLines = n.w.legacyKeyLine + " lab-shared-lvfence\n"
	}
	writeFile(t, rootAK, rootLines, 0o644)

	l, err := net.Listen("tcp", net.JoinHostPort(n.ip, "0"))
	if err != nil {
		return prereq("cannot bind %s, which this test gives %s: %v", n.ip, n.name, err)
	}
	n.port = l.Addr().(*net.TCPAddr).Port
	l.Close()
	readAK := ak
	if n.skipRendered {
		readAK = ""
	}
	cfg := filepath.Join(filepath.Dir(n.dir), "sshd_config")
	writeFile(t, cfg, fmt.Sprintf(`Port %d
ListenAddress %s
HostKey %s
PidFile none
UsePAM no
StrictModes no
AuthorizedKeysFile %s %s
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
AllowTcpForwarding yes
SetEnv PATH=%s:/usr/bin:/bin
LogLevel VERBOSE
`, n.port, n.ip, n.hkPath, rootAK, readAK, filepath.Join(filepath.Dir(n.dir), "bin"))+n.extraConfig, 0o600)
	logf, err := os.Create(n.sshdLog)
	if err != nil {
		t.Fatal(err)
	}
	sshdLog := func() []byte {
		raw, _ := os.ReadFile(n.sshdLog)
		return bytes.TrimSpace(raw)
	}
	cmd := exec.Command(fencessh.SSHDPath(), "-D", "-e", "-f", cfg)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		logf.Close()
		return prereq("cannot run %s as this user: %v", fencessh.SSHDPath(), err)
	}
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
		logf.Close()
		if t.Failed() {
			raw, _ := os.ReadFile(n.sshdLog)
			t.Logf("%s sshd log:\n%s", n.name, raw)
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(n.ip, fmt.Sprint(n.port)), 200*time.Millisecond)
		if err == nil {
			c.Close()
			return nil
		}
		select {
		case <-exited:
			return fmt.Errorf("sshd for %s exited before listening on %s:%d (%v): %s", n.name, n.ip, n.port, waitErr, sshdLog())
		default:
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("sshd for %s did not listen on %s:%d within 5s: %s", n.name, n.ip, n.port, sshdLog())
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// agent is n's fence ssh agent over the world's database, in mode.
func (n *node) agent(mode string) *fencessh.Agent {
	return fencessh.New(fencessh.Config{
		Self: n.name, PKIDir: n.pkiDir, DB: n.w.db, Dir: n.dir, SSHUser: n.w.user,
		Mode: func() string { return mode },
	})
}

// fence runs the production fence of target from n, as the coordinator and
// FenceHost build it: the target's hosts row, and the path n's agent decides.
func (n *node) fence(a *fencessh.Agent, target string) fence.Result {
	t := n.w.t
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h, err := corrosion.GetHost(ctx, n.w.db, target)
	if err != nil || h == nil {
		t.Fatalf("GetHost %s: %v", target, err)
	}
	return fence.Execute(ctx, fence.HostConfig{
		Name: h.Name, Address: h.Address, SSHUser: h.SSHUser, SSHPort: h.SSHPort, FenceStrategy: "ssh",
		SSH: a.FenceConfig(ctx, target),
	})
}

// parseIPOrNil is ip, or nil for "" (a certificate naming only 127.0.0.1).
func parseIPOrNil(ip string) net.IP {
	if ip == "" {
		return nil
	}
	return net.ParseIP(ip)
}
