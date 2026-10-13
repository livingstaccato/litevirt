package libvirt

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/rfb"
)

// VNC password probe (docs/ui.md "Console passwords").
//
// VNC authentication is DES. A QEMU whose crypto backend has no DES — every
// FIPS-mode host — cannot do it, and current QEMU (10.x) finds that out only
// when a viewer AUTHENTICATES: the display starts, the guest runs, and every
// console then fails. So the probe proves the whole thing on this host's own
// QEMU: it starts a password-protected display, sets a password over QMP and
// authenticates to it with the console proxy's own code (internal/rfb). Only a
// successful authentication counts as "can". A FIPS-mode kernel counts as
// "cannot" whatever QEMU says. A host that cannot sets no VNC passwords (SPICE
// keeps its own): its consoles stay open, and it says so in
// PingResponse.not_enforcing. The start backstop (startWithConsoleBackstop)
// covers an older QEMU that refuses at start-up instead.

// probeProcess is the probe's QEMU.
type probeProcess interface {
	Wait() error
	Kill() error
	// Stderr is what QEMU wrote, once Wait has returned.
	Stderr() string
}

// execProbe is a probeProcess run with os/exec.
type execProbe struct {
	cmd    *exec.Cmd
	mu     sync.Mutex
	stderr bytes.Buffer
}

func (p *execProbe) Wait() error { return p.cmd.Wait() }
func (p *execProbe) Kill() error {
	if p.cmd.Process == nil {
		return nil
	}
	return p.cmd.Process.Kill()
}
func (p *execProbe) Stderr() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stderr.String()
}

type lockedWriter struct {
	mu *sync.Mutex
	b  *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

// vncProbeLaunch starts QEMU with args. A variable so the tests run a fake.
var vncProbeLaunch = func(ctx context.Context, bin string, args []string) (probeProcess, error) {
	p := &execProbe{cmd: exec.CommandContext(ctx, bin, args...)}
	p.cmd.Stderr = lockedWriter{&p.mu, &p.stderr}
	if err := p.cmd.Start(); err != nil {
		return nil, err
	}
	return p, nil
}

// vncProbeBinary finds this host's QEMU system emulator, "" when it has none.
var vncProbeBinary = func() string {
	arch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	cands := []string{"/usr/libexec/qemu-kvm"}
	if arch != "" {
		cands = append(cands, "qemu-system-"+arch)
	}
	for _, c := range cands {
		if p, err := exec.LookPath(c); err == nil {
			return p
		}
	}
	return ""
}

// fipsEnabledPath is the kernel's FIPS switch. A variable for the tests.
var fipsEnabledPath = "/proc/sys/crypto/fips_enabled"

func fipsEnabled() bool {
	b, err := os.ReadFile(fipsEnabledPath)
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// vncProbeTimeout bounds the whole probe.
const vncProbeTimeout = 20 * time.Second

// ProbeVNCPassword reports why this host cannot give a VNC console a
// password, "" when it can. A FIPS-mode kernel cannot. Otherwise it starts
// this host's QEMU with no machine and a password-protected VNC display on a
// private unix socket, sets a random password over QMP, and authenticates to
// the display with it: only success counts as "can". A QEMU that refuses the
// display at start-up cannot. Anything inconclusive — no QEMU, a failure for
// another reason — counts as "can", because the start backstop still catches
// a refusal at start-up and nothing would otherwise get a password at all.
func ProbeVNCPassword(ctx context.Context) string {
	r, _ := probeVNCPassword(ctx)
	return r
}

// probeVNCPassword is ProbeVNCPassword, and whether the "can" was PROVEN by an
// authentication (false for every inconclusive "can").
func probeVNCPassword(ctx context.Context) (string, bool) {
	if fipsEnabled() {
		return "the kernel is in FIPS mode (fips_enabled=1), and VNC authentication is DES", false
	}
	bin := vncProbeBinary()
	if bin == "" {
		return "", false
	}
	dir, err := os.MkdirTemp("", "lv-vncprobe-")
	if err != nil {
		return "", false
	}
	defer os.RemoveAll(dir)
	vncSock, qmpSock := filepath.Join(dir, "vnc.sock"), filepath.Join(dir, "qmp.sock")
	ctx, cancel := context.WithTimeout(ctx, vncProbeTimeout)
	defer cancel()
	p, err := vncProbeLaunch(ctx, bin, []string{
		"-machine", "none", "-nodefaults", "-no-user-config", "-display", "none", "-S",
		"-vnc", "unix:" + vncSock + ",password=on",
		"-qmp", "unix:" + qmpSock + ",server=on,wait=off",
	})
	if err != nil {
		return "", false
	}
	exited := make(chan error, 1)
	go func() { exited <- p.Wait() }()
	defer func() {
		_ = p.Kill()
		<-exited
	}()

	// Both sockets, or QEMU's exit.
	for {
		_, e1 := os.Stat(vncSock)
		_, e2 := os.Stat(qmpSock)
		if e1 == nil && e2 == nil {
			break
		}
		select {
		case werr := <-exited:
			exited <- werr // the deferred wait reads it again
			stderr := p.Stderr()
			if IsConsolePasswordRefusal(errors.New(stderr)) {
				return fmt.Sprintf("%s refuses a VNC password display: %s", filepath.Base(bin), firstLine(stderr)), false
			}
			return "", false
		case <-ctx.Done():
			return "", false
		case <-time.After(50 * time.Millisecond):
		}
	}

	password, err := newConsolePassword(VNCPasswordLen)
	if err != nil {
		return "", false
	}
	qmp, err := (&net.Dialer{}).DialContext(ctx, "unix", qmpSock)
	if err != nil {
		return "", false
	}
	defer qmp.Close()
	deadline, _ := ctx.Deadline()
	_ = qmp.SetDeadline(deadline)
	q := &qmpConn{dec: json.NewDecoder(bufio.NewReader(qmp)), enc: json.NewEncoder(qmp)}
	if err := q.greeting(); err != nil {
		return "", false
	}
	if err := q.run("qmp_capabilities", nil); err != nil {
		return "", false
	}
	if err := q.run("set_password", map[string]any{"protocol": "vnc", "password": password}); err != nil {
		return fmt.Sprintf("%s refuses to set a VNC password: %v", filepath.Base(bin), err), false
	}

	vnc, err := (&net.Dialer{}).DialContext(ctx, "unix", vncSock)
	if err != nil {
		return "", false
	}
	_ = vnc.SetDeadline(deadline)
	// AuthenticateVNC, not Authenticate: a display that asks for no password
	// at all (security type None) would let anything in, so it is "cannot
	// enforce", not "can".
	aerr := rfb.AuthenticateVNC(vnc, password)
	_ = vnc.Close()
	_ = q.run("quit", nil)
	if errors.Is(aerr, rfb.ErrNoVNCAuth) {
		return fmt.Sprintf("%s does not enforce a VNC password: %v", filepath.Base(bin), aerr), false
	}
	if aerr != nil {
		return fmt.Sprintf("%s cannot authenticate a VNC password: %v", filepath.Base(bin), aerr), false
	}
	return "", true
}

// SpiceUnusableReason is why SPICE consoles cannot connect on this host, ""
// when nothing says so. On a FIPS-mode kernel spice-server generates an
// RSA-1024 key for every SPICE link, which FIPS refuses ("Failed to generate
// 1024 bits RSA key", lab 2 on QEMU 8.2.2): the guest runs and VNC works,
// but every SPICE connection is closed, with or without a password. Nothing
// is refused because of it; the host says so (daemon WARN at startup,
// GetSpiceInfo's warning).
func SpiceUnusableReason() string {
	if fipsEnabled() {
		return "the kernel is in FIPS mode: spice-server makes an RSA-1024 key for every SPICE link, " +
			"which FIPS refuses, so no SPICE client can connect to a console on this host (VNC works)"
	}
	return ""
}

// SpiceUnusable is SpiceUnusableReason for this client's host.
func (c *Client) SpiceUnusable() string { return SpiceUnusableReason() }

// MarkVNCProbed records that the startup probe has answered (whatever it
// found), releasing WaitVNCProbe.
func (c *Client) MarkVNCProbed() {
	if c.vncProbed == nil {
		return
	}
	c.vncProbedOnce.Do(func() { close(c.vncProbed) })
}

// WaitVNCProbe waits, at most d, for the startup probe to answer, so a
// target asked whether it can take a guest's VNC password right after it
// started answers from the probe rather than from not knowing yet.
func (c *Client) WaitVNCProbe(d time.Duration) {
	if c.vncProbed == nil {
		return
	}
	select {
	case <-c.vncProbed:
	case <-time.After(d):
	}
}

// qmpConn is the least of QMP the probe needs: the greeting, and commands
// that return or fail (events in between are skipped).
type qmpConn struct {
	dec *json.Decoder
	enc *json.Encoder
}

type qmpMsg struct {
	QMP    json.RawMessage `json:"QMP"`
	Return json.RawMessage `json:"return"`
	Error  *struct {
		Class string `json:"class"`
		Desc  string `json:"desc"`
	} `json:"error"`
}

func (q *qmpConn) greeting() error {
	var m qmpMsg
	if err := q.dec.Decode(&m); err != nil {
		return err
	}
	if m.QMP == nil {
		return errors.New("no QMP greeting")
	}
	return nil
}

func (q *qmpConn) run(cmd string, args map[string]any) error {
	req := map[string]any{"execute": cmd}
	if args != nil {
		req["arguments"] = args
	}
	if err := q.enc.Encode(req); err != nil {
		return err
	}
	for {
		var m qmpMsg
		if err := q.dec.Decode(&m); err != nil {
			return err
		}
		if m.Error != nil {
			return fmt.Errorf("%s: %s", m.Error.Class, m.Error.Desc)
		}
		if m.Return != nil {
			return nil
		}
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return s
}
