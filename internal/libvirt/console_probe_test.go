package libvirt

import (
	"bytes"
	"context"
	"crypto/des"
	"encoding/json"
	"errors"
	"io"
	"math/bits"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeProbeQEMU is QEMU as the probe meets it: a QMP socket and a VNC socket
// with password=on. authWorks=false models a FIPS-mode host whose QEMU starts
// (and even takes set_password) but cannot do the DES of VNC authentication,
// which is where current QEMU refuses it. exitStderr != "" models a QEMU that
// refuses the display at startup instead.
type fakeProbeQEMU struct {
	authWorks  bool
	exitStderr string

	mu       sync.Mutex
	password string
	authed   bool
	done     chan struct{}
	once     sync.Once
	lns      []net.Listener
}

func (q *fakeProbeQEMU) launch(t *testing.T) func(context.Context, string, []string) (probeProcess, error) {
	return func(_ context.Context, _ string, args []string) (probeProcess, error) {
		q.done = make(chan struct{})
		if q.exitStderr != "" {
			close(q.done)
			return q, nil
		}
		var vncPath, qmpPath string
		for i, a := range args {
			if i == 0 {
				continue
			}
			switch args[i-1] {
			case "-vnc":
				vncPath = strings.TrimPrefix(strings.SplitN(a, ",", 2)[0], "unix:")
			case "-qmp":
				qmpPath = strings.TrimPrefix(strings.SplitN(a, ",", 2)[0], "unix:")
			}
		}
		if vncPath == "" || qmpPath == "" || !strings.Contains(strings.Join(args, " "), "password=on") {
			t.Errorf("probe args lack a password VNC or a QMP socket: %v", args)
			close(q.done)
			return q, nil
		}
		qmp, err := net.Listen("unix", qmpPath)
		if err != nil {
			return nil, err
		}
		vnc, err := net.Listen("unix", vncPath)
		if err != nil {
			return nil, err
		}
		q.lns = []net.Listener{qmp, vnc}
		go q.serveQMP(qmp)
		go q.serveVNC(vnc)
		return q, nil
	}
}

func (q *fakeProbeQEMU) serveQMP(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	enc := json.NewEncoder(conn)
	_ = enc.Encode(map[string]any{"QMP": map[string]any{"version": map[string]any{}}})
	dec := json.NewDecoder(conn)
	for {
		var cmd struct {
			Execute   string         `json:"execute"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := dec.Decode(&cmd); err != nil {
			return
		}
		switch cmd.Execute {
		case "set_password":
			q.mu.Lock()
			q.password, _ = cmd.Arguments["password"].(string)
			q.mu.Unlock()
		case "quit":
			_ = enc.Encode(map[string]any{"return": map[string]any{}})
			_ = q.Kill()
			return
		}
		_ = enc.Encode(map[string]any{"return": map[string]any{}})
	}
}

func (q *fakeProbeQEMU) serveVNC(ln net.Listener) {
	conn, err := ln.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("RFB 003.008\n"))
	ver := make([]byte, 12)
	if _, err := io.ReadFull(conn, ver); err != nil {
		return
	}
	_, _ = conn.Write([]byte{1, 2})
	pick := make([]byte, 1)
	if _, err := io.ReadFull(conn, pick); err != nil {
		return
	}
	challenge := []byte("probe-challenge!")
	_, _ = conn.Write(challenge)
	resp := make([]byte, 16)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return
	}
	q.mu.Lock()
	pw := q.password
	q.mu.Unlock()
	var key [8]byte
	copy(key[:], pw)
	for i := range key {
		key[i] = bits.Reverse8(key[i])
	}
	c, _ := des.NewCipher(key[:])
	want := make([]byte, 16)
	c.Encrypt(want[:8], challenge[:8])
	c.Encrypt(want[8:], challenge[8:])
	if !q.authWorks || pw == "" || !bytes.Equal(resp, want) {
		reason := "Authentication failed"
		_, _ = conn.Write([]byte{0, 0, 0, 1, 0, 0, 0, byte(len(reason))})
		_, _ = conn.Write([]byte(reason))
		return
	}
	q.mu.Lock()
	q.authed = true
	q.mu.Unlock()
	_, _ = conn.Write([]byte{0, 0, 0, 0})
}

func (q *fakeProbeQEMU) Wait() error {
	<-q.done
	if q.exitStderr != "" {
		return errors.New("exit status 1")
	}
	return nil
}

func (q *fakeProbeQEMU) Kill() error {
	q.once.Do(func() {
		for _, ln := range q.lns {
			ln.Close()
		}
		if q.exitStderr == "" {
			close(q.done)
		}
	})
	return nil
}

func (q *fakeProbeQEMU) Stderr() string { return q.exitStderr }

func withProbe(t *testing.T, q *fakeProbeQEMU, fips bool) {
	t.Helper()
	oldLaunch, oldBin, oldFIPS := vncProbeLaunch, vncProbeBinary, fipsEnabledPath
	t.Cleanup(func() { vncProbeLaunch, vncProbeBinary, fipsEnabledPath = oldLaunch, oldBin, oldFIPS })
	f := filepath.Join(t.TempDir(), "fips_enabled")
	v := "0\n"
	if fips {
		v = "1\n"
	}
	_ = os.WriteFile(f, []byte(v), 0o644)
	fipsEnabledPath = f
	vncProbeBinary = func() string { return "/usr/bin/qemu-system-x86_64" }
	vncProbeLaunch = q.launch(t)
}

// The probe tests AUTHENTICATION, not start-up: current QEMU starts a
// password display on a FIPS host and fails only when a viewer authenticates,
// so only a successful VNC authentication against a password set over QMP
// counts as "can".
//
// Mutation "probe returns once QEMU starts" — red (authFails).
func TestProbeVNCPassword_AuthenticatesAgainstTheProbeQEMU(t *testing.T) {
	ok := &fakeProbeQEMU{authWorks: true}
	withProbe(t, ok, false)
	if r, proven := probeVNCPassword(context.Background()); r != "" || !proven {
		t.Fatalf("a QEMU that authenticates: reason %q, proven %v; want able, proven", r, proven)
	}
	if !ok.authed {
		t.Fatal("the probe never authenticated to the probe QEMU's VNC socket")
	}

	bad := &fakeProbeQEMU{authWorks: false}
	withProbe(t, bad, false)
	if r := ProbeVNCPassword(context.Background()); r == "" {
		t.Fatal("a QEMU that starts but cannot authenticate a VNC password was reported able")
	}
}

// fips_enabled=1 is unavailable even when QEMU starts and authenticates.
//
// Mutation "fips only consulted when QEMU fails" — red.
func TestProbeVNCPassword_FIPSKernelIsUnavailable(t *testing.T) {
	q := &fakeProbeQEMU{authWorks: true}
	withProbe(t, q, true)
	if r := ProbeVNCPassword(context.Background()); !strings.Contains(r, "FIPS") {
		t.Fatalf("a FIPS kernel was reported able: %q", r)
	}
}

// A QEMU that refuses the display at startup is unavailable; an inconclusive
// failure is not (the start backstop still covers it).
func TestProbeVNCPassword_StartupRefusal(t *testing.T) {
	withProbe(t, &fakeProbeQEMU{exitStderr: "qemu-system-x86_64: -vnc unix:/x/vnc.sock,password=on: Cipher backend does not support DES algorithm\n"}, false)
	if r := ProbeVNCPassword(context.Background()); !strings.Contains(r, "DES") {
		t.Fatalf("a QEMU refusing the display at startup was reported able: %q", r)
	}
	withProbe(t, &fakeProbeQEMU{exitStderr: "qemu-system-x86_64: some other failure\n"}, false)
	if r := ProbeVNCPassword(context.Background()); r != "" {
		t.Fatalf("an inconclusive failure on a non-FIPS host was reported unable: %q", r)
	}
	_ = time.Second
}
