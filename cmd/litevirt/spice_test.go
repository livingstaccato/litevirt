package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv spice --launch` hands remote-viewer a 0600 connection file carrying the
// console's password, never the password on argv (where every local user
// could read it from /proc).
//
// Mutation "launch with the URI + password on argv" — red.
func TestSpiceLaunch_PasswordInA0600FileNotArgv(t *testing.T) {
	resp := &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5930, Uri: "spice://10.0.0.5:5930",
		Password: "Spice24CharPasswordAbcde"}
	path, err := writeSpiceVV(t.TempDir(), "desk", "127.0.0.1", 5930, resp.Password)
	if err != nil {
		t.Fatalf("writeSpiceVV: %v", err)
	}
	args := spiceLaunchArgs(path)
	for _, a := range args {
		if strings.Contains(a, resp.Password) {
			t.Fatalf("the password is on remote-viewer's argv: %v", args)
		}
	}
	if len(args) != 1 || args[0] != path {
		t.Fatalf("remote-viewer args = %v, want just the connection file", args)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("connection file mode %v, want 0600", fi.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	for _, want := range []string{"[virt-viewer]", "type=spice", "host=127.0.0.1", "port=5930",
		"password=Spice24CharPasswordAbcde", "delete-this-file=1"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("connection file missing %q:\n%s", want, b)
		}
	}
}

// A host where SPICE cannot connect (a FIPS-mode kernel) is named in the
// output; the info is still printed.
//
// Mutation "warning not printed" — red.
func TestSpiceInfo_PrintsTheHostsWarning(t *testing.T) {
	var b bytes.Buffer
	printSpiceInfo(&b, "desk", &pb.GetSpiceInfoResponse{Host: "h", Port: 5930, Uri: "spice://h:5930",
		Warning: "the kernel is in FIPS mode: no SPICE client can connect"}, false)
	if !strings.Contains(b.String(), "Warning:") || !strings.Contains(b.String(), "FIPS") || !strings.Contains(b.String(), "Port: 5930") {
		t.Errorf("lv spice output lacks the warning or the info:\n%s", b.String())
	}
}

// The password is printed only on request.
//
// Mutation "always print the password" — red.
func TestSpiceInfo_PasswordOnlyWithShowPassword(t *testing.T) {
	resp := &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5930, Uri: "spice://10.0.0.5:5930",
		Password: "Spice24CharPasswordAbcde"}
	var hidden, shown bytes.Buffer
	printSpiceInfo(&hidden, "desk", resp, false)
	printSpiceInfo(&shown, "desk", resp, true)
	if strings.Contains(hidden.String(), resp.Password) {
		t.Errorf("the password is printed without --show-password:\n%s", hidden.String())
	}
	if !strings.Contains(hidden.String(), "--show-password") {
		t.Errorf("the output does not say how to get the password:\n%s", hidden.String())
	}
	if !strings.Contains(shown.String(), "Password: "+resp.Password) {
		t.Errorf("--show-password does not print it:\n%s", shown.String())
	}
	var none bytes.Buffer
	printSpiceInfo(&none, "desk", &pb.GetSpiceInfoResponse{Host: "h", Port: 1, Uri: "spice://h:1"}, true)
	if strings.Contains(none.String(), "Password") {
		t.Errorf("a console with no password prints a Password line:\n%s", none.String())
	}
}

// `lv spice --launch` points remote-viewer at a loopback port on THIS
// machine that litevirt carries to the VM's SPICE listener, never at the
// VM's host address: SPICE listens on that host's 127.0.0.1 only, so the
// host address is always "connection refused" (N2 in vnc-password-lab.md).
//
// Mutation "connection file uses resp.Host / resp.Port" — red.
func TestSpiceLaunch_ConnectionFilePointsAtTheLocalRelay(t *testing.T) {
	resp := &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5930, Uri: "spice://10.0.0.5:5930",
		Password: "Spice24CharPasswordAbcde"}
	ln, err := listenConsoleLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	path, err := writeSpiceRelayVV(t.TempDir(), "desk", resp, ln)
	if err != nil {
		t.Fatalf("writeSpiceRelayVV: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)
	for _, want := range []string{"\nhost=127.0.0.1\n", "\nport=" + port + "\n", "\npassword=Spice24CharPasswordAbcde\n"} {
		if !strings.Contains(string(b), want) {
			t.Errorf("connection file lacks %q:\n%s", strings.TrimSpace(want), b)
		}
	}
	if strings.Contains(string(b), "10.0.0.5") {
		t.Errorf("connection file points at the VM's host address, where SPICE does not listen:\n%s", b)
	}
}

// spiceStreamFake is the ProxySpice client stream: what the client sends
// lands in sent, and toClient is what the daemon answers.
type spiceStreamFake struct {
	grpc.ClientStream
	ctx      context.Context
	sent     chan []byte
	toClient chan []byte
}

func (s *spiceStreamFake) Send(m *pb.SpiceData) error { s.sent <- m.Data; return nil }
func (s *spiceStreamFake) Recv() (*pb.SpiceData, error) {
	select {
	case b, ok := <-s.toClient:
		if !ok {
			return nil, io.EOF
		}
		return &pb.SpiceData{Data: b}, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *spiceStreamFake) CloseSend() error { return nil }

type spiceClientFake struct {
	pb.LiteVirtClient
	stream *spiceStreamFake
	vm     string
}

func (c *spiceClientFake) ProxySpice(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[pb.SpiceData, pb.SpiceData], error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	if v := md.Get("x-vm-name"); len(v) > 0 {
		c.vm = v[0]
	}
	c.stream.ctx = ctx
	return c.stream, nil
}

// Each connection to the local port (one per SPICE channel) is carried over
// ProxySpice for the named VM, both ways and unchanged.
//
// Mutation "no x-vm-name" — red. Mutation "one direction only" — red.
func TestServeSpiceListener_CarriesAChannelOverProxySpice(t *testing.T) {
	st := &spiceStreamFake{sent: make(chan []byte, 4), toClient: make(chan []byte, 4)}
	c := &spiceClientFake{stream: st}
	ln, err := listenConsoleLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveSpiceListener(ctx, c, "desk", ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("REDQ-link")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-st.sent:
		if !bytes.Equal(b, []byte("REDQ-link")) {
			t.Errorf("daemon got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the client's bytes never reached ProxySpice")
	}
	st.toClient <- []byte("REDQ-reply")
	got := make([]byte, len("REDQ-reply"))
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "REDQ-reply" {
		t.Fatalf("client read %q, %v; want the daemon's bytes", got, err)
	}
	if c.vm != "desk" {
		t.Errorf("ProxySpice opened for x-vm-name %q, want desk", c.vm)
	}
	conn.Close()
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serveSpiceListener: %v", err)
	}
}

// Plain `lv spice` says where the listener is (the host's 127.0.0.1) and how
// to reach it through litevirt, rather than offering a URI that cannot
// connect from anywhere but that host.
//
// Mutation "no --launch / --listen hint" — red.
func TestSpiceInfo_SaysHowToReachTheLoopbackListener(t *testing.T) {
	var b bytes.Buffer
	printSpiceInfo(&b, "desk", &pb.GetSpiceInfoResponse{Host: "10.0.0.5", Port: 5930, Uri: "spice://10.0.0.5:5930"}, false)
	for _, want := range []string{"127.0.0.1", "lv spice desk --launch", "lv spice desk --listen 127.0.0.1:5930"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("lv spice output lacks %q:\n%s", want, b.String())
		}
	}
	if strings.Contains(b.String(), "spice://10.0.0.5:5930") {
		t.Errorf("lv spice offers a URI at the host address, where SPICE does not listen:\n%s", b.String())
	}
}

// echoSpiceClient answers GetSpiceInfo with resp and gives every ProxySpice
// call a stream of its own that echoes what it is sent, counting the
// streams — a SPICE listener behind the daemon, one connection per channel.
type echoSpiceClient struct {
	pb.LiteVirtClient
	resp    *pb.GetSpiceInfoResponse
	mu      sync.Mutex
	streams int
}

func (c *echoSpiceClient) GetSpiceInfo(context.Context, *pb.GetSpiceInfoRequest, ...grpc.CallOption) (*pb.GetSpiceInfoResponse, error) {
	return c.resp, nil
}

func (c *echoSpiceClient) ProxySpice(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[pb.SpiceData, pb.SpiceData], error) {
	c.mu.Lock()
	c.streams++
	c.mu.Unlock()
	return &echoSpiceStream{ctx: ctx, ch: make(chan []byte, 16)}, nil
}

func (c *echoSpiceClient) opened() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.streams
}

type echoSpiceStream struct {
	grpc.ClientStream
	ctx context.Context
	ch  chan []byte
}

func (s *echoSpiceStream) Send(m *pb.SpiceData) error { s.ch <- m.Data; return nil }
func (s *echoSpiceStream) Recv() (*pb.SpiceData, error) {
	select {
	case b := <-s.ch:
		return &pb.SpiceData{Data: b}, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *echoSpiceStream) CloseSend() error { return nil }

// fakeViewer reads the connection file it was started with, opens one
// channel at once and another a while later — as remote-viewer opens
// channels throughout a session — then exits.
type fakeViewer struct {
	vv     string
	echoes []string
	errs   []error
	done   chan struct{}
	killed bool
}

func (v *fakeViewer) Wait() error { <-v.done; return nil }
func (v *fakeViewer) Kill() error { v.killed = true; return nil }

func (v *fakeViewer) run() {
	defer close(v.done)
	b, err := os.ReadFile(v.vv)
	if err != nil {
		v.errs = append(v.errs, err)
		return
	}
	_ = os.Remove(v.vv) // delete-this-file, as remote-viewer does
	v.vv = string(b)
	host, port := "", ""
	for _, line := range strings.Split(v.vv, "\n") {
		if h, ok := strings.CutPrefix(line, "host="); ok {
			host = h
		}
		if p, ok := strings.CutPrefix(line, "port="); ok {
			port = p
		}
	}
	for i, msg := range []string{"main-channel", "display-channel"} {
		if i > 0 {
			time.Sleep(300 * time.Millisecond)
		}
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 2*time.Second)
		if err != nil {
			v.errs = append(v.errs, err)
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
		_, _ = conn.Write([]byte(msg))
		got := make([]byte, len(msg))
		if _, err := io.ReadFull(conn, got); err != nil {
			v.errs = append(v.errs, err)
		} else {
			v.echoes = append(v.echoes, string(got))
		}
		conn.Close()
	}
}

// `lv spice --launch` end to end, through runSpice: remote-viewer is handed a
// file for the LOCAL relay (not the host address), and the relay keeps
// carrying channels until the viewer exits, not just the first one.
//
// Mutation "RunE writes the .vv with resp.Host/resp.Port" — red.
// Mutation "return right after starting the viewer" — red.
func TestRunSpice_LaunchCarriesChannelsUntilTheViewerExits(t *testing.T) {
	c := &echoSpiceClient{resp: &pb.GetSpiceInfoResponse{Host: "192.0.2.10", Port: 5930,
		Uri: "spice://192.0.2.10:5930", Password: "Spice24CharPasswordAbcde"}}
	v := &fakeViewer{done: make(chan struct{})}
	launcher := spiceViewerLauncher{
		find: func() (string, error) { return "/usr/bin/remote-viewer", nil },
		start: func(path, vvPath string) (viewerProc, error) {
			v.vv = vvPath
			go v.run()
			return v, nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var out bytes.Buffer
	if err := runSpice(ctx, c, &out, "desk", spiceOpts{launch: true}, launcher); err != nil {
		t.Fatalf("runSpice --launch: %v\n%s", err, out.String())
	}
	<-v.done
	if !strings.Contains(v.vv, "\nhost=127.0.0.1\n") || !strings.Contains(v.vv, "\npassword=Spice24CharPasswordAbcde\n") {
		t.Errorf("remote-viewer's connection file does not point at the local relay with the password:\n%s", v.vv)
	}
	if len(v.errs) != 0 || len(v.echoes) != 2 {
		t.Fatalf("the viewer's channels: echoes %q, errors %v; want both channels carried", v.echoes, v.errs)
	}
	if n := c.opened(); n != 2 {
		t.Errorf("ProxySpice opened %d stream(s), want one per channel (2)", n)
	}
	if v.killed {
		t.Error("the viewer was killed although it exited on its own")
	}
}

// `lv spice --listen` refuses an address other users could reach, before it
// opens anything.
//
// Mutation "RunE listens with net.Listen" — red.
func TestRunSpice_ListenRefusesANonLoopbackAddress(t *testing.T) {
	c := &echoSpiceClient{resp: &pb.GetSpiceInfoResponse{Host: "192.0.2.10", Port: 5930, Password: "p"}}
	// Bounded, so a --listen that wrongly opens serves only briefly.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := runSpice(ctx, c, &out, "desk", spiceOpts{listen: "0.0.0.0:0"}, remoteViewer)
	if err == nil || !strings.Contains(err.Error(), "not a loopback address") {
		t.Fatalf("lv spice --listen 0.0.0.0:0: %v, want a refusal", err)
	}
	if c.opened() != 0 {
		t.Errorf("ProxySpice was opened for a refused --listen")
	}
}

// A console with no password is open to anyone on this machine who reaches
// the local port; --listen says so.
//
// Mutation "no warning" — red.
func TestRunSpice_WarnsWhenTheConsoleHasNoPassword(t *testing.T) {
	c := &echoSpiceClient{resp: &pb.GetSpiceInfoResponse{Host: "192.0.2.10", Port: 5930}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // the listener closes at once
	var out bytes.Buffer
	if err := runSpice(ctx, c, &out, "desk", spiceOpts{listen: "127.0.0.1:0"}, remoteViewer); err != nil {
		t.Fatalf("runSpice --listen: %v", err)
	}
	if !strings.Contains(out.String(), "no password") {
		t.Errorf("lv spice --listen on a console with no password does not warn:\n%s", out.String())
	}
	c.resp.Password = "p"
	out.Reset()
	_ = runSpice(ctx, c, &out, "desk", spiceOpts{listen: "127.0.0.1:0"}, remoteViewer)
	if strings.Contains(out.String(), "no password") {
		t.Errorf("a passworded console gets the no-password warning:\n%s", out.String())
	}
}
