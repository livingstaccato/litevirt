package main

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// `lv vnc --listen` binds loopback only: the port carries the console with
// the caller's credentials.
//
// Mutation "accept any address" — red.
func TestListenVNCLoopback_RefusesANonLoopbackAddress(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", "192.0.2.10:0", ":0"} {
		if ln, err := listenVNCLoopback(addr); err == nil {
			ln.Close()
			t.Errorf("--listen %s was accepted", addr)
		}
	}
	ln, err := listenVNCLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatalf("--listen 127.0.0.1:0: %v", err)
	}
	ln.Close()
}

// vncStreamFake is the ProxyVNC client stream: what the viewer sends lands in
// sent, and toViewer is what the daemon answers.
type vncStreamFake struct {
	grpc.ClientStream
	ctx      context.Context
	sent     chan []byte
	toViewer chan []byte
}

func (s *vncStreamFake) Send(m *pb.VNCData) error { s.sent <- m.Data; return nil }
func (s *vncStreamFake) Recv() (*pb.VNCData, error) {
	select {
	case b, ok := <-s.toViewer:
		if !ok {
			return nil, io.EOF
		}
		return &pb.VNCData{Data: b}, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *vncStreamFake) CloseSend() error { return nil }

type vncClientFake struct {
	pb.LiteVirtClient
	stream *vncStreamFake
	vm     string
}

func (c *vncClientFake) ProxyVNC(ctx context.Context, _ ...grpc.CallOption) (grpc.BidiStreamingClient[pb.VNCData, pb.VNCData], error) {
	md, _ := metadata.FromOutgoingContext(ctx)
	if v := md.Get("x-vm-name"); len(v) > 0 {
		c.vm = v[0]
	}
	c.stream.ctx = ctx
	return c.stream, nil
}

// Each connection to the local port is carried over ProxyVNC for the named
// VM, both ways — the web UI's path, where the daemon presents the password.
//
// Mutation "no x-vm-name" — red. Mutation "one direction only" — red.
func TestServeVNCListener_CarriesAViewerOverProxyVNC(t *testing.T) {
	st := &vncStreamFake{sent: make(chan []byte, 4), toViewer: make(chan []byte, 4)}
	c := &vncClientFake{stream: st}
	ln, err := listenVNCLoopback("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveVNCListener(ctx, c, "web", ln) }()

	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	st.toViewer <- []byte("RFB 003.008\n")
	got := make([]byte, 12)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "RFB 003.008\n" {
		t.Fatalf("viewer read %q, %v; want the daemon's bytes", got, err)
	}
	if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case b := <-st.sent:
		if !bytes.Equal(b, []byte("RFB 003.008\n")) {
			t.Errorf("daemon got %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the viewer's bytes never reached ProxyVNC")
	}
	if c.vm != "web" {
		t.Errorf("ProxyVNC opened for x-vm-name %q, want web", c.vm)
	}
	conn.Close()
	cancel()
	if err := <-done; err != nil {
		t.Errorf("serveVNCListener: %v", err)
	}
}

// `lv vnc` says when the console needs a password and how to reach it.
//
// Mutation "no password note" — red.
func TestPrintVNCInfo_SaysAPasswordIsNeededAndHow(t *testing.T) {
	var b strings.Builder
	printVNCInfo(&b, "web", &pb.VM{VncAddress: "vnc://10.0.0.5:5900", VncPasswordRequired: true})
	for _, want := range []string{"127.0.0.1", "required", "lv vnc web --listen 127.0.0.1:5900", "web UI"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("lv vnc output lacks %q:\n%s", want, b.String())
		}
	}
	var open strings.Builder
	printVNCInfo(&open, "web", &pb.VM{VncAddress: "vnc://10.0.0.5:5900"})
	if strings.Contains(open.String(), "Password") {
		t.Errorf("a console with no password prints a password note:\n%s", open.String())
	}
}
