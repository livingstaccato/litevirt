// Fleet scenarios: SPICE carried through the daemon (ProxySpice).
//
// A VM's SPICE listener is bound to its host's 127.0.0.1, so a client
// anywhere else can never reach it directly: handing it the host's address
// (what `lv spice --launch` and the UI's .vv used to do) gets "connection
// refused". ProxySpice carries each SPICE channel connection between the
// caller and that loopback listener, entering on any host and forwarded to
// the owning one, as ProxyVNC does for VNC.
//
// What only a fleet can show: the relay host forwards over real mTLS gRPC
// to the owning host, whose daemon dials ITS loopback listener, and a SPICE
// client's several channels each get a connection of their own.
package fleet

import (
	"bytes"
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// spiceListener stands in for a VM's SPICE listener on the owning host's
// 127.0.0.1: every connection gets the greeting, then an echo of what it
// receives. It counts the connections it accepted.
type spiceListener struct {
	ln    net.Listener
	mu    sync.Mutex
	conns int
}

var spiceGreeting = []byte("REDQ")

func startSpiceListener(t *testing.T) *spiceListener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &spiceListener{ln: ln}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			l.mu.Lock()
			l.conns++
			l.mu.Unlock()
			go func() {
				defer c.Close()
				if _, err := c.Write(spiceGreeting); err != nil {
					return
				}
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l
}

func (l *spiceListener) port() int { return l.ln.Addr().(*net.TCPAddr).Port }

func (l *spiceListener) accepted() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.conns
}

// spiceStreamReader reads the bytes of a ProxySpice client stream.
type spiceStreamReader struct {
	st  grpc.BidiStreamingClient[pb.SpiceData, pb.SpiceData]
	buf []byte
}

func (r *spiceStreamReader) Read(p []byte) (int, error) {
	for len(r.buf) == 0 {
		m, err := r.st.Recv()
		if err != nil {
			return 0, err
		}
		r.buf = m.Data
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// spiceChannel opens one ProxySpice stream for vm at entry, reads the
// listener's greeting, sends payload and reads it back.
func spiceChannel(ctx context.Context, c *Cluster, entry *Node, vm string, payload []byte) ([]byte, error) {
	ctx = metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", vm))
	st, err := c.SelfClient(entry).ProxySpice(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.CloseSend() }()
	r := &spiceStreamReader{st: st}
	greet := make([]byte, len(spiceGreeting))
	if _, err := io.ReadFull(r, greet); err != nil {
		return nil, err
	}
	if !bytes.Equal(greet, spiceGreeting) {
		return greet, nil
	}
	if err := st.Send(&pb.SpiceData{Data: payload}); err != nil {
		return nil, err
	}
	back := make([]byte, len(payload))
	if _, err := io.ReadFull(r, back); err != nil {
		return nil, err
	}
	return back, nil
}

// TestFleet_SpiceProxy_ChannelsReachTheLoopbackListenerThroughAPeer: the VM
// runs on owner, whose SPICE listener is on 127.0.0.1; the client enters on
// relay. Two channels at once each reach the listener over a connection of
// their own, and the bytes come back unchanged both ways (the client
// presents the SPICE password itself, so nothing may be rewritten).
//
// Mutation "ProxySpice not forwarded to the owning host" — red.
// Mutation "one direction only" — red.
func TestFleet_SpiceProxy_ChannelsReachTheLoopbackListenerThroughAPeer(t *testing.T) {
	c := consoleCluster(t)
	relay, owner := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, relay, "desk", owner.Name, true)
	l := startSpiceListener(t)
	owner.Virt.SetSpicePort("desk", l.port())
	// relay must NOT find it: the listener is owner's, reached only there.
	relay.Virt.SetSpicePort("desk", 1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	payloads := [][]byte{[]byte("main-channel-link"), []byte("display-channel-link")}
	var wg sync.WaitGroup
	errs := make([]error, len(payloads))
	got := make([][]byte, len(payloads))
	for i, p := range payloads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got[i], errs[i] = spiceChannel(ctx, c, relay, "desk", p)
		}()
	}
	wg.Wait()
	for i, p := range payloads {
		if errs[i] != nil {
			t.Fatalf("SPICE channel %d via %s: %v", i, relay.Name, errs[i])
		}
		if !bytes.Equal(got[i], p) {
			t.Errorf("SPICE channel %d via %s: got %q back, want %q", i, relay.Name, got[i], p)
		}
	}
	if n := l.accepted(); n != len(payloads) {
		t.Errorf("the SPICE listener accepted %d connection(s), want one per channel (%d)", n, len(payloads))
	}
}

// TestFleet_SpiceProxy_StoppedVMRefused: a stopped VM has no SPICE listener;
// the caller is told so, wherever it entered.
func TestFleet_SpiceProxy_StoppedVMRefused(t *testing.T) {
	c := consoleCluster(t)
	relay, owner := c.Nodes[0], c.Nodes[1]
	createConsoleVM(t, c, relay, "desk", owner.Name, true)
	if _, err := c.SelfClient(relay).StopVM(context.Background(), &pb.StopVMRequest{Name: "desk"}); err != nil {
		t.Fatalf("stop desk: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	eventually(t, 10*time.Second, "ProxySpice for a stopped VM to be refused with FailedPrecondition", func() bool {
		_, err := spiceChannel(ctx, c, relay, "desk", []byte("x"))
		return status.Code(err) == codes.FailedPrecondition
	})
}
