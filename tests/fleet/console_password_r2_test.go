// Fleet scenario for console passwords, review round 2: a viewer that stalls
// in the RFB handshake is cut off, and the listener connection with it.
package fleet

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/grpcapi"
)

// TestFleet_ConsolePassword_AStalledViewerIsCutOff (review M4/R1-M3): a
// viewer that opens the console and never answers the RFB handshake gets
// DeadlineExceeded once vncHandshakeTimeout passes, and the owning daemon
// closes its connection to the VM's listener — a stalled viewer holds
// nothing open. The handshake runs on the handler's goroutine, so nothing
// writing to the stream outlives the handler.
//
// Mutation "no viewer deadline" — red (the stream never ends).
func TestFleet_ConsolePassword_AStalledViewerIsCutOff(t *testing.T) {
	t.Cleanup(grpcapi.SetVNCHandshakeTimeoutForTests(300 * time.Millisecond))
	c := consoleCluster(t)
	owner := c.Nodes[1]
	createConsoleVM(t, c, c.Nodes[0], "web", owner.Name, false)
	if consolePassword(t, owner, "web", "vnc") == "" {
		t.Fatal("fixture: the VM has no console password")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	closed := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn.Write([]byte("RFB 003.008\n"))
		_, _ = io.Copy(io.Discard, conn) // until the daemon lets go of it
		conn.Close()
		close(closed)
	}()
	owner.Virt.SetVNCPort("web", ln.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := c.SelfClient(owner).ProxyVNC(metadata.NewOutgoingContext(ctx, metadata.Pairs("x-vm-name", "web")))
	if err != nil {
		t.Fatal(err)
	}
	// The daemon's ProtocolVersion; the viewer then says nothing.
	if _, err := st.Recv(); err != nil {
		t.Fatalf("no protocol version from the daemon: %v", err)
	}
	start := time.Now()
	_, err = st.Recv()
	if status.Code(err) != codes.DeadlineExceeded || !strings.Contains(status.Convert(err).Message(), "handshake") || time.Since(start) > 5*time.Second {
		t.Fatalf("a stalled viewer's stream ended with %v, want DeadlineExceeded from the handshake bound", err)
	}
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("the daemon kept its connection to the VM's listener open after cutting the viewer off")
	}
}
