package grpcapi

import (
	"context"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The real ProxySpice releases the SPICE socket when the session is revoked:
// the SPICE listener sees its connection closed, as ProxyVNC's does (a
// SPICE session reached through litevirt ends with the credential that
// opened it; docs/auth.md).
//
// Mutation "no registerStreamCloser / no select on the context" — red.
func TestN1_RealSpiceIsCutOnRevoke(t *testing.T) {
	s, v := consoleServer(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	v.SetSpicePort("web1", ln.Addr().(*net.TCPAddr).Port)
	serverSide := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			serverSide <- c
		}
	}()
	token := login(t, s, "bob", "bob-pw").Token
	done, _ := runRealStream(t, s, token, "/litevirt.v1.LiteVirt/ProxySpice", "web1", func(ss grpc.ServerStream) error {
		return s.ProxySpice(&grpc.GenericServerStream[pb.SpiceData, pb.SpiceData]{ServerStream: ss})
	})
	var conn net.Conn
	select {
	case conn = <-serverSide:
	case err := <-done:
		t.Fatalf("ProxySpice ended before connecting to the SPICE socket: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("ProxySpice never connected to the SPICE socket")
	}
	defer conn.Close()
	if _, err := s.RevokeSession(adminCtx(), &pb.RevokeSessionRequest{Id: strings.TrimPrefix(token, SessionTokenPrefix)}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if status.Code(err) != codes.Unauthenticated {
			t.Fatalf("SPICE ended with %v, want Unauthenticated", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the real SPICE proxy was still open 3s after the session was revoked")
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("the SPICE socket was not closed by the proxy: read = %v, want EOF", err)
	}
}

// spiceAuthzServer is a server whose running VM "desk" (project acme) has a
// real SPICE listener that counts the connections it accepts.
func spiceAuthzServer(t *testing.T) (*Server, *atomic.Int32) {
	t.Helper()
	s := testServer(t)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "desk", HostName: s.hostName, State: "running", Spec: "{}", Project: "acme",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			c.Close()
		}
	}()
	v := libvirtfake.New()
	v.SetSpicePort("desk", ln.Addr().(*net.TCPAddr).Port)
	s.virt = v
	return s, &accepted
}

// proxySpiceAs runs the real ProxySpice for "desk" as the caller in ctx and
// returns its result (the transport ends with the test).
func proxySpiceAs(t *testing.T, s *Server, ctx context.Context) error {
	t.Helper()
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs("x-vm-name", "desk"))
	ts := &transportStream{ctx: ctx, transport: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		done <- s.ProxySpice(&grpc.GenericServerStream[pb.SpiceData, pb.SpiceData]{ServerStream: ts})
	}()
	select {
	case err := <-done:
		close(ts.transport)
		return err
	case <-time.After(500 * time.Millisecond):
		// Still relaying: it was let through. End it.
		close(ts.transport)
		return nil
	}
}

// ProxySpice is interactive access to the guest, so it requires vm.console
// on THIS VM: a caller bound only on another project (or a token scoped to
// one) is refused before anything dials the SPICE listener. The SPICE
// password is a second lock, not the authorization.
//
// Mutation "delete the RequirePerm(vm.console) in ProxySpice" — red.
func TestProxySpice_RequiresVMConsoleOnTheVM(t *testing.T) {
	t.Run("bound on another project", func(t *testing.T) {
		s, accepted := spiceAuthzServer(t)
		ctx := boundAtCtx(t, s, "mallory", "operator", "Operator", "/projects/beta")
		if err := proxySpiceAs(t, s, ctx); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("ProxySpice for a caller with no vm.console on desk: %v, want PermissionDenied", err)
		}
		if n := accepted.Load(); n != 0 {
			t.Errorf("the SPICE listener was dialled %d time(s) for a refused caller", n)
		}
	})
	t.Run("token scoped to another project", func(t *testing.T) {
		s, accepted := spiceAuthzServer(t)
		ctx := context.WithValue(userCtx("tok-admin", "admin"), ctxKeyScopePaths, []string{"/projects/beta"})
		if err := proxySpiceAs(t, s, ctx); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("ProxySpice for a token scoped to beta: %v, want PermissionDenied", err)
		}
		if n := accepted.Load(); n != 0 {
			t.Errorf("the SPICE listener was dialled %d time(s) for a refused token", n)
		}
	})
	// The control: bound on the VM's own project, the same caller gets
	// through to the listener, so the refusals above are the permission's.
	t.Run("bound on the VM's project", func(t *testing.T) {
		s, accepted := spiceAuthzServer(t)
		ctx := boundAtCtx(t, s, "alice", "operator", "Operator", "/projects/acme")
		if err := proxySpiceAs(t, s, ctx); status.Code(err) == codes.PermissionDenied {
			t.Fatalf("ProxySpice for a caller bound on acme was refused: %v", err)
		}
		deadline := time.Now().Add(2 * time.Second)
		for accepted.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if accepted.Load() == 0 {
			t.Error("a caller with vm.console on desk never reached the SPICE listener")
		}
	})
}
