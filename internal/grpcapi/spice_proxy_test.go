package grpcapi

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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
