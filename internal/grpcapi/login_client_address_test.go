package grpcapi

import (
	"context"
	"net"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func loopbackOrRemoteCtx(addr string) context.Context {
	host, _, _ := net.SplitHostPort(addr)
	return peer.NewContext(context.Background(), &peer.Peer{Addr: &net.TCPAddr{IP: net.ParseIP(host), Port: 40000}})
}

func sessionIP(t *testing.T, s *Server, ctx context.Context, claimed string) string {
	t.Helper()
	resp, err := s.Login(ctx, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: claimed})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	sess, err := corrosion.GetSession(context.Background(), s.db, strings.TrimPrefix(resp.Token, SessionTokenPrefix))
	if err != nil || sess == nil {
		t.Fatalf("GetSession: %v", err)
	}
	return sess.IP
}

// O2: the web UI reaches the daemon over 127.0.0.1, so every UI session
// recorded that. A loopback caller (this node's UI or REST gateway) passes the
// browser's address and the session records it; nobody else can name one.
func TestLogin_RecordsClientAddressOnlyFromLoopback(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")

	if got := sessionIP(t, s, loopbackOrRemoteCtx("127.0.0.1:1"), "203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("loopback caller passing the browser's address: session ip %q, want 203.0.113.7", got)
	}
	if got := sessionIP(t, s, loopbackOrRemoteCtx("198.51.100.9:1"), "203.0.113.7"); got != "198.51.100.9" {
		t.Errorf("remote caller naming an address: session ip %q, want its own 198.51.100.9", got)
	}
	if got := sessionIP(t, s, loopbackOrRemoteCtx("127.0.0.1:1"), "not-an-ip"); got != "127.0.0.1" {
		t.Errorf("loopback caller passing a non-address: session ip %q, want 127.0.0.1", got)
	}
	if got := sessionIP(t, s, loopbackOrRemoteCtx("127.0.0.1:1"), ""); got != "127.0.0.1" {
		t.Errorf("loopback caller passing nothing: session ip %q, want 127.0.0.1", got)
	}
}

// The login throttle keys on the same address, so one browser's failures
// through the UI no longer lock the account out of the UI for every browser.
func TestLogin_ThrottleKeysOnForwardedClientAddress(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	seedUser(t, s, "alice", "viewer", "hunter2")
	ui := loopbackOrRemoteCtx("127.0.0.1:1")
	for i := 0; i < defaultLoginMaxFailures; i++ {
		_, _ = s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "wrong", ClientAddress: "203.0.113.66"})
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "203.0.113.66"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("the failing browser: got %v, want ResourceExhausted", err)
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "203.0.113.7"}); err != nil {
		t.Fatalf("another browser through the same UI was locked out: %v", err)
	}
}
