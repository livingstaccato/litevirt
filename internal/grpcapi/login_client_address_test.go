package grpcapi

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// uiCtx is this node's web UI or REST gateway as Login sees it: the host's own
// certificate over loopback (the host row makes its CN a trusted host).
func uiCtx(t *testing.T, s *Server) context.Context {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "test-host", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	return mtlsPeerCtx("test-host", tcpAddr("127.0.0.1"), "")
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
// recorded that. This node's UI or REST gateway — a host certificate over
// loopback — passes the browser's address and the session records it.
func TestLogin_RecordsClientAddressFromTheHostIdentity(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	ui := uiCtx(t, s)

	cases := []struct{ claimed, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"::ffff:203.0.113.8", "203.0.113.8"}, // a mapped address in its IPv4 form
		{"2001:db8::7", "2001:db8::7"},
		{"not-an-ip", "127.0.0.1"},
		{"", "127.0.0.1"},
	}
	for _, c := range cases {
		if got := sessionIP(t, s, ui, c.claimed); got != c.want {
			t.Errorf("UI passing %q: session ip %q, want %q", c.claimed, got, c.want)
		}
	}
}

// I1 (round 1): nobody else can name an address — not a remote host, and not
// a loopback caller holding the distributable lv-cli certificate or none.
func TestLogin_ClientAddressIgnoredFromAnyoneButTheHostIdentity(t *testing.T) {
	s := testServer(t)
	seedUser(t, s, "alice", "viewer", "hunter2")
	_ = uiCtx(t, s) // test-host is a trusted host CN
	cases := []struct {
		name string
		ctx  context.Context
		want string
	}{
		{"the host certificate from another address", mtlsPeerCtx("test-host", tcpAddr("198.51.100.9"), ""), "198.51.100.9"},
		{"the lv-cli certificate over loopback", mtlsPeerCtx("lv-cli", tcpAddr("127.0.0.1"), ""), "127.0.0.1"},
		{"no certificate over loopback", mtlsPeerCtx("", tcpAddr("127.0.0.1"), ""), "127.0.0.1"},
	}
	for _, c := range cases {
		if got := sessionIP(t, s, c.ctx, "203.0.113.7"); got != c.want {
			t.Errorf("%s naming 203.0.113.7: session ip %q, want %q", c.name, got, c.want)
		}
	}
}

// I1: the lv-cli certificate cannot rotate a claimed address to escape the
// throttle: it is counted at its own (loopback) address.
func TestLogin_LVCLICertCannotRotateItsThrottleKey(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	seedUser(t, s, "alice", "viewer", "hunter2")
	cli := mtlsPeerCtx("lv-cli", tcpAddr("127.0.0.1"), "")
	for i := 0; i < defaultLoginMaxFailures; i++ {
		_, _ = s.Login(cli, &pb.LoginRequest{Username: "alice", Password: "wrong", ClientAddress: fmt.Sprintf("10.0.0.%d", i+1)})
	}
	if _, err := s.Login(cli, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "10.0.9.9"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("rotated claims from the lv-cli cert: got %v, want ResourceExhausted", err)
	}
}

// The login throttle keys on the same address, so one browser's failures
// through the UI no longer lock the account out of the UI for every browser.
func TestLogin_ThrottleKeysOnForwardedClientAddress(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	seedUser(t, s, "alice", "viewer", "hunter2")
	ui := uiCtx(t, s)
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

// I2: an IPv6 client counts by its /64, so rotating addresses inside one
// allocation shares one bucket.
func TestLogin_ThrottleGroupsIPv6By64(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	seedUser(t, s, "alice", "viewer", "hunter2")
	ui := uiCtx(t, s)
	for i := 0; i < defaultLoginMaxFailures; i++ {
		_, _ = s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "wrong", ClientAddress: fmt.Sprintf("2001:db8:1:2::%x", i+1)})
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "2001:db8:1:2:ffff::9"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("another address in the same /64: got %v, want ResourceExhausted", err)
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "2001:db8:1:3::1"}); err != nil {
		t.Fatalf("a different /64 was locked out: %v", err)
	}
}

// I2: failures spread over many addresses still meet a per-account ceiling,
// which locks only that account.
func TestLogin_ThrottleHasAPerAccountCeiling(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	seedUser(t, s, "alice", "viewer", "hunter2")
	seedUser(t, s, "bob", "viewer", "hunter2")
	ui := uiCtx(t, s)
	for i := 0; i < defaultLoginAccountMaxFailures; i++ {
		// Each address stays under its own bound.
		_, _ = s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "wrong", ClientAddress: fmt.Sprintf("198.51.%d.%d", i/200, i%200+1)})
	}
	_, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "203.0.113.200"})
	if status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("alice after %d failures from distinct addresses: got %v, want ResourceExhausted", defaultLoginAccountMaxFailures, err)
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "bob", Password: "hunter2", ClientAddress: "203.0.113.200"}); err != nil {
		t.Fatalf("another account was locked by alice's ceiling: %v", err)
	}
}

// I2: the owner's successful login between guesses does not reset the
// account ceiling, so an attacker cannot ride on it.
func TestLogin_AccountCeilingSurvivesASuccess(t *testing.T) {
	s := testServer(t)
	s.loginThrottle = newLoginThrottle()
	seedUser(t, s, "alice", "viewer", "hunter2")
	ui := uiCtx(t, s)
	for i := 0; i < defaultLoginAccountMaxFailures-1; i++ {
		_, _ = s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "wrong", ClientAddress: fmt.Sprintf("198.51.100.%d", i+1)})
	}
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "203.0.113.5"}); err != nil {
		t.Fatalf("the owner, under the ceiling: %v", err)
	}
	_, _ = s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "wrong", ClientAddress: "198.51.100.250"})
	if _, err := s.Login(ui, &pb.LoginRequest{Username: "alice", Password: "hunter2", ClientAddress: "203.0.113.6"}); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("after the ceiling's last failure: got %v, want ResourceExhausted", err)
	}
}
