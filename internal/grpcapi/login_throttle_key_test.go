package grpcapi

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc/peer"
)

func ctxFromAddr(t *testing.T, addr string) context.Context {
	t.Helper()
	a, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		t.Fatalf("resolve %s: %v", addr, err)
	}
	return peer.NewContext(context.Background(), &peer.Peer{Addr: a})
}

// The brute-force lockout exists so a password cannot be ground out. It is keyed
// on (username, client address) — and the address came from Addr.String(), which
// on TCP is "IP:PORT". Every reconnect gets a fresh ephemeral source port and
// therefore a fresh bucket, so an attacker who opens a new connection per attempt
// never accumulates failures and the limit never engages.
func TestThrottleClientIP_IgnoresTheEphemeralSourcePort(t *testing.T) {
	first := throttleClientIP(ctxFromAddr(t, "203.0.113.7:54321"))
	second := throttleClientIP(ctxFromAddr(t, "203.0.113.7:54322"))

	if first != second {
		t.Fatalf("two connections from one host keyed differently (%q vs %q) — each reconnect "+
			"starts a fresh lockout bucket, so the limit never engages against an attacker "+
			"who opens a new connection per attempt", first, second)
	}
	if first == "" {
		t.Fatal("the key is empty, which collapses every host into one bucket instead")
	}
}

// A different host must still key differently, or one attacker locks everyone out.
func TestThrottleClientIP_SeparatesDifferentHosts(t *testing.T) {
	a := throttleClientIP(ctxFromAddr(t, "203.0.113.7:54321"))
	b := throttleClientIP(ctxFromAddr(t, "198.51.100.9:54321"))
	if a == b {
		t.Fatalf("two different hosts share a lockout bucket (%q) — one attacker could lock "+
			"out an innocent client", a)
	}
}

// End to end through the real throttle: failures from one port must count
// against an attempt from another.
func TestLoginThrottle_FailuresAccumulateAcrossReconnects(t *testing.T) {
	s := gateTestServer(t)
	s.loginThrottle = newLoginThrottle()
	key1 := loginThrottleKey("alice", throttleClientIP(ctxFromAddr(t, "203.0.113.7:40001")))
	for i := 0; i < 12; i++ {
		s.loginThrottle.fail(key1)
	}
	key2 := loginThrottleKey("alice", throttleClientIP(ctxFromAddr(t, "203.0.113.7:40002")))

	if wait := s.loginThrottle.retryAfter(key2); wait <= 0 {
		t.Fatalf("a reconnect from the same host was not locked out (retryAfter=%v) after "+
			"12 failures — the lockout is defeated by opening a new connection", time.Duration(wait))
	}
}

// An address with no port — a Unix socket, or anything non-TCP — must still
// separate one caller from another. Collapsing it to "" would put every such
// caller in ONE bucket, so a single attacker could lock out everybody at once:
// the opposite failure to the one above, and worse.
func TestThrottleClientIP_KeepsAnUnparseableAddressDistinct(t *testing.T) {
	mk := func(path string) context.Context {
		return peer.NewContext(context.Background(),
			&peer.Peer{Addr: &net.UnixAddr{Name: path, Net: "unix"}})
	}
	a := throttleClientIP(mk("/run/litevirt/a.sock"))
	b := throttleClientIP(mk("/run/litevirt/b.sock"))

	if a == "" || b == "" {
		t.Fatalf("an address without a port keyed as empty (%q, %q) — every such caller "+
			"shares one lockout bucket, so one attacker locks out all of them", a, b)
	}
	if a == b {
		t.Fatalf("two distinct addresses share a bucket (%q)", a)
	}
}
