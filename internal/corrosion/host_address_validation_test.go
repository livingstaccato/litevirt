package corrosion

import (
	"context"
	"testing"
)

// TestValidHostAddress is the second half of the `lv host add` injection fix.
//
// Quoting the remote command line stops the shell executing hosts.address, but
// the column should never have held a shell payload in the first place. The
// cluster transport is IPv4-only and the daemon already refuses to start on a
// hostname, a host:port or IPv6 — so requiring a bare IPv4 literal at the write
// costs nothing and removes the class.
func TestValidHostAddress(t *testing.T) {
	valid := []string{"10.0.0.1", "192.168.1.254", "127.0.0.1", "0.0.0.0"}
	for _, a := range valid {
		if !ValidHostAddress(a) {
			t.Errorf("ValidHostAddress(%q) = false, want true", a)
		}
	}
	invalid := []string{
		"",
		"$(touch /tmp/pwned)",
		"10.0.0.1`id`",
		"10.0.0.1; rm -rf /",
		"10.0.0.1 10.0.0.2",
		"node-1.example.com", // hostname: transport is IPv4-only
		"10.0.0.1:7946",      // host:port
		"::1",                // IPv6
		"fe80::1",
		"10.0.0.1\nHOST_NAME=evil",
	}
	for _, a := range invalid {
		if ValidHostAddress(a) {
			t.Errorf("ValidHostAddress(%q) = true, want false", a)
		}
	}
}

// TestAdmitHost_RefusesAnAddressThatIsNotBareIPv4 pins ValidHostAddress at
// its call site. TestValidHostAddress only proves the predicate; this proves
// AdmitHost consults it, for both a new name and the re-admission of a
// tombstone, and that a refused admission writes nothing.
func TestAdmitHost_RefusesAnAddressThatIsNotBareIPv4(t *testing.T) {
	ctx := context.Background()
	payloads := []string{
		"$(touch /tmp/pwned)",
		"10.0.0.1; rm -rf /",
		"node-1.example.com",
		"10.0.0.1:7946",
		"fe80::1",
	}

	t.Run("new host", func(t *testing.T) {
		c := newTestDB(t)
		for _, addr := range payloads {
			err := AdmitHost(ctx, c, HostRecord{
				Name: "host-new", Address: addr, SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
				State: HostStateJoining, CertSerial: readmitSerial,
			})
			if err == nil {
				t.Errorf("AdmitHost(address=%q) = nil, want a refusal", addr)
			}
		}
		rows, err := c.Query(ctx, `SELECT address FROM hosts WHERE name = 'host-new'`)
		if err != nil {
			t.Fatalf("query: %v", err)
		}
		if len(rows) != 0 {
			t.Fatalf("a refused admission wrote a hosts row with address %q", rows[0].String("address"))
		}
	})

	t.Run("re-admitting a tombstone", func(t *testing.T) {
		c := newTestDB(t)
		oldIncarnation(t, c)
		for _, addr := range payloads {
			err := AdmitHost(ctx, c, HostRecord{
				Name: "host-x", Address: addr, SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
				State: HostStateJoining, CertSerial: readmitSerial,
			})
			if err == nil {
				t.Errorf("AdmitHost(address=%q) over a tombstone = nil, want a refusal", addr)
			}
		}
		rows, err := c.Query(ctx, `SELECT address, deleted_at FROM hosts WHERE name = 'host-x'`)
		if err != nil || len(rows) != 1 {
			t.Fatalf("query host-x: rows=%d err=%v", len(rows), err)
		}
		if got := rows[0].String("address"); got != "10.0.0.15" {
			t.Fatalf("a refused re-admission rewrote hosts.address to %q", got)
		}
		if rows[0].String("deleted_at") == "" {
			t.Fatal("a refused re-admission revived the tombstone")
		}
	})
}
