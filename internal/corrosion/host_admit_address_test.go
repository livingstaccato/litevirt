package corrosion

import (
	"context"
	"strings"
	"testing"
)

// Codex cand30 I1: AdmitHost's address check (grpcapi) read the hosts table
// before, and apart from, the admission write, so two admissions of distinct
// names at one address could both pass it and both commit. Each admission
// write applies now only if, in its own transaction, no other live or joining
// host holds the address at the admitted port: a fresh insert, a legacy
// re-admission and an incarnation-issuing one.
//
// Mutation: drop the guard from any one write — its case admits a second
// name at the address.
func TestAdmitHost_TheWriteRefusesAnAddressAnotherHostHolds(t *testing.T) {
	ctx := context.Background()
	held := HostRecord{Name: "other", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "ffee"}
	for _, tc := range []struct {
		name  string
		admit func(t *testing.T, c *Client) error
	}{
		{"insert", func(t *testing.T, c *Client) error {
			return AdmitHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22,
				GRPCPort: 7443, State: HostStateJoining, CertSerial: incSerialA})
		}},
		{"legacy re-admission", func(t *testing.T, c *Client) error {
			oldIncarnation(t, c)
			return AdmitHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22,
				GRPCPort: 7443, State: HostStateJoining, CertSerial: incSerialA})
		}},
		{"re-admission at the next incarnation", func(t *testing.T, c *Client) error {
			oldIncarnation(t, c)
			_, _, err := AdmitHostV2(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", SSHUser: "root",
				SSHPort: 22, GRPCPort: 7443, State: HostStateJoining, CertSerial: incSerialA}, incGrant(t))
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			// Inserted directly: the row arrived from a peer, or was admitted
			// after this admission's own checks had read the table.
			if err := InsertHost(ctx, c, held); err != nil {
				t.Fatal(err)
			}
			err := tc.admit(t, c)
			if err == nil || !strings.Contains(err.Error(), "other") {
				t.Fatalf("admission at an address other holds = %v, want a refusal naming it", err)
			}
			if holder, ok := AsAddressHeld(err); !ok || holder != "other" {
				t.Errorf("refusal %v does not carry the holder", err)
			}
			rows, err := c.Query(ctx, `SELECT name FROM hosts WHERE address = '10.0.0.15' AND deleted_at IS NULL`)
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 1 || rows[0].String("name") != "other" {
				t.Errorf("live hosts at the address after the refusal: %v", rows)
			}
			ml, err := c.Query(ctx, `SELECT stmts FROM mutation_log WHERE stmts LIKE '%`+incSerialA+`%'`)
			if err != nil {
				t.Fatal(err)
			}
			if len(ml) != 0 {
				t.Errorf("the refused admission was logged for peers: %v", ml)
			}
		})
	}
}

// The guard keeps what the address check allowed: a removed host's address,
// and one held at another gRPC port (several daemons on one machine, as the
// fleet tests run them).
//
// Mutation: drop deleted_at or the port from the guard — a case is refused.
func TestAdmitHost_TheWriteTakesAnAddressNoLiveHostHoldsAtThePort(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		port    int
		removed bool
	}{
		{"removed", 7443, true},
		{"another port", 7500, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			if err := InsertHost(ctx, c, HostRecord{Name: "other", Address: "10.0.0.15", GRPCPort: tc.port,
				State: "active", CertSerial: "ffee"}); err != nil {
				t.Fatal(err)
			}
			if tc.removed {
				if err := DeleteHost(ctx, c, "other"); err != nil {
					t.Fatal(err)
				}
			}
			if err := AdmitHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", SSHUser: "root", SSHPort: 22,
				GRPCPort: 7443, State: HostStateJoining, CertSerial: incSerialA}); err != nil {
				t.Fatalf("admit = %v, want it admitted", err)
			}
		})
	}
}
