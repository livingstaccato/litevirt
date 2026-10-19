package corrosion

import (
	"context"
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func repointFixture(t *testing.T) (*Client, context.Context) {
	t.Helper()
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`INSERT INTO ip_allocations
		(network, ip, mac, vm_name, owner_kind, owner_host, netbox_ip_id, netbox_prefix_id, allocated_at, updated_at)
		VALUES ('bound', '10.0.5.9', '52:54:00:00:00:01', 'vm-1', 'vm', '', 41, 7, '2026-10-18T00:00:00Z', '1')`); err != nil {
		t.Fatal(err)
	}
	return c, ctx
}

func leaseNetBoxID(t *testing.T, c *Client) int {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT COALESCE(netbox_ip_id, 0) AS id FROM ip_allocations WHERE network = 'bound' AND ip = '10.0.5.9'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read lease: rows=%d err=%v", len(rows), err)
	}
	return rows[0].Int("id")
}

func TestRepointNetBoxLeaseRefusesUntilTheGateOpens(t *testing.T) {
	c, ctx := repointFixture(t)
	if _, err := RepointNetBoxLease(ctx, c, "bound", "10.0.5.9", 41, 77); !errors.Is(err, ErrNetBoxRepointGateClosed) {
		t.Fatalf("err = %v, want ErrNetBoxRepointGateClosed before netbox_ip_repoint_v1 latches", err)
	}
	c.SetNetBoxRepointGate(func() bool { return false })
	if _, err := RepointNetBoxLease(ctx, c, "bound", "10.0.5.9", 41, 77); !errors.Is(err, ErrNetBoxRepointGateClosed) {
		t.Fatalf("err = %v with the gate reading false", err)
	}
	if got := leaseNetBoxID(t, c); got != 41 {
		t.Fatalf("lease names %d after a refused re-point, want 41 untouched", got)
	}
}

func TestRepointNetBoxLeaseMovesOnlyFromTheDeadID(t *testing.T) {
	c, ctx := repointFixture(t)
	c.SetNetBoxRepointGate(func() bool { return true })

	// From an id the lease does not name: nothing moves.
	if moved, err := RepointNetBoxLease(ctx, c, "bound", "10.0.5.9", 40, 77); err != nil || moved {
		t.Fatalf("re-point from a stale id: moved=%v err=%v, want false and nothing changed", moved, err)
	}
	if got := leaseNetBoxID(t, c); got != 41 {
		t.Fatalf("lease names %d, want 41", got)
	}

	if moved, err := RepointNetBoxLease(ctx, c, "bound", "10.0.5.9", 41, 77); err != nil || !moved {
		t.Fatalf("re-point: moved=%v err=%v", moved, err)
	}
	if got := leaseNetBoxID(t, c); got != 77 {
		t.Fatalf("lease names %d after the re-point, want 77", got)
	}
}

func TestRepointNetBoxLeaseLeavesAReleasedLeaseAlone(t *testing.T) {
	c, ctx := repointFixture(t)
	c.SetNetBoxRepointGate(func() bool { return true })
	if _, err := c.db.Exec(`UPDATE ip_allocations SET deleted_at = '2026-10-18T00:00:01Z'
		WHERE network = 'bound' AND ip = '10.0.5.9'`); err != nil {
		t.Fatal(err)
	}
	if moved, err := RepointNetBoxLease(ctx, c, "bound", "10.0.5.9", 41, 77); err != nil || moved {
		t.Fatalf("re-point of a released lease: moved=%v err=%v, want false", moved, err)
	}
	if got := leaseNetBoxID(t, c); got != 41 {
		t.Fatalf("a released lease was re-pointed to %d", got)
	}
}

// TestRepointGuardedOutIsNotRelayedToALaggingPeer: the origin has already
// applied the lease's release, so its re-point matches nothing. A peer that has
// not received the release yet still holds the lease live under the dead id,
// and would apply a relayed re-point, after which LWW keeps it over the
// release. A guarded-out re-point must therefore never reach mutation_log.
func TestRepointGuardedOutIsNotRelayedToALaggingPeer(t *testing.T) {
	ctx := context.Background()
	origin, _ := repointFixture(t)
	if _, err := origin.db.Exec(`UPDATE ip_allocations SET deleted_at = '2026-10-18T00:00:01Z'
		WHERE network = 'bound' AND ip = '10.0.5.9'`); err != nil {
		t.Fatal(err)
	}
	origin.SetNetBoxRepointGate(func() bool { return true })
	if moved, err := RepointNetBoxLease(ctx, origin, "bound", "10.0.5.9", 41, 77); err != nil || moved {
		t.Fatalf("re-point of a released lease: moved=%v err=%v, want false", moved, err)
	}

	lagging, _ := repointFixture(t) // still holds the lease live, under 41
	rows, err := origin.Query(ctx, `SELECT seq, hlc, origin, stmts FROM mutation_log ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	var entries []*pb.MutationEntry
	for _, r := range rows {
		entries = append(entries, &pb.MutationEntry{
			Seq: int64(r.Int("seq")), Hlc: r.String("hlc"), Origin: r.String("origin"), Stmts: r.String("stmts"),
		})
	}
	if len(entries) > 0 {
		if _, err := NewReplicator(lagging, "", RelayConfig{}).ApplyRemoteMutations(ctx, entries); err != nil {
			t.Fatalf("apply the origin's stream on the lagging peer: %v", err)
		}
	}
	if got := leaseNetBoxID(t, lagging); got != 41 {
		t.Fatalf("the lagging peer's lease names %d: a re-point its origin reported as not made "+
			"was relayed and applied (%d mutation_log row(s))", got, len(entries))
	}
}
