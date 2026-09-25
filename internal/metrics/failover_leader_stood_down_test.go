package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// litevirt_failover_leader must say whether this host is the leader, not
// whether its own leader_election row still names it. After a contested lease
// converges, the losing claimant's row keeps naming it until it expires (up to
// one TTL — its peer's renewals are no-ops against a live row), while the term
// ledger already names the winner's fresh term. For that window the gauge
// reported two leaders.
func TestFailoverLeaderGauge_AStoodDownClaimantIsNotTheLeader(t *testing.T) {
	for _, tc := range []struct {
		name         string
		newestHolder string
		want         float64
	}{
		{"the ledger's newest term is ours", "host-a", 1},
		{"the ledger's newest term is another host's", "host-b", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testDB(t)
			ctx := context.Background()
			if err := corrosion.InitSchema(ctx, db); err != nil {
				t.Fatalf("InitSchema: %v", err)
			}
			now := time.Now().UTC()
			ts := now.Format(time.RFC3339)
			if err := db.Execute(ctx,
				`INSERT INTO leader_election (key, holder, expires_at, updated_at) VALUES (?, ?, ?, ?)`,
				corrosion.LeaseKeyFailover, "host-a", now.Add(40*time.Second).Format(time.RFC3339), ts); err != nil {
				t.Fatalf("seed lease row: %v", err)
			}
			for term, holder := range map[int64]string{1: "host-a", 2: tc.newestHolder} {
				if err := db.Execute(ctx,
					`INSERT INTO leader_lease_terms (key, term, holder, acquired_at, created_at, updated_at)
					 VALUES (?, ?, ?, ?, ?, ?)`,
					corrosion.LeaseKeyFailover, term, holder, ts, ts, db.NowTS()); err != nil {
					t.Fatalf("seed term %d: %v", term, err)
				}
			}

			c := newCollector(db, nil, nil, "host-a")
			ch := make(chan prometheus.Metric, 200)
			c.Collect(ch)
			close(ch)

			got, found := 0.0, false
			for m := range ch {
				if m.Desc() != c.leaderHolder {
					continue
				}
				var pb dto.Metric
				if err := m.Write(&pb); err != nil {
					t.Fatal(err)
				}
				got, found = pb.GetGauge().GetValue(), true
			}
			if !found {
				t.Fatal("litevirt_failover_leader not emitted")
			}
			if got != tc.want {
				t.Fatalf("litevirt_failover_leader = %v, want %v (lease row names host-a; ledger's newest term names %s)",
					got, tc.want, tc.newestHolder)
			}
		})
	}
}
