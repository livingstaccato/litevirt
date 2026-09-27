package metrics

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/prometheus/client_golang/prometheus"
)

func insertLogRowAt(t *testing.T, db *corrosion.Client, at time.Time) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT INTO mutation_log (hlc, origin, stmts, created_at) VALUES ('0','n','x', ?)`,
		at.UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert mutation_log: %v", err)
	}
}

func maxSeq(t *testing.T, db *corrosion.Client) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT COALESCE(MAX(seq),0) AS m FROM mutation_log`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("max seq: %v", err)
	}
	return rows[0].Int("m")
}

func setWatermark(t *testing.T, db *corrosion.Client, peer string, seq int, updated time.Time) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT OR REPLACE INTO replication_watermarks (peer_name, last_seq, updated_at) VALUES (?, ?, ?)`,
		peer, seq, updated.UTC().Format(time.RFC3339)); err != nil {
		t.Fatalf("insert watermark: %v", err)
	}
}

func backlogAge(t *testing.T, db *corrosion.Client) float64 {
	t.Helper()
	c := newCollector(db, nil, nil, "host-a")
	ch := make(chan prometheus.Metric, 200)
	c.Collect(ch)
	close(ch)
	got, found := gaugeValue(t, ch, "litevirt_replication_backlog_age_seconds")
	if !found {
		t.Fatal("missing litevirt_replication_backlog_age_seconds")
	}
	return got
}

// The gauge is how long the oldest un-acked entry has been waiting.
//
// pending_entries says how MUCH is queued, which is the wrong question for an
// alert: a thousand entries a second behind is healthy, and three entries an
// hour behind is a peer that has stopped acknowledging. Age answers "how stale
// is the slowest live peer's view", which is the number an operator can put a
// threshold on.
func TestCollect_BacklogAgeIsTheOldestUnackedEntry(t *testing.T) {
	db := initTestDB(t)
	// Old entries the peer HAS acknowledged: they must not count, however old.
	insertLogRowAt(t, db, time.Now().Add(-time.Hour))
	insertLogRowAt(t, db, time.Now().Add(-time.Hour))
	setWatermark(t, db, "peer-a", maxSeq(t, db), time.Now())
	// The oldest entry the peer has NOT acknowledged is five minutes old.
	insertLogRowAt(t, db, time.Now().Add(-5*time.Minute))
	insertLogRowAt(t, db, time.Now().Add(-time.Minute))

	got := backlogAge(t, db)

	if got < 290 || got > 330 {
		t.Errorf("backlog age = %.0fs, want ~300s — the oldest UN-ACKED entry, not the oldest in the log (3600s) "+
			"and not the newest (60s)", got)
	}
}

// Caught up is zero, however old the log itself is. The log is retained past
// acknowledgement for pruning, so its oldest row says nothing about lag.
func TestCollect_BacklogAgeIsZeroWhenCaughtUp(t *testing.T) {
	db := initTestDB(t)
	insertLogRowAt(t, db, time.Now().Add(-time.Hour))
	setWatermark(t, db, "peer-a", maxSeq(t, db), time.Now())

	// Not exactly 0: the watermark write above is itself a replicated write, so
	// it lands in mutation_log a moment after the seq it acknowledges and is
	// genuinely un-acked. What this pins is that the hour-old acknowledged row
	// does not count — 3600 against a few seconds.
	if got := backlogAge(t, db); got > 60 {
		t.Errorf("backlog age = %.0fs with the old entry acknowledged, want ~0 — the log's oldest row is not lag", got)
	}
}

// With no LIVE peer there is nobody to be behind, so a single or fully
// partitioned node does not report its whole log as lag — the same rule
// pending_entries follows.
func TestCollect_BacklogAgeIsZeroWithNoLivePeers(t *testing.T) {
	db := initTestDB(t)
	setWatermark(t, db, "gone", 0, time.Now().Add(-2*corrosion.LiveWatermarkWindow))
	insertLogRowAt(t, db, time.Now().Add(-time.Hour))

	if got := backlogAge(t, db); got != 0 {
		t.Errorf("backlog age = %.0fs with only a stale watermark, want 0", got)
	}
}

// The SLOWEST live peer decides it. A fast peer being caught up does not make
// the slow one's backlog disappear.
func TestCollect_BacklogAgeFollowsTheSlowestLivePeer(t *testing.T) {
	db := initTestDB(t)
	setWatermark(t, db, "slow", maxSeq(t, db), time.Now())
	insertLogRowAt(t, db, time.Now().Add(-10*time.Minute))
	setWatermark(t, db, "fast", maxSeq(t, db), time.Now())

	got := backlogAge(t, db)

	if got < 590 || got > 630 {
		t.Errorf("backlog age = %.0fs, want ~600s — the slow peer has not acked the 10-minute-old entry", got)
	}
}

// A peer that stops acknowledging stops updating its watermark row, so after
// LiveWatermarkWindow it falls out of the "live" set — and a gauge computed
// over live rows dropped back to 0, resolving the very alert it is documented
// for while the peer was still wedged. The peers the replicator is actively
// pushing to are the set that is behind, however stale their rows look.
func TestCollect_BacklogAgeKeepsCountingAPeerThatStoppedAcking(t *testing.T) {
	db := initTestDB(t)
	setWatermark(t, db, "peer-b", 0, time.Now().Add(-2*time.Hour)) // last ack two hours ago
	insertLogRowAt(t, db, time.Now().Add(-time.Hour))              // waiting an hour

	c := newCollector(db, nil, nil, "host-a")
	c.replicationTargets = func() []string { return []string{"peer-b"} }
	ch := make(chan prometheus.Metric, 200)
	c.Collect(ch)
	close(ch)
	got, found := gaugeValue(t, ch, "litevirt_replication_backlog_age_seconds")
	if !found {
		t.Fatal("missing litevirt_replication_backlog_age_seconds")
	}
	if got < 3500 {
		t.Errorf("backlog age = %.0fs with a replication target an hour behind; want ~3600s — "+
			"the gauge went quiet because the stuck peer's watermark row aged out", got)
	}
}
