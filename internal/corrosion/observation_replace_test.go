package corrosion

import (
	"context"
	"testing"
)

// The checker's two verdict shapes (health/checker.go), exactly as it sends
// them: the ledger knows both, so a receiver applies them.
const (
	testHealthyVerdictSQL = `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, 0, ?, ?)`
	testUnhealthyVerdictSQL = `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`
)

func healthRowState(t *testing.T, c *Client) (status, deletedAt, updatedAt string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT status, COALESCE(deleted_at, '') AS d, updated_at FROM host_health WHERE observer = 'o' AND target = 'd'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read host_health: %d rows, %v", len(rows), err)
	}
	return rows[0].String("status"), rows[0].String("d"), rows[0].String("updated_at")
}

// A verdict published over a removal's tombstone is live on a receiver, as it
// is on its observer, whose INSERT OR REPLACE replaced the whole row. A
// receiver kept the tombstone, so the observer's verdicts on a host re-added
// under a removed name stayed deleted everywhere else.
//
// Mutation: applying the plain upsert (no deleted_at = NULL) leaves the
// receiver's row deleted after both verdict shapes.
func TestReplicatedHealthVerdictClearsTheTombstoneItSupersedes(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		sql  string
		args func(c *Client) []interface{}
	}{
		{"healthy", testHealthyVerdictSQL, func(c *Client) []interface{} {
			return []interface{}{"o", "d", "healthy", c.NowWall(), c.NowTS()}
		}},
		{"suspect", testUnhealthyVerdictSQL, func(c *Client) []interface{} {
			return []interface{}{"o", "d", "suspect", 3, nil, c.NowTS()}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src, dst := newTestDB(t), newTestDB(t)
			if err := src.Execute(ctx, tc.sql, tc.args(src)...); err != nil {
				t.Fatal(err)
			}
			// DeleteHost's tombstone of every row about the host.
			if err := src.Execute(ctx, `UPDATE host_health SET deleted_at = ?, updated_at = ? WHERE observer = ? OR target = ?`,
				"2026-01-01T00:00:00Z", src.NowTS(), "d", "d"); err != nil {
				t.Fatal(err)
			}
			if _, err := shipWAL(t, src, dst, 0); err != nil {
				t.Fatalf("ship: %v", err)
			}
			if _, del, _ := healthRowState(t, dst); del == "" {
				t.Fatal("fixture: the receiver does not hold the tombstone")
			}
			seq := lastWALSeq(t, src)
			if err := src.Execute(ctx, tc.sql, tc.args(src)...); err != nil {
				t.Fatal(err)
			}
			if _, err := shipWAL(t, src, dst, seq); err != nil {
				t.Fatalf("ship the verdict: %v", err)
			}
			ws, wd, wu := healthRowState(t, src)
			gs, gd, gu := healthRowState(t, dst)
			if wd != "" {
				t.Fatalf("fixture: the observer's own row is deleted (%q)", wd)
			}
			if gd != "" || gs != ws || gu != wu {
				t.Fatalf("receiver holds status=%q deleted_at=%q updated_at=%q; the observer holds %q, live, at %q",
					gs, gd, gu, ws, wu)
			}
		})
	}
}

// A verdict the removal superseded does not bring the row back: the LWW gate
// skips it before the apply form matters.
func TestReplicatedHealthVerdictOlderThanTheTombstoneStaysDeleted(t *testing.T) {
	ctx := context.Background()
	src, dst := newTestDB(t), newTestDB(t)
	old := src.NowTS()
	if err := src.Execute(ctx, testUnhealthyVerdictSQL, "o", "d", "suspect", 3, nil, old); err != nil {
		t.Fatal(err)
	}
	// The receiver has the removal already, newer than the verdict.
	if err := dst.Execute(ctx, `INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at, deleted_at)
		VALUES ('o', 'd', 'suspect', 2, NULL, ?, '2026-01-01T00:00:00Z')`, dst.NowTS()); err != nil {
		t.Fatal(err)
	}
	if _, err := shipWAL(t, src, dst, 0); err != nil {
		t.Fatalf("ship: %v", err)
	}
	if _, del, _ := healthRowState(t, dst); del == "" {
		t.Fatal("a verdict older than the removal brought the row back")
	}
}

func TestReplacedObservationApply_OnlyHostHealthReplaceWithoutDeletedAt(t *testing.T) {
	pk := []string{"observer", "target"}
	shape := func(sql string) StmtShape {
		sh, err := parseStmtShape(sql, pk)
		if err != nil {
			t.Fatal(err)
		}
		return sh
	}
	const upsert = "INSERT INTO host_health (...) VALUES (...) ON CONFLICT(observer, target) DO UPDATE SET status = excluded.status"
	if got := replacedObservationApply("host_health", shape(testHealthyVerdictSQL), upsert); got != upsert+", deleted_at = NULL" {
		t.Errorf("host_health INSERT OR REPLACE: %q", got)
	}
	plain := `INSERT INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at) VALUES (?, ?, ?, 0, ?, ?)`
	if got := replacedObservationApply("host_health", shape(plain), upsert); got != upsert {
		t.Errorf("a plain INSERT, which never replaced the row on its origin, gained the clear: %q", got)
	}
	named := `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at, deleted_at) VALUES (?, ?, ?, 0, ?, ?, ?)`
	if got := replacedObservationApply("host_health", shape(named), upsert); got != upsert {
		t.Errorf("a statement naming deleted_at gained a second assignment: %q", got)
	}
	if got := replacedObservationApply("clock_skew", shape(testHealthyVerdictSQL), upsert); got != upsert {
		t.Errorf("another table gained the clear: %q", got)
	}
}
