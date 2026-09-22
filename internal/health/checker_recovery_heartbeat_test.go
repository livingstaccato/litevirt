package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// healthUpdatedAt reads the observer's host_health row for target, or "" if
// there is none.
func healthUpdatedAt(t *testing.T, db *corrosion.Client, observer, target string) string {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT updated_at FROM host_health WHERE observer = ? AND target = ?`,
		observer, target)
	if err != nil {
		t.Fatalf("read host_health: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("updated_at")
}

// schemaDB is testDB plus the schema, which host_health lives in.
func schemaDB(t *testing.T) *corrosion.Client {
	t.Helper()
	db := testDB(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

// healthyChecker returns a Checker whose probe always succeeds.
func healthyChecker(t *testing.T, db *corrosion.Client) *Checker {
	t.Helper()
	c := NewChecker("observer-1", "/tmp/pki", db)
	c.probeFn = func(string) bool { return true }
	return c
}

// A host awaiting recovery must keep a FRESH health row while it is steadily
// healthy.
//
// checkHost persists only on transition, so a peer that comes back and then
// stays healthy writes exactly one row and never touches it again. The
// coordinator's recovery quorum only counts rows newer than
// failover.healthFreshness (30s), and its recentlyFenced suppression runs for
// 5 minutes — so by the time recovery is allowed to look, the only healthy row
// is minutes old, fails the cutoff, quorum is never met, and the host stays
// `offline` until someone runs `lv host undrain` by hand.
func TestCheckHost_OfflineHostKeepsAFreshHealthyRow(t *testing.T) {
	db := schemaDB(t)
	c := healthyChecker(t, db)

	offline := corrosion.HostRecord{
		Name: "peer-1", Address: "10.0.0.1", GRPCPort: 9000, State: "offline",
	}

	// First probe: the transition into "healthy" writes the row.
	c.checkHost(context.Background(), offline)
	first := healthUpdatedAt(t, db, "observer-1", "peer-1")
	if first == "" {
		t.Fatal("no host_health row after the first healthy probe")
	}

	// Age the local write anchor past the heartbeat so the next probe is due
	// a refresh, exactly as wall-clock time would.
	c.mu.Lock()
	c.peers["peer-1"].lastWriteAt = time.Now().Add(-2 * HeartbeatInterval)
	c.mu.Unlock()

	// Second probe: nothing has CHANGED — still healthy, still 0 failures.
	c.checkHost(context.Background(), offline)
	second := healthUpdatedAt(t, db, "observer-1", "peer-1")

	if second == first {
		t.Fatalf("updated_at stayed %q across two probes of an offline-but-healthy host; "+
			"the row ages out of the recovery freshness window and the host can never auto-recover", first)
	}
}

// The heartbeat must NOT apply to a host that is already active. Rewriting
// every healthy row on a timer is O(N^2) replication traffic across the
// cluster for no reader: recovery only ever looks at hosts in offline/fenced.
func TestCheckHost_ActiveHostDoesNotHeartbeat(t *testing.T) {
	db := schemaDB(t)
	c := healthyChecker(t, db)

	active := corrosion.HostRecord{
		Name: "peer-2", Address: "10.0.0.2", GRPCPort: 9000, State: "active",
	}

	c.checkHost(context.Background(), active)
	first := healthUpdatedAt(t, db, "observer-1", "peer-2")
	if first == "" {
		t.Fatal("no host_health row after the first healthy probe")
	}

	c.mu.Lock()
	c.peers["peer-2"].lastWriteAt = time.Now().Add(-2 * HeartbeatInterval)
	c.mu.Unlock()

	c.checkHost(context.Background(), active)
	if second := healthUpdatedAt(t, db, "observer-1", "peer-2"); second != first {
		t.Fatalf("an ACTIVE host's row was rewritten (%q -> %q) with nothing changed; "+
			"that is per-probe replication traffic no reader needs", first, second)
	}
}

// A fenced host is the other recovery-eligible state and gets the same
// treatment as offline.
func TestCheckHost_FencedHostKeepsAFreshHealthyRow(t *testing.T) {
	db := schemaDB(t)
	c := healthyChecker(t, db)

	fenced := corrosion.HostRecord{
		Name: "peer-3", Address: "10.0.0.3", GRPCPort: 9000, State: "fenced",
	}

	c.checkHost(context.Background(), fenced)
	first := healthUpdatedAt(t, db, "observer-1", "peer-3")

	c.mu.Lock()
	c.peers["peer-3"].lastWriteAt = time.Now().Add(-2 * HeartbeatInterval)
	c.mu.Unlock()

	c.checkHost(context.Background(), fenced)
	if second := healthUpdatedAt(t, db, "observer-1", "peer-3"); second == first {
		t.Fatalf("a FENCED host's healthy row stayed %q; recovery quorum will never see it fresh", first)
	}
}

// The heartbeat is a rewrite, not a re-probe: it must not fire more often than
// HeartbeatInterval, or it degenerates into writing on every 2s tick.
func TestCheckHost_HeartbeatRespectsItsInterval(t *testing.T) {
	db := schemaDB(t)
	c := healthyChecker(t, db)

	offline := corrosion.HostRecord{
		Name: "peer-4", Address: "10.0.0.4", GRPCPort: 9000, State: "offline",
	}

	c.checkHost(context.Background(), offline)
	first := healthUpdatedAt(t, db, "observer-1", "peer-4")

	// No ageing this time — the last write was moments ago.
	c.checkHost(context.Background(), offline)
	if second := healthUpdatedAt(t, db, "observer-1", "peer-4"); second != first {
		t.Fatalf("row rewritten (%q -> %q) within the heartbeat interval; "+
			"the heartbeat must be rate-limited, not every probe", first, second)
	}
}
