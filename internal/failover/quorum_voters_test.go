package failover

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// colonelpanik/litevirt#251: the fence and recovery quorums take their
// numerator and their denominator from ONE voter set (corrosion.VoterSet). The
// denominator was always the voting-eligible hosts; the numerator was every
// distinct observer name on a fresh host_health row, joined to nothing. So a
// row from a host that is not a voter — fenced, deleted, never admitted, or the
// target reporting on itself — could supply the vote that tipped a fence.
//
// Each fixture is five voters (coordinator, h1, h2, h3 and the target), so
// quorum is 3. Two honest observers plus one row from a non-voter is exactly
// one short, and the non-voter's row must not make up the difference. The
// "honest majority" case pins that the same fixture does fence with a third
// real voter, so every refusal below is the voter filter's doing.

// voterFixture builds the cluster shared by the fence and recovery cases: four
// active voters plus the target, a fenced host and a deleted one.
func voterFixture(t *testing.T, db *corrosion.Client, target, targetState string) {
	t.Helper()
	ctx := context.Background()
	for _, n := range []string{"coordinator", "h1", "h2", "h3"} {
		ensureObserverHost(t, db, n)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: target, Address: "10.0.8.1", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: targetState, FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatalf("InsertHost %s: %v", target, err)
	}
	// A fenced host that is still running and still probing its peers.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "fenced-obs", Address: "10.0.8.2", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "fenced", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost fenced-obs: %v", err)
	}
	// A host removed from the cluster whose daemon was never stopped.
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "deleted-obs", Address: "10.0.8.3", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "manual",
	}); err != nil {
		t.Fatalf("InsertHost deleted-obs: %v", err)
	}
	if err := corrosion.DeleteHost(ctx, db, "deleted-obs"); err != nil {
		t.Fatalf("DeleteHost deleted-obs: %v", err)
	}
}

// writeHealthRow writes one fresh host_health row without registering the
// observer as a host (downObservers/healthyObservers do register it, which is
// exactly what these cases must avoid).
func writeHealthRow(t *testing.T, db *corrosion.Client, observer, target, status string, failures int) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health
		 (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, ?, ?, ?, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`,
		observer, target, status, failures); err != nil {
		t.Fatalf("insert health %s->%s: %v", observer, target, err)
	}
}

var nonVoterCases = []struct {
	name     string
	observer string // "" means the target itself
}{
	{"fenced observer", "fenced-obs"},
	{"deleted observer", "deleted-obs"},
	{"observer not in hosts", "ghost"},
	{"target observing itself", ""},
}

func TestFenceQuorum_CountsVotersOnly(t *testing.T) {
	const target = "bad"

	t.Run("honest majority fences", func(t *testing.T) {
		db := newTestDB(t)
		voterFixture(t, db, target, "active")
		for _, o := range []string{"h1", "h2", "h3"} {
			writeHealthRow(t, db, o, target, "suspect", offlineThreshold)
		}
		newTestCoordinator("coordinator", db).run(context.Background())
		if h, _ := corrosion.GetHost(context.Background(), db, target); h == nil || h.State != "fenced" {
			t.Fatalf("three of five voters report %s down: want fenced, got %+v", target, h)
		}
	})

	for _, tc := range nonVoterCases {
		t.Run(tc.name+" cannot supply the deciding vote", func(t *testing.T) {
			db := newTestDB(t)
			voterFixture(t, db, target, "active")
			observer := tc.observer
			if observer == "" {
				observer = target
			}
			writeHealthRow(t, db, "h1", target, "suspect", offlineThreshold)
			writeHealthRow(t, db, "h2", target, "suspect", offlineThreshold)
			writeHealthRow(t, db, observer, target, "suspect", offlineThreshold)

			newTestCoordinator("coordinator", db).run(context.Background())
			if h, _ := corrosion.GetHost(context.Background(), db, target); h == nil || h.State != "active" {
				t.Fatalf("two voters plus a row from %q is below quorum (3 of 5): "+
					"want %s still active, got %+v", observer, target, h)
			}
		})
	}
}

func TestRecoveryQuorum_CountsVotersOnly(t *testing.T) {
	// The target is 'offline', so it is not a voter: four voters, quorum 3.
	const target = "rec"

	t.Run("honest majority recovers", func(t *testing.T) {
		db := newTestDB(t)
		voterFixture(t, db, target, "offline")
		for _, o := range []string{"h1", "h2", "h3"} {
			writeHealthRow(t, db, o, target, "healthy", 0)
		}
		newTestCoordinator("coordinator", db).run(context.Background())
		if h, _ := corrosion.GetHost(context.Background(), db, target); h == nil || h.State != "active" {
			t.Fatalf("three of four voters report %s healthy: want active, got %+v", target, h)
		}
	})

	for _, tc := range nonVoterCases {
		t.Run(tc.name+" cannot supply the deciding vote", func(t *testing.T) {
			db := newTestDB(t)
			voterFixture(t, db, target, "offline")
			observer := tc.observer
			if observer == "" {
				observer = target
			}
			writeHealthRow(t, db, "h1", target, "healthy", 0)
			writeHealthRow(t, db, "h2", target, "healthy", 0)
			writeHealthRow(t, db, observer, target, "healthy", 0)

			newTestCoordinator("coordinator", db).run(context.Background())
			if h, _ := corrosion.GetHost(context.Background(), db, target); h == nil || h.State != "offline" {
				t.Fatalf("two voters plus a row from %q is below quorum (3 of 4): "+
					"want %s still offline, got %+v", observer, target, h)
			}
		})
	}
}

// A voter set that cannot be read is no voters: the cycle stops at the quorum
// phase, counted as a store error, before any observation is weighed.
func TestFenceQuorum_VoterSetReadErrorFailsClosed(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	voterFixture(t, db, "bad", "active")
	for _, o := range []string{"h1", "h2", "h3"} {
		writeHealthRow(t, db, o, "bad", "suspect", offlineThreshold)
	}
	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	if _, err := db.DB().ExecContext(ctx, `ALTER TABLE hosts RENAME TO hosts_gone`); err != nil {
		t.Fatalf("hide hosts: %v", err)
	}
	c.run(ctx)

	if got := fm.attempts[foKey(PhaseQuorum, ResultError, ErrDBError)]; got != 1 {
		t.Errorf("quorum db-error = %d, want 1 (attempts=%v)", got, fm.attempts)
	}
	if got := fm.attempts[foKey(PhaseFence, ResultSuccess, errClassNone)]; got != 0 {
		t.Errorf("fenced with an unreadable voter set (attempts=%v)", fm.attempts)
	}
}
