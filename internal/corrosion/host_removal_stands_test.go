package corrosion

import (
	"context"
	"testing"
	"time"
)

// A removal stands over a live copy of its own admission at incarnation 0,
// and decides nothing between two admissions (host_removal_stands.go).
//
// Mutations: sameLegacyAdmission returning false turns the two "stands" cases
// red; dropping its serial check turns "an unstamped re-admission" and "a
// v1.9.0 re-add over a stamped admission" red; dropping its created_at check
// turns "a re-admission's stamp" red.
func TestCompareHostKeys_ARemovalStandsOverItsAdmission(t *testing.T) {
	const stamp, later, legacy = "2026-01-01T00:00:00.000000000Z", "2026-01-02T00:00:00.000000000Z", "2026-01-01T00:00:00Z"
	for _, tc := range []struct {
		name      string
		tomb, liv hostKey
		want      int // compareHostKeys(tomb, liv)
	}{
		{"a stamped admission: the removal stands", hostKey{at: stamp, serial: "a", deleted: true}, hostKey{at: stamp, serial: "a"}, 1},
		{"a v1.9.0 re-add over a stamped admission (or a renewal): the clock decides", hostKey{at: stamp, serial: "a", deleted: true}, hostKey{at: stamp, serial: "b"}, 0},
		{"an older build's admission: the removal stands", hostKey{at: legacy, serial: "a", deleted: true}, hostKey{at: legacy, serial: "A"}, 1},
		{"an unstamped re-admission: the clock decides", hostKey{at: legacy, serial: "a", deleted: true}, hostKey{at: legacy, serial: "b"}, 0},
		{"a re-admission's stamp: the clock decides", hostKey{at: stamp, serial: "a", deleted: true}, hostKey{at: later, serial: "b"}, 0},
		{"no created_at: the clock decides", hostKey{serial: "a", deleted: true}, hostKey{serial: "a"}, 0},
	} {
		if got := compareHostKeys(tc.tomb, tc.liv); got != tc.want {
			t.Errorf("%s: compareHostKeys(tombstone, live) = %d, want %d", tc.name, got, tc.want)
		}
		if got := compareHostKeys(tc.liv, tc.tomb); got != -tc.want {
			t.Errorf("%s: compareHostKeys(live, tombstone) = %d, want %d", tc.name, got, -tc.want)
		}
	}
}

// Two tombstones of one admission under one clock converge by content-max;
// two naming different certificates are left to the carve-out.
//
// Mutation: the hosts chain without ruleRemovedAdmission turns "a state
// apart" unresolved.
func TestHostsTieChain_TombstonesOfOneAdmission(t *testing.T) {
	cols := []string{"name", "incarnation", "created_at", "cert_serial", "state", "isolation_epoch", "isolation_reason", "deleted_at", "updated_at"}
	idx := columnIndexMap(cols)
	const at, ts = "2026-01-01T00:00:00.000000000Z", "2026-01-02T00:00:00.000000000Z"
	row := func(serial, state string, epoch int64) []interface{} {
		return []interface{}{"h", int64(0), at, serial, state, epoch, "", ts, ts}
	}
	for _, tc := range []struct {
		name            string
		local, incoming []interface{}
		wantDecided     bool
	}{
		{"a state apart", row("a", "active", 0), row("a", "offline", 0), true},
		{"a serial apart", row("a", "active", 0), row("b", "active", 0), false},
	} {
		rv := rowView{cols: cols, colIdx: idx, local: tc.local, incoming: tc.incoming}
		var d tieDecision
		for _, rule := range capabilityMap["hosts"].chain {
			if d = rule(rv); d.decided {
				break
			}
		}
		if got := d.decided && !d.unresolved; got != tc.wantDecided {
			t.Errorf("%s: settled=%v (%+v), want %v", tc.name, got, d, tc.wantDecided)
		}
	}
}

// A previous build's dump carries no incarnation column: its live copy of a
// removed host's admission still does not replace the tombstone.
//
// Mutation: sameLegacyAdmission returning false turns it red.
func TestHostRemoval_StandsAgainstAPreviousBuildsDump(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	if err := InsertHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
		t.Fatal(err)
	}
	k := incKey(t, c)
	if err := DeleteHost(ctx, c, "host-x"); err != nil {
		t.Fatal(err)
	}
	stale := newTestDB(t)
	if err := InsertHost(ctx, stale, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
		t.Fatal(err)
	}
	if _, err := stale.DB().Exec(`UPDATE hosts SET created_at = ?, state = 'offline', updated_at = '2999-01-01T00:00:00.000000000Z' WHERE name = 'host-x'`, k.at); err != nil {
		t.Fatal(err)
	}
	st, ok := stale.dumpTable("hosts")
	if !ok {
		t.Fatal("dump hosts")
	}
	mergeHostsTable(t, c, withoutColumn(st, "incarnation"))
	if got := incKey(t, c); !got.deleted {
		t.Errorf("a previous build's live copy replaced the removal: %+v", got)
	}
}

// The WAL rule at incarnation 0 (hostRemovalEndsLocalAdmission): a removal
// made after the local admission's created_at applies over a later write to
// it, once host_membership_split_v1 has latched; before the latch, and for a
// removal made before the admission (or within an older build's whole
// second), the clock decides and the row stays live.
//
// Mutations: dropping the latch condition turns "before the latch" red;
// dropping the "after created_at" check turns "a removal made before the
// admission" and "within the admission's second" red; the rule always false
// turns both "after the latch" cases red.
func TestHostRemoval_WALRuleAtIncarnationZero(t *testing.T) {
	ctx := context.Background()
	const later = "2999-01-01T00:00:00.000000000Z"
	for _, tc := range []struct {
		name     string
		created  string        // "" keeps InsertHost's stamp
		removeAt time.Duration // the removal's instant, after created_at
		latched  bool
		removed  bool
	}{
		{"after the latch", "", time.Second, true, true},
		{"before the latch", "", time.Second, false, false},
		{"a removal made before the admission", "", -time.Second, true, false},
		{"an older build's row, after the latch", "2026-01-01T00:00:00Z", 2 * time.Second, true, true},
		{"within the admission's second", "2026-01-01T00:00:00Z", 500 * time.Millisecond, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTestDB(t)
			if tc.latched {
				c.SetHostMembershipGate(func() bool { return true })
			}
			if err := InsertHost(ctx, c, HostRecord{Name: "host-x", Address: "10.0.0.15", State: "active", CertSerial: "01old"}); err != nil {
				t.Fatal(err)
			}
			if tc.created != "" {
				if _, err := c.DB().Exec(`UPDATE hosts SET created_at = ? WHERE name = 'host-x'`, tc.created); err != nil {
					t.Fatal(err)
				}
			}
			// A later write to the admission: the row's clock is past the removal's.
			if _, err := c.DB().Exec(`UPDATE hosts SET state = 'offline', updated_at = ? WHERE name = 'host-x'`, later); err != nil {
				t.Fatal(err)
			}
			at, err := time.Parse(time.RFC3339, incKey(t, c).at)
			if err != nil {
				t.Fatal(err)
			}
			ts := at.Add(tc.removeAt).UTC().Format(nowTSLayout)
			applyRemote(t, c, "2999000000000-0000-remover",
				Statement{SQL: deleteHostSQL, Params: []interface{}{ts, ts, "host-x"}})
			if got := incKey(t, c).deleted; got != tc.removed {
				t.Errorf("removed = %v, want %v", got, tc.removed)
			}
		})
	}
}
