package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// backdateMembership stamps every host's membership, and its hosts copy, at
// ts: no host's voting state changed during the outage the test builds.
func backdateMembership(t *testing.T, db *corrosion.Client, ts time.Time) {
	t.Helper()
	s := ts.UTC().Format(time.RFC3339Nano)
	for _, q := range []string{`UPDATE host_membership SET updated_at = ?`, `UPDATE hosts SET updated_at = ?`} {
		if err := db.Execute(context.Background(), q, s); err != nil {
			t.Fatal(err)
		}
	}
}

// deadlineScope re-reads the voter scope as the deadline's own cycle does,
// with down already fenced (the fence's cycle read it while down was active).
func deadlineScope(t *testing.T, c *Coordinator, db *corrosion.Client) {
	t.Helper()
	vr, err := corrosion.VoterRegions(context.Background(), db)
	if err != nil {
		t.Fatal(err)
	}
	c.scope = quorumView{vr: vr}
}

// skewRec is one clock_skew row.
type skewRec struct {
	observer, target string
	seconds          float64
}

// skewRow records the clock skew observer measured on target.
func skewRow(t *testing.T, db *corrosion.Client, observer, target string, seconds float64) {
	t.Helper()
	if err := db.Execute(context.Background(),
		`INSERT OR REPLACE INTO clock_skew (observer, target, skew_seconds, updated_at) VALUES (?, ?, ?, ?)`,
		observer, target, seconds, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
}

// The bridged hold is bounded (lab 1 at f9bafd75, W1 P2 and W5c). At the
// self-pause deadline, an answer since the fence that the rows have
// overwritten (a failing run begun after it) or this node's own probe answer
// holds the recovery only while it could be the host's regained majority.
// Once n−q+1 voters other than the host have failed it without a break since
// before the fence, over every voter set it may count over, it cannot have
// held a majority since, and the deadline goes ahead; the host's condition,
// raised on a clock behind the voters', "predates this outage" and limits
// nothing. With one spanning run fewer the deadline still refuses (H1, the
// host came back and fell again).
//
// Mutations: drop the noRegainSinceIn check from selfPauseStillStands'
// explicit path — "three spanning voters, a restarted non-voter" and "this
// node's probe, three other voters span" refuse; count this node's own row
// when it has probed the host since the wait began — "this node's probe, it
// is one of three" goes ahead; require one spanning run fewer (n−q) in
// noRegainSinceIn — "two spanning voters, a restarted voter" goes ahead;
// ignore clock_skew — "a spanning voter's clock is behind" goes ahead. "The
// host's clock is behind" pins that the host's own skew shifts no
// observer's run.
func TestSelfPauseExplicit_SpanningVotersBoundARestartedRunOrAProbeAnswer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spanning []string
		restart  []string
		contact  bool
		skew     []skewRec
		wantOK   bool
		wantKey  string
	}{
		{"three spanning voters, a restarted non-voter", []string{"coordinator", "alive", "v4"}, []string{"bridge"}, false, nil, true, ""},
		{"three spanning voters, a restarted voter", []string{"coordinator", "alive", "v4"}, []string{"v5"}, false, nil, true, ""},
		{"two spanning voters, a restarted voter", []string{"coordinator", "v4"}, []string{"alive"}, false, nil, false, keyRestarted},
		{"this node's probe, it is one of three", []string{"coordinator", "alive", "v4"}, nil, true, nil, false, keyContacted},
		{"this node's probe, three other voters span", []string{"coordinator", "alive", "v4", "v5"}, []string{"bridge"}, true, nil, true, ""},
		// v4's clock is 70 s behind: its run began after the fence, though
		// its last_seen reads a minute before it.
		{"a spanning voter's clock is behind", []string{"coordinator", "alive", "v4"}, []string{"bridge"}, false,
			[]skewRec{{"coordinator", "v4", 70}}, false, keyRestarted},
		{"a spanning voter's clock is behind, recorded by it", []string{"coordinator", "alive", "v4"}, []string{"bridge"}, false,
			[]skewRec{{"v4", "coordinator", 70}}, false, keyRestarted},
		// The host's own skew dates nothing here (W5c).
		{"the host's clock is behind", []string{"coordinator", "alive", "v4"}, []string{"bridge"}, false,
			[]skewRec{{"coordinator", "down", 60}, {"down", "coordinator", 60}}, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := explicitPause(t)
			c.run(ctx) // the fence, and the voter scope the deadline counts over
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil {
				t.Fatal(err)
			}
			at := time.Now().Add(-time.Minute)
			backdateMembership(t, db, at.Add(-time.Hour))
			deadlineScope(t, c, db)
			// Raised on a clock behind the voters': it predates this outage.
			pausedCondition(t, db, at.Add(-time.Hour))
			// A voter neither spanning nor restarted last answered long
			// before the fence: no voter's row is left from the fixture.
			for _, o := range []string{"coordinator", "alive", "v4", "v5"} {
				healthRow(t, db, o, "healthy", 0, at.Add(-time.Hour))
			}
			for _, o := range tc.spanning {
				failingSince(t, db, o, at.Add(-time.Minute), time.Now())
			}
			for _, o := range tc.restart {
				failingSince(t, db, o, at.Add(20*time.Second), time.Now())
			}
			for _, s := range tc.skew {
				skewRow(t, db, s.observer, s.target, s.seconds)
			}
			mono := time.Now()
			if tc.contact {
				c.LastContact = func(string) (time.Time, bool) { return mono.Add(time.Second), true }
			}
			v := c.selfPauseStillStands(ctx, h, at, mono)
			if tc.wantOK {
				if !v.ok || v.only != nil {
					t.Fatalf("deadline: %+v; want it to go ahead on everything", v)
				}
				return
			}
			if v.ok || !strings.HasPrefix(v.key, tc.wantKey) || v.bridged {
				t.Fatalf("deadline: %+v; want refused under %q, not bridged", v, tc.wantKey)
			}
		})
	}
}

// A host that has not adopted the current generation counts over the one
// before it. Generation 1 is down, coordinator, alive, v4, v5 (q = 3); the
// adopted generation 2 adds v6 (q = 4). v4, v5 and v6 spanning are n−q+1 of
// generation 2, but only two of generation 1, on which down, coordinator and
// alive are a majority: the deadline refuses until generation 1 is spanned
// too.
//
// Mutation: leave the previous generation out of regainCandidates — "only
// the adopted generation spanned" goes ahead.
func TestSelfPauseExplicit_ThePreviousGenerationMustBeSpannedToo(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spanning []string
		restart  []string
		wantOK   bool
	}{
		{"only the adopted generation spanned", []string{"v4", "v5", "v6"}, []string{"coordinator", "alive"}, false},
		{"both generations spanned", []string{"alive", "v4", "v5", "v6"}, []string{"coordinator"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := explicitPause(t)
			ensureVoter(t, db, "v6")
			writeGen(t, db, 2, "coordinator", "alive", "down", "v4", "v5", "v6")
			if err := corrosion.RecordVoterAdoption(ctx, db, 2); err != nil {
				t.Fatal(err)
			}
			c.run(ctx)
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil {
				t.Fatal(err)
			}
			at := time.Now().Add(-time.Minute)
			backdateMembership(t, db, at.Add(-time.Hour))
			deadlineScope(t, c, db)
			if v := c.scope.voters("down"); len(v) != 6 {
				t.Fatalf("setup: the deadline counts over %v, not generation 2", v)
			}
			pausedCondition(t, db, at.Add(-time.Hour))
			for _, o := range []string{"coordinator", "alive", "v4", "v5", "v6"} {
				healthRow(t, db, o, "healthy", 0, at.Add(-time.Hour))
			}
			for _, o := range tc.spanning {
				failingSince(t, db, o, at.Add(-time.Minute), time.Now())
			}
			for _, o := range tc.restart {
				failingSince(t, db, o, at.Add(20*time.Second), time.Now())
			}
			v := c.selfPauseStillStands(ctx, h, at, time.Now())
			if v.ok != tc.wantOK || (!v.ok && !strings.HasPrefix(v.key, keyRestarted)) {
				t.Fatalf("deadline: %+v; want ok=%v (refused under %q)", v, tc.wantOK, keyRestarted)
			}
		})
	}
}

// The same bound on the derived voter set, counted as the host counts it. At
// the deadline the host is fenced, so this node's derived set (down's own
// cycle) no longer holds it; down's replica, frozen since the outage began,
// still counts itself among five. Two spanning runs are n−q+1 of the four
// this node now derives, but not of down's five: down with the two restarted
// voters is three of five, a majority it may have held and resumed on.
//
// Mutations: count over this node's derived set (drop down from
// derivedRegainCandidate's set) — "two spanning, two restarted" goes ahead;
// pass noRegain=false to quietFallback on the derived path — "three
// spanning" refuses; drop the answeredSinceIn check from its noRegain branch
// — "three spanning, the bridge still answers" goes ahead; count a voter
// whose state changed since the outage began — "two spanning, a third fenced
// since the outage began" goes ahead.
func TestSelfPauseDerived_SpanningVotersBoundARestartedRun(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spanning []string
		restart  []string
		bridge   bool   // a non-voter's latest verdict is an answer
		changed  string // a voter whose state changed since the outage began
		wantOK   bool
		wantKey  string
	}{
		{"three spanning", []string{"coordinator", "v4", "v5"}, []string{"alive"}, false, "", true, ""},
		{"two spanning, two restarted", []string{"v4", "v5"}, []string{"coordinator", "alive"}, false, "", false, keyRestarted},
		{"three spanning, the bridge still answers", []string{"coordinator", "v4", "v5"}, []string{"alive"}, true, "", false, keyAnswered},
		{"two spanning, a third fenced since the outage began", []string{"coordinator", "v4", "v5"}, []string{"alive"}, false, "v5", false, keyRestarted},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := pauseCoordinator(t, true)
			for _, v := range []string{"v4", "v5"} {
				ensureVoter(t, db, v)
			}
			// A third voter failing down: a quorum of five, so the cycle fences.
			healthRow(t, db, "v4", "suspect", offlineThreshold, time.Now())
			c.run(ctx)
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil || (h.State != "fenced" && h.State != "offline") {
				t.Fatalf("setup: down is %+v after the fence (%v)", h, err)
			}
			if a, err := corrosion.AdoptedVoterConfig(ctx, db); err != nil || a.Explicit() {
				t.Fatalf("setup: the voter set is not derived (%v)", err)
			}
			at := time.Now().Add(-time.Minute)
			backdateMembership(t, db, at.Add(-time.Hour))
			if tc.changed != "" {
				if err := corrosion.UpdateHostState(ctx, db, tc.changed, "fenced"); err != nil {
					t.Fatal(err)
				}
			}
			deadlineScope(t, c, db)
			if v := c.scope.voters("down"); v["down"] {
				t.Fatalf("setup: the deadline's derived set %v still holds the fenced host", v)
			}
			for _, o := range tc.spanning {
				failingSince(t, db, o, at.Add(-time.Minute), time.Now())
			}
			for _, o := range tc.restart {
				failingSince(t, db, o, at.Add(20*time.Second), time.Now())
			}
			if tc.bridge {
				healthRow(t, db, "bridge", "healthy", 0, time.Now())
			}
			v := c.selfPauseStillStands(ctx, h, at, time.Time{})
			if tc.wantOK {
				if !v.ok {
					t.Fatalf("deadline: %+v; want it to go ahead", v)
				}
				return
			}
			if v.ok || v.key != tc.wantKey {
				t.Fatalf("deadline: %+v; want refused under %q", v, tc.wantKey)
			}
		})
	}
}
