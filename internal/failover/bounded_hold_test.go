package failover

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// backdateHistory stamps every host's membership, its hosts copy and every
// voter generation at ts: no host's voting state changed, and no generation
// was decided, during the outage the test builds.
func backdateHistory(t *testing.T, db *corrosion.Client, ts time.Time) {
	t.Helper()
	s := ts.UTC().Format(time.RFC3339Nano)
	for _, q := range []string{`UPDATE host_membership SET updated_at = ?`, `UPDATE hosts SET updated_at = ?`,
		`UPDATE voter_configs SET created_at = ?`} {
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
			backdateHistory(t, db, at.Add(-time.Hour))
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
			backdateHistory(t, db, at.Add(-time.Hour))
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

// The voter configuration down may be counting over must be pinned: two
// generations decided since the outage began (`voter rm down` then
// `voter add v6`), or a reset, keep the hold whatever spans. down,
// coordinator and alive are a majority of generation 1, which down still
// counts over; the deadline's generation 3 and the generation 2 before it
// are both spanned by v4, v5 and v6.
//
// Mutation: allow two generations since the outage in regainCandidates —
// "rm down, then add v6" goes ahead.
func TestSelfPauseExplicit_TheVoterConfigurationMustBePinned(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gens   [][]string // generations decided since the outage, from 2; nil a reset
		adopt  int64
		wantOK bool
	}{
		{"rm down, then add v6", [][]string{{"coordinator", "alive", "v4", "v5"}, {"coordinator", "alive", "v4", "v5", "v6"}}, 3, false},
		{"a reset", [][]string{nil}, 1, false},
		{"one generation, spanned with the one before it", [][]string{{"coordinator", "alive", "v4", "v5", "v6"}}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := explicitPause(t)
			ensureVoter(t, db, "v6")
			c.run(ctx)
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil {
				t.Fatal(err)
			}
			at := time.Now().Add(-time.Minute)
			backdateHistory(t, db, at.Add(-time.Hour))
			for i, g := range tc.gens {
				writeGen(t, db, int64(i+2), g...)
			}
			if err := corrosion.RecordVoterAdoption(ctx, db, tc.adopt); err != nil {
				t.Fatal(err)
			}
			deadlineScope(t, c, db)
			pausedCondition(t, db, at.Add(-time.Hour))
			for _, o := range []string{"coordinator", "alive", "v4", "v5", "v6"} {
				healthRow(t, db, o, "healthy", 0, at.Add(-time.Hour))
			}
			spanning, restart := []string{"v4", "v5", "v6"}, []string{"coordinator", "alive"}
			if tc.wantOK {
				spanning, restart = []string{"alive", "v4", "v5", "v6"}, []string{"coordinator"}
			}
			for _, o := range spanning {
				failingSince(t, db, o, at.Add(-time.Minute), time.Now())
			}
			for _, o := range restart {
				failingSince(t, db, o, at.Add(20*time.Second), time.Now())
			}
			v := c.selfPauseStillStands(ctx, h, at, time.Now())
			if v.ok != tc.wantOK {
				t.Fatalf("deadline: %+v; want ok=%v", v, tc.wantOK)
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
// The other arms keep the hold where down may count over a set this node
// cannot pin or measure: a voter whose state changed since, or within
// healthFreshness before, the outage began (down's replica may not hold the
// change); an explicit generation decided since the outage began; the
// explicit generation a reset replaced, on which down with the restarted
// voters is a majority though the larger derived set is spanned; and a
// spanning voter whose clock skew this node has never measured, whose run
// began only 20 s before the fence.
//
// Mutations: count over this node's derived set (drop down from
// derivedRegainCandidate's set) — "two spanning, two restarted" goes ahead;
// pass noRegain=false to quietFallback on the derived path — "three
// spanning" refuses; drop the answeredSinceIn check from its noRegain branch
// — "three spanning, the bridge still answers" goes ahead; count a voter
// whose state changed since the outage began — "a third fenced since" goes
// ahead; count a voter whose state reads unknown — "a third reads unknown"
// goes ahead; date a change against the outage start alone — "a third changed
// just before" goes ahead; date a change by this node's clock alone — "a
// third changed 45 s before, a host never measured" goes ahead; allow a generation since the outage on the
// derived set — "an explicit generation since" goes ahead; leave out the
// generation a reset replaced — "a reset replaced generation 1" goes ahead;
// read an unmeasured observer's skew as 0 — "a voter never measured" goes
// ahead.
func TestSelfPauseDerived_SpanningVotersBoundARestartedRun(t *testing.T) {
	type env struct {
		c   *Coordinator
		db  *corrosion.Client
		ctx context.Context
		at  time.Time
	}
	for _, tc := range []struct {
		name     string
		spanning []string
		restart  []string
		bridge   bool // a non-voter's latest verdict is an answer
		extra    []string
		late     map[string]time.Duration // spanning runs that begin this long before the fence, not a minute
		setup    func(t *testing.T, e env)
		wantOK   bool
		wantKey  string
	}{
		{name: "three spanning", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"}, wantOK: true},
		{name: "two spanning, two restarted", spanning: []string{"v4", "v5"}, restart: []string{"coordinator", "alive"}, wantKey: keyRestarted},
		{name: "three spanning, the bridge still answers", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"}, bridge: true, wantKey: keyAnswered},
		{name: "a third fenced since the outage began", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"}, wantKey: keyRestarted,
			setup: func(t *testing.T, e env) {
				if err := corrosion.UpdateHostState(e.ctx, e.db, "v5", "fenced"); err != nil {
					t.Fatal(err)
				}
			}},
		// Every observer is measured at no skew, so the outage is dated a
		// minute before the fence, less 5 s: v5's membership was written
		// 15 s before that, inside healthFreshness.
		{name: "a third changed just before the outage began", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"}, wantKey: keyRestarted,
			setup: func(t *testing.T, e env) {
				ts := e.at.Add(-time.Minute - 5*time.Second - 15*time.Second).UTC().Format(time.RFC3339Nano)
				for _, q := range []string{`UPDATE host_membership SET updated_at = ? WHERE host_name = 'v5'`, `UPDATE hosts SET updated_at = ? WHERE name = 'v5'`} {
					if err := e.db.Execute(e.ctx, q, ts); err != nil {
						t.Fatal(err)
					}
				}
				e.c.PeerClockSkew = func(string) (time.Duration, bool) { return 0, true }
			}},
		// v5's change is 45 s before the outage, outside healthFreshness by
		// this node's clock, but alive was never measured: the change may be
		// stamped by a writer 30 s behind, so it is not settled.
		{name: "a third changed 45 s before, a host never measured", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"}, wantKey: keyRestarted,
			setup: func(t *testing.T, e env) {
				ts := e.at.Add(-time.Minute - 5*time.Second - 45*time.Second).UTC().Format(time.RFC3339Nano)
				for _, q := range []string{`UPDATE host_membership SET updated_at = ? WHERE host_name = 'v5'`, `UPDATE hosts SET updated_at = ? WHERE name = 'v5'`} {
					if err := e.db.Execute(e.ctx, q, ts); err != nil {
						t.Fatal(err)
					}
				}
				e.c.PeerClockSkew = func(p string) (time.Duration, bool) { return 0, p != "alive" }
			}},
		// v5 has no membership row and this node's hosts copy is frozen:
		// it reads unknown here, which down's replica need not share.
		{name: "a third reads unknown", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"}, wantKey: keyRestarted,
			setup: func(t *testing.T, e env) {
				// Every other host keeps a membership row, down's fenced.
				e.db.SetHostMembershipGate(func() bool { return true })
				if _, err := e.db.SplitHostMembership(e.ctx); err != nil {
					t.Fatal(err)
				}
				if err := e.db.Execute(e.ctx, `DELETE FROM host_membership WHERE host_name = 'v5'`); err != nil {
					t.Fatal(err)
				}
				backdateHistory(t, e.db, e.at.Add(-time.Hour))
				e.db.SetHostMembershipRetireGate(func() bool { return true })
				if st, err := corrosion.HostMembershipStamps(e.ctx, e.db); err != nil {
					t.Fatal(err)
				} else {
					for _, x := range st {
						if (x.Name == "v5") != (x.State == corrosion.HostStateUnknown) {
							t.Fatalf("setup: %s reads %q; want only v5 unknown", x.Name, x.State)
						}
					}
				}
			}},
		{name: "an explicit generation decided since the outage began", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"}, wantKey: keyRestarted,
			setup: func(t *testing.T, e env) {
				writeGen(t, e.db, 1, "coordinator", "alive", "down", "v4", "v5")
			}},
		{name: "a reset replaced generation 1", spanning: []string{"v4", "v5", "w1", "w2"}, restart: []string{"coordinator", "alive"}, extra: []string{"w1", "w2"}, wantKey: keyRestarted,
			setup: func(t *testing.T, e env) {
				writeGen(t, e.db, 1, "coordinator", "alive", "down", "v4", "v5")
				writeGen(t, e.db, 2)
				if err := corrosion.RecordVoterAdoption(e.ctx, e.db, 2); err != nil {
					t.Fatal(err)
				}
				backdateHistory(t, e.db, e.at.Add(-time.Hour))
			}},
		{name: "a voter never measured, 20 s before the fence", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"},
			late: map[string]time.Duration{"v5": 20 * time.Second}, wantKey: keyRestarted,
			setup: func(t *testing.T, e env) {
				e.c.PeerClockSkew = func(p string) (time.Duration, bool) { return 0, p != "v5" }
			}},
		{name: "a voter measured, 20 s before the fence", spanning: []string{"coordinator", "v4", "v5"}, restart: []string{"alive"},
			late: map[string]time.Duration{"v5": 20 * time.Second}, wantOK: true,
			setup: func(t *testing.T, e env) {
				e.c.PeerClockSkew = func(string) (time.Duration, bool) { return 0, true }
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := pauseCoordinator(t, true)
			db.SetVoterConfigGate(func() bool { return true })
			for _, v := range append([]string{"v4", "v5"}, tc.extra...) {
				ensureVoter(t, db, v)
			}
			// More voters failing down: a quorum, so the cycle fences.
			for _, v := range append([]string{"v4"}, tc.extra...) {
				healthRow(t, db, v, "suspect", offlineThreshold, time.Now())
			}
			c.run(ctx)
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil || (h.State != "fenced" && h.State != "offline") {
				t.Fatalf("setup: down is %+v after the fence (%v)", h, err)
			}
			at := time.Now().Add(-time.Minute)
			backdateHistory(t, db, at.Add(-time.Hour))
			if tc.setup != nil {
				tc.setup(t, env{c: c, db: db, ctx: ctx, at: at})
			}
			if a, err := corrosion.AdoptedVoterConfig(ctx, db); err != nil || a.Explicit() {
				t.Fatalf("setup: the voter set is not derived (%v)", err)
			}
			deadlineScope(t, c, db)
			if v := c.scope.voters("down"); v["down"] {
				t.Fatalf("setup: the deadline's derived set %v still holds the fenced host", v)
			}
			for _, o := range tc.spanning {
				lead := time.Minute
				if d, ok := tc.late[o]; ok {
					lead = d
				}
				failingSince(t, db, o, at.Add(-lead), time.Now())
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

// A generation decided just before the outage began is not settled: down may
// not have adopted it (its claim round, replication, the adoption tick). On
// generation 1 = down, coordinator, alive, v4, v5, `voter add v6` (2) is
// decided shortly before the cut, and `voter rm down` (3) since. down, still
// on 1 with coordinator and alive, may hold a majority there, which neither 2
// nor 3 shows: v4, v5 and v6 span both. So a generation stamped within
// healthFreshness of the outage counts as decided since, and two since keep
// the hold. The stamps name the operator, so they are moved by the largest
// skew of any host but down: one host never measured moves them 30 s.
//
// Every voter's skew is measured as none (alive's too, but in the last arm),
// so the outage is dated a minute before the fence less 5 s, and the window
// reaches 30 s further back.
//
// Mutations: date a generation against the outage start alone, without the
// window — "add v6 10 s before the outage" goes ahead; move an operator's
// stamp by no skew — "add v6 40 s before, alive never measured" goes ahead.
func TestSelfPauseExplicit_AGenerationJustBeforeTheOutageIsNotSettled(t *testing.T) {
	for _, tc := range []struct {
		name       string
		addBefore  time.Duration // how long before the outage began v6 was added
		unmeasured string
		wantOK     bool
	}{
		{"add v6 10 s before the outage, rm down since", 10 * time.Second, "", false},
		{"add v6 40 s before the outage, rm down since", 40 * time.Second, "", true},
		{"add v6 40 s before, alive never measured", 40 * time.Second, "alive", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := explicitPause(t)
			ensureVoter(t, db, "v6")
			c.run(ctx)
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil {
				t.Fatal(err)
			}
			at := time.Now().Add(-time.Minute)
			backdateHistory(t, db, at.Add(-time.Hour))
			outage := at.Add(-time.Minute - 5*time.Second)
			writeGen(t, db, 2, "coordinator", "alive", "down", "v4", "v5", "v6")
			writeGen(t, db, 3, "coordinator", "alive", "v4", "v5", "v6")
			for g, ts := range map[int64]time.Time{2: outage.Add(-tc.addBefore), 3: time.Now()} {
				if err := db.Execute(ctx, `UPDATE voter_configs SET created_at = ?, created_by = ? WHERE generation = ?`,
					ts.UTC().Format(time.RFC3339Nano), "admin via coordinator", g); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.RecordVoterAdoption(ctx, db, 3); err != nil {
				t.Fatal(err)
			}
			c.PeerClockSkew = func(p string) (time.Duration, bool) { return 0, p != tc.unmeasured }
			deadlineScope(t, c, db)
			pausedCondition(t, db, at.Add(-time.Hour))
			for _, o := range []string{"coordinator", "alive", "v4", "v5", "v6"} {
				healthRow(t, db, o, "healthy", 0, at.Add(-time.Hour))
			}
			for _, o := range []string{"v4", "v5", "v6"} {
				failingSince(t, db, o, at.Add(-time.Minute), time.Now())
			}
			for _, o := range []string{"coordinator", "alive"} {
				failingSince(t, db, o, at.Add(20*time.Second), time.Now())
			}
			v := c.selfPauseStillStands(ctx, h, at, time.Now())
			if v.ok != tc.wantOK || (!v.ok && !strings.HasPrefix(v.key, keyRestarted)) {
				t.Fatalf("deadline: %+v; want ok=%v (refused under %q)", v, tc.wantOK, keyRestarted)
			}
		})
	}
}
