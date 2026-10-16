package failover

import (
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The bridged hold is bounded (lab 1 at f9bafd75, W1 P2 and W5c). At the
// self-pause deadline, an answer since the fence that the rows have
// overwritten (a failing run begun after it) or this node's own probe answer
// holds the recovery only while it could be the host's regained majority.
// Once n−q+1 voters other than the host have failed it without a break since
// before the fence, it cannot have held a majority since, and the deadline
// goes ahead; the host's condition, raised on a clock behind the voters',
// "predates this outage" and limits nothing. With one spanning run fewer the
// deadline still refuses (H1, the host came back and fell again).
//
// Mutations: drop the noRegainSinceIn check from selfPauseStillStands'
// explicit path — "three spanning voters, a restarted non-voter" and "this
// node's probe, three other voters span" refuse; count this node's own row
// when it has probed the host since the wait began — "this node's probe, it
// is one of three" goes ahead; require one spanning run fewer (n−q) in
// noRegainSinceIn — "two spanning voters, a restarted voter" goes ahead.
func TestSelfPauseExplicit_SpanningVotersBoundARestartedRunOrAProbeAnswer(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spanning []string
		restart  []string
		contact  bool
		wantOK   bool
		wantKey  string
	}{
		{"three spanning voters, a restarted non-voter", []string{"coordinator", "alive", "v4"}, []string{"bridge"}, false, true, ""},
		{"three spanning voters, a restarted voter", []string{"coordinator", "alive", "v4"}, []string{"v5"}, false, true, ""},
		{"two spanning voters, a restarted voter", []string{"coordinator", "v4"}, []string{"alive"}, false, false, keyRestarted},
		{"this node's probe, it is one of three", []string{"coordinator", "alive", "v4"}, nil, true, false, keyContacted},
		{"this node's probe, three other voters span", []string{"coordinator", "alive", "v4", "v5"}, []string{"bridge"}, true, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := explicitPause(t)
			c.run(ctx) // the fence, and the voter scope the deadline counts over
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil {
				t.Fatal(err)
			}
			at := time.Now().Add(-time.Minute)
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

// The same bound on the derived voter set: quietFallback's restarted-run
// rule gives way once n−q+1 voters other than the host have failed it
// without a break since before the fence, and holds with one fewer. A latest
// verdict that is an answer (a bridge that still stands) still refuses.
//
// Mutations: pass noRegain=false to quietFallback on the derived path —
// "enough spanning" refuses; drop the answeredSinceIn check from its noRegain
// branch — "enough spanning, the bridge still answers" goes ahead.
func TestSelfPauseDerived_SpanningVotersBoundARestartedRun(t *testing.T) {
	for _, tc := range []struct {
		name    string
		short   int  // spanning runs fewer than n−q+1
		bridge  bool // a non-voter's latest verdict is an answer
		wantOK  bool
		wantKey string
	}{
		{"enough spanning", 0, false, true, ""},
		{"one spanning run short", 1, false, false, keyRestarted},
		{"enough spanning, the bridge still answers", 0, true, false, keyAnswered},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, db, ctx, _ := pauseCoordinator(t, true)
			for _, v := range []string{"v4", "v5"} {
				ensureVoter(t, db, v)
			}
			c.run(ctx)
			h, err := corrosion.GetHost(ctx, db, "down")
			if err != nil || h == nil {
				t.Fatal(err)
			}
			if a, err := corrosion.AdoptedVoterConfig(ctx, db); err != nil || a.Explicit() {
				t.Fatalf("setup: the voter set is not derived (%v)", err)
			}
			var others []string
			voters := c.scope.voters("down")
			for v := range voters {
				if v != "down" {
					others = append(others, v)
				}
			}
			sort.Strings(others)
			need := len(voters) - (len(voters)/2 + 1) + 1 - tc.short
			if need < 1 || len(others) <= need {
				t.Fatalf("setup: derived voters %v leave no restarted voter beside %d spanning", others, need)
			}
			at := time.Now().Add(-time.Minute)
			for i, o := range others {
				since := at.Add(20 * time.Second)
				if i < need {
					since = at.Add(-time.Minute)
				}
				failingSince(t, db, o, since, time.Now())
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
