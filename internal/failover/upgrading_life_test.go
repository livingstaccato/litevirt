package failover

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// failingFromRun is failing() with the observer's run begun at runStart.
func failingFromRun(target, observer string, at, runStart time.Time) HealthObservation {
	o := failing(target, observer, at)
	o.LastSeen = runStart.UTC().Format(time.RFC3339Nano)
	return o
}

// TestFenceCandidates_RunBegunWhileUpgradingKeepsTheRestartAllowance: a host
// recorded 'upgrading' at u, failing since just after, is recorded active at
// `since` by something other than its own serving write (lab 1, 2026-10-17:
// an undrain, 19 s before its daemon served). Its observers' run began while
// it was 'upgrading', so it keeps the rest of its restart allowance, timed from
// u: it is not a candidate inside it, and is one once it has passed, as a host
// stuck 'upgrading' is.
//
// Mutations: drop upgradingLifeGrace from countVoters — "inside the
// allowance" names the host (fenced afreshRun after the activation); cap the
// allowance 15 s late — "one second past the cap" does not name it.
func TestFenceCandidates_RunBegunWhileUpgradingKeepsTheRestartAllowance(t *testing.T) {
	five := []string{"coordinator", "h1", "h2", "h3", "bad"}
	const allowance = 2 * time.Minute
	type tc struct {
		name               string
		now, since, run, u time.Time
		end                time.Time
		want               []string
	}
	u := time.Unix(1_900_000_000, 0)
	cases := []tc{
		{name: "inside the allowance", u: u, run: u.Add(2 * time.Second), since: u.Add(40 * time.Second),
			now: u.Add(70 * time.Second), want: []string{}},
		{name: "allowance passed", u: u, run: u.Add(2 * time.Second), since: u.Add(100 * time.Second),
			now: u.Add(allowance + 20*time.Second), want: []string{"bad"}},
		// The cap, to the second: with the activation 60 s into the life,
		// the allowance ends at u+T, not afreshRun after the activation.
		{name: "one second before the cap", u: u, run: u.Add(2 * time.Second), since: u.Add(60 * time.Second),
			now: u.Add(allowance - time.Second), want: []string{}},
		{name: "one second past the cap", u: u, run: u.Add(2 * time.Second), since: u.Add(60 * time.Second),
			now: u.Add(allowance + time.Second), want: []string{"bad"}},
		{name: "run began before the upgrading write", u: u, run: u.Add(-30 * time.Second), since: u.Add(40 * time.Second),
			now: u.Add(70 * time.Second), want: []string{"bad"}},
		{name: "a later activation", u: u, run: u.Add(2 * time.Second), since: u.Add(40 * time.Second),
			end: u.Add(30 * time.Second), now: u.Add(70 * time.Second), want: []string{"bad"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := candInputs(c.now, five...)
			in.UpgradingTimeout = allowance
			in.ActiveSince = map[string]time.Time{"bad": c.since}
			end := c.end
			if end.IsZero() {
				end = c.since
			}
			in.UpgradingLives = map[string]UpgradingLife{"bad": {Start: c.u, End: end}}
			for _, o := range []string{"h1", "h2", "h3"} {
				in.Observations = append(in.Observations, failingFromRun("bad", o, c.now, c.run))
			}
			cands, _ := FenceCandidates(in)
			if got := targets(cands); len(got) != len(c.want) || (len(got) > 0 && got[0] != c.want[0]) {
				t.Errorf("candidates = %v, want %v", got, c.want)
			}
		})
	}

	// Control: the same host with no upgrading life known is a candidate
	// afreshRun after its activation.
	in := candInputs(u.Add(70*time.Second), five...)
	in.ActiveSince = map[string]time.Time{"bad": u.Add(40 * time.Second)}
	for _, o := range []string{"h1", "h2", "h3"} {
		in.Observations = append(in.Observations, failingFromRun("bad", o, u.Add(70*time.Second), u.Add(2*time.Second)))
	}
	if cands, _ := FenceCandidates(in); len(cands) != 1 {
		t.Errorf("fixture: with no upgrading life the host is not a candidate 30 s after its activation: %v", cands)
	}
}

// TestNoteUpgradingLives: the holder's record of each host's 'upgrading' life,
// from the membership state it reads every cycle. The life starts at the
// 'upgrading' write, ends at the activation the first cycle after it sees, is
// kept while that activation stands, and is forgotten on a later activation,
// on a life that ended in another state, and on a step-down or a lease gap.
//
// Mutations: never set End (the "ended by" case); keep a life past a later
// activation, or past one that ended in another state; drop the clear from
// stepDownGauges or from forgetEpisodes.
func TestNoteUpgradingLives(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	db.SetHostMembershipGate(func() bool { return true })
	if _, err := db.SplitHostMembership(ctx); err != nil || !db.HostMembershipLive() {
		t.Fatalf("split host membership: live=%v err=%v", db.HostMembershipLive(), err)
	}
	c := newTestCoordinator("coordinator", db)
	set := func(state string) time.Time {
		t.Helper()
		if err := corrosion.UpdateHostState(ctx, db, "down", state); err != nil {
			t.Fatalf("record %s: %v", state, err)
		}
		since, ok, err := corrosion.HostStateSince(ctx, db, "down")
		if err != nil || !ok {
			t.Fatalf("read when 'down' turned %s: ok=%v err=%v", state, ok, err)
		}
		return since
	}
	life := func() (UpgradingLife, bool) {
		l, ok := c.upgradingLives["down"]
		return l, ok
	}

	start := set("upgrading")
	c.noteUpgradingLives(ctx)
	if l, ok := life(); !ok || !l.Start.Equal(start) || !l.End.IsZero() {
		t.Fatalf("while 'upgrading': life %+v (ok=%v), want Start %v and no End", l, ok, start)
	}
	if _, ok := c.upgradingLives["alive"]; ok {
		t.Fatal("an active host that was never 'upgrading' has a life")
	}

	end := set("active")
	c.noteUpgradingLives(ctx)
	if l, ok := life(); !ok || !l.Start.Equal(start) || !l.End.Equal(end) {
		t.Fatalf("ended by an activation: life %+v (ok=%v), want %v..%v", l, ok, start, end)
	}
	c.noteUpgradingLives(ctx)
	if l, ok := life(); !ok || !l.End.Equal(end) {
		t.Fatalf("the activation still stands: life %+v (ok=%v), want it kept", l, ok)
	}

	set("draining")
	set("active")
	c.noteUpgradingLives(ctx)
	if l, ok := life(); ok {
		t.Fatalf("a later activation: life %+v kept, want it forgotten", l)
	}

	set("upgrading")
	c.noteUpgradingLives(ctx)
	set("draining")
	c.noteUpgradingLives(ctx)
	if l, ok := life(); ok {
		t.Fatalf("a life that ended draining: %+v kept, want it forgotten", l)
	}

	for name, stepDown := range map[string]func(){"stepDownGauges": c.stepDownGauges, "forgetEpisodes": c.forgetEpisodes} {
		set("upgrading")
		c.noteUpgradingLives(ctx)
		if _, ok := life(); !ok {
			t.Fatalf("fixture: no life before %s", name)
		}
		stepDown()
		if l, ok := life(); ok {
			t.Errorf("%s kept the life %+v: a later tenure has not seen what happened meanwhile", name, l)
		}
	}
}
