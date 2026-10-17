package failover

import (
	"testing"
	"time"
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
// Mutation: drop upgradingLifeGrace from countVoters — "inside the allowance"
// names the host (fenced afreshRun after the activation).
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
