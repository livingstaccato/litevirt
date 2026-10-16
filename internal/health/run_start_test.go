package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A failing verdict carries when its run of unanswered probes began, in
// last_seen. Failover reads it as the start of the outage the observer is
// watching. It used to derive the start from the count, one probe per
// ProbeInterval, and a probe of a powered-off host takes ~2.85 s on the kvm003
// lab: the derived start drifted later through the outage, until a fence or an
// operator confirmation made minutes into it read as older than the outage
// (drills 3 and 6 on main-e004c250).
//
// Each probe here runs ~2.85 s on the observer's clock, beating as the
// heartbeat would, so no probe straddles a stall.
//
// Mutation: drop the last_seen argument from the failing verdict (bind nil) —
// every failing verdict publishes no start.
func TestCheckHost_FailingVerdictCarriesItsRunStart(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "obs", Address: "10.9.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "01"},
		{Name: "dead", Address: "10.9.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "02"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}

	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	advance := func(d time.Duration) { mu.Lock(); now = now.Add(d); mu.Unlock() }

	c := NewChecker("obs", t.TempDir(), db)
	c.clock = clock
	answer := "down" // "up", "unready" or "down"
	c.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) {
		// The probe of a dead host runs out its timeout; the heartbeat keeps
		// beating meanwhile.
		switch answer {
		case "up":
			return true, "", nil
		case "unready":
			return false, "store wedged", nil
		}
		for i := 0; i < 3; i++ {
			advance(950 * time.Millisecond)
			c.beat(c.now())
		}
		return false, "", errors.New("i/o timeout")
	})
	type verdict struct {
		failures int
		lastSeen interface{}
	}
	var published []verdict
	c.writeFn = func(_ context.Context, sqlStr string, args ...interface{}) error {
		if args[1] != "dead" {
			return nil
		}
		if sqlStr == healthyVerdictSQL {
			published = append(published, verdict{0, args[3]})
		} else {
			published = append(published, verdict{args[3].(int), args[4]})
		}
		return nil
	}
	host := corrosion.HostRecord{Name: "dead", Address: "10.9.0.2", GRPCPort: 7443, State: "active"}
	probe := func() {
		advance(100 * time.Millisecond)
		c.beat(c.now())
		c.checkHost(ctx, host)
	}

	// The host answers once, then goes dark: the run starts at the first
	// unanswered probe's observation, and every verdict of the run says so.
	answer = "up"
	probe()
	answer = "down"
	published = nil
	probe()
	start := clock()
	for i := 0; i < 40; i++ {
		probe()
	}
	if len(published) != 41 || published[40].failures != 41 {
		t.Fatalf("want 41 failing verdicts counting to 41, have %d (last %+v)", len(published), published[len(published)-1])
	}
	want := start.UTC().Format(time.RFC3339Nano)
	for i, v := range published {
		if v.lastSeen != want {
			t.Fatalf("failing verdict %d (count %d) carries last_seen %v, want the run's start %s", i, v.failures, v.lastSeen, want)
		}
	}
	// What the count alone used to say: 40 × ProbeInterval back from the
	// last verdict is well after the run began.
	if derived := clock().Add(-40 * ProbeInterval); !derived.After(start.Add(30 * time.Second)) {
		t.Fatalf("fixture: the cadence must outrun ProbeInterval (derived %v, start %v)", derived, start)
	}

	// An unready answer ends the run; the next silence starts a new one.
	answer = "unready"
	published = nil
	probe()
	if len(published) != 1 || published[0].lastSeen != nil {
		t.Fatalf("an unready answer must publish no run start, have %+v", published)
	}
	answer = "down"
	published = nil
	probe()
	restart := clock()
	probe()
	probe()
	for _, v := range published {
		if v.lastSeen != restart.UTC().Format(time.RFC3339Nano) {
			t.Fatalf("after an unready answer the run must restart at its first silent probe %s, verdict %+v", restart.UTC().Format(time.RFC3339Nano), v)
		}
	}

	// So does a healthy one.
	answer = "up"
	published = nil
	probe()
	if len(published) != 1 || published[0].failures != 0 {
		t.Fatalf("want one healthy verdict, have %+v", published)
	}
	answer = "down"
	published = nil
	probe()
	again := clock()
	probe()
	if len(published) != 2 || published[1].lastSeen != again.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("after a healthy answer the run must restart at its first failed probe %s, have %+v",
			again.UTC().Format(time.RFC3339Nano), published)
	}
}

// runStartRig is TestCheckHost_FailingVerdictCarriesItsRunStart's observer,
// reusable: "obs" probing "dead" on a settable clock, every published verdict
// about "dead" recorded, its observer_stalled condition in db.
type runStartRig struct {
	c         *Checker
	db        *corrosion.Client
	mu        sync.Mutex
	now       time.Time
	answer    string // "up", "unready" or "down"
	straddle  time.Duration
	host      corrosion.HostRecord
	published []runStartVerdict
}

type runStartVerdict struct {
	failures int
	lastSeen interface{}
}

func newRunStartRig(t *testing.T) *runStartRig {
	t.Helper()
	db := testCheckHostDB(t)
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "obs", Address: "10.9.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "01"},
		{Name: "dead", Address: "10.9.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CertSerial: "02"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	r := &runStartRig{db: db, now: time.Now(), answer: "up",
		host: corrosion.HostRecord{Name: "dead", Address: "10.9.0.2", GRPCPort: 7443, State: "active"}}
	r.c = NewChecker("obs", t.TempDir(), db)
	r.c.clock = r.clock
	r.c.SetPeerReadiness(func(context.Context, string, string) (bool, string, error) {
		if d := r.straddle; d > 0 {
			// The process stops while this probe is in flight: the clock
			// moves on and nothing beats.
			r.straddle = 0
			r.advance(d)
		}
		switch r.answer {
		case "up":
			return true, "", nil
		case "unready":
			return false, "store wedged", nil
		}
		return false, "", errors.New("i/o timeout")
	})
	r.c.writeFn = func(_ context.Context, sqlStr string, args ...interface{}) error {
		if args[1] != "dead" {
			return nil
		}
		if sqlStr == healthyVerdictSQL {
			r.published = append(r.published, runStartVerdict{0, args[3]})
		} else {
			r.published = append(r.published, runStartVerdict{args[3].(int), args[4]})
		}
		return nil
	}
	return r
}

func (r *runStartRig) clock() time.Time { r.mu.Lock(); defer r.mu.Unlock(); return r.now }
func (r *runStartRig) advance(d time.Duration) {
	r.mu.Lock()
	r.now = r.now.Add(d)
	r.mu.Unlock()
}

// run is the process running normally for d: the heartbeat ticks every
// stallBeat (keeping observer_stalled in line), and the probe loop probes
// every checkInterval.
func (r *runStartRig) run(d time.Duration) {
	for moved := time.Duration(0); moved < d; moved += stallBeat {
		r.advance(stallBeat)
		r.c.stallTick(context.Background())
		if moved%checkInterval == 0 {
			r.c.checkHost(context.Background(), r.host)
		}
	}
}

// stop is the process not running for d: no beat, no probe.
func (r *runStartRig) stop(d time.Duration) { r.advance(d) }

// failing returns the failing verdicts published since the last call.
func (r *runStartRig) failing() []runStartVerdict {
	var out []runStartVerdict
	for _, v := range r.published {
		if v.failures > 0 {
			out = append(out, v)
		}
	}
	r.published = nil
	return out
}

// silentSince is what obs's observer_stalled condition records for the run
// v belongs to (SilentSince, as failover reads it).
func (r *runStartRig) silentSince(t *testing.T, v runStartVerdict) (time.Time, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), r.db, StallEvaluator, CondObserverStalled, "host", "obs")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		return time.Time{}, false
	}
	ls, _ := v.lastSeen.(string)
	return SilentSince(row.Evidence, "dead", ls)
}

// seenAt parses a verdict's last_seen; the zero time when it has none.
func seenAt(v runStartVerdict) time.Time {
	s, _ := v.lastSeen.(string)
	at, _ := time.Parse(time.RFC3339Nano, s)
	return at
}

// An observer that was not running (frozen, suspended) while its target went
// dark last saw the target answer before it stopped. Its first failing run
// after the stall starts, as any does, at its first counted probe — but it
// records the run, with the stall's start, in its observer_stalled condition,
// which is what lets failover tell it from a run begun after an answer
// (restartedSinceObserversIn). Without the record, a frozen observer thawed
// after a fence refused that fence's recovery for good (lab 1 Drill2,
// 2026-10-16). The run's start itself is not moved back: the observer did not
// watch the target while it was stopped (observerStreakSpans).
//
// Mutations: drop the noteSilentRun call — the record check goes red; publish
// the stall's start as last_seen — the run-start check goes red.
func TestCheckHost_ARunSilentThroughAStallIsRecorded(t *testing.T) {
	r := newRunStartRig(t)
	r.run(10 * time.Second) // "dead" answers
	if len(r.failing()) != 0 {
		t.Fatal("fixture: failing verdicts while the target answers")
	}
	stoppedAt := r.clock()
	r.answer = "down"
	r.stop(40 * time.Second)
	resumed := r.clock()
	r.run(StallGrace + 10*time.Second)
	got := r.failing()
	if len(got) == 0 {
		t.Fatal("no failing verdict after the grace window")
	}
	if ls := seenAt(got[0]); ls.Before(resumed.Add(StallGrace)) || got[0].failures != 1 {
		t.Fatalf("first failing verdict %+v; the run starts at its first counted probe, after the grace window (%s)",
			got[0], wallStamp(resumed.Add(StallGrace)))
	}
	for i, v := range got {
		if v.lastSeen != got[0].lastSeen {
			t.Fatalf("verdict %d carries last_seen %v, the run began at %v", i, v.lastSeen, got[0].lastSeen)
		}
	}
	since, ok := r.silentSince(t, got[0])
	if !ok || !since.Equal(stoppedAt) {
		t.Fatalf("observer_stalled records the run as silent since %v (%v); the observer last ran, and last could have "+
			"seen the target answer, at %s", since, ok, wallStamp(stoppedAt))
	}
}

func wallStamp(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// The other side of it: an observer that HAS seen the target answer since it
// resumed records nothing, and its run excuses nothing, as without a stall.
// Nor does one whose probe in flight across the stall came back answered — the
// answer may have arrived at any moment of the stall — nor one that began
// tracking the target only after the stall. Each run began after an answer
// the observer may have seen after a fence, and must keep refusing it.
//
// Mutations: record every first run after a stall, whatever was answered —
// the "answered after resuming" and "answer straddled" cases go red; drop the
// "tracked since before the stall" condition — the "first probed after" case
// goes red.
func TestCheckHost_ARunAfterAnAnswerIsNotSilentThroughTheStall(t *testing.T) {
	check := func(t *testing.T, r *runStartRig) {
		t.Helper()
		got := r.failing()
		if len(got) == 0 {
			t.Fatal("no failing verdict")
		}
		if since, ok := r.silentSince(t, got[0]); ok {
			t.Fatalf("the run beginning at %v is recorded silent since %s; the observer may have seen the target answer after that",
				got[0].lastSeen, wallStamp(since))
		}
	}
	t.Run("answered after resuming", func(t *testing.T) {
		r := newRunStartRig(t)
		r.run(10 * time.Second)
		r.stop(40 * time.Second)
		r.run(4 * time.Second) // "dead" answers, inside the grace window
		r.answer = "down"
		r.failing()
		r.run(StallGrace + 6*time.Second)
		check(t, r)
	})
	t.Run("answer straddled the stall", func(t *testing.T) {
		r := newRunStartRig(t)
		r.run(10 * time.Second)
		r.straddle = 40 * time.Second
		r.c.checkHost(context.Background(), r.host) // answered, but withheld
		r.answer = "down"
		r.run(StallGrace + 6*time.Second)
		check(t, r)
	})
	t.Run("first probed after the stall", func(t *testing.T) {
		r := newRunStartRig(t)
		r.answer = "down"
		for i := 0; i < 8; i++ { // running, but not yet probing "dead"
			r.advance(stallBeat)
			r.c.stallTick(context.Background())
		}
		r.stop(40 * time.Second)
		r.run(StallGrace + 6*time.Second)
		check(t, r)
	})
}

// A long stop is commonly followed by a short one as the process catches up
// (8.0 s then 2.2 s on the lab). The run after the second is still silent
// since the FIRST: the observer has seen no answer since before it. Recorded
// from the latest stall instead, it reads as silent only since after the
// fence, and failover refuses the recovery for good, as before the record
// existed. Whether or not a probe of the target ran between the two stops.
//
// Mutation: record the latest stall's start (drop silentFrom's carry-over,
// use the newest epoch's from) — both cases go red.
func TestCheckHost_ASilentRunCarriesTheEarliestStallAcrossACatchUp(t *testing.T) {
	for _, tc := range []struct {
		name    string
		between func(r *runStartRig)
	}{
		{"probed between the stops", func(r *runStartRig) { r.run(3 * time.Second) }},
		{"no probe between the stops", func(r *runStartRig) {
			r.advance(stallBeat)
			r.c.stallTick(context.Background())
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunStartRig(t)
			r.run(10 * time.Second)
			stoppedAt := r.clock()
			r.answer = "down"
			r.stop(40 * time.Second)
			tc.between(r)
			r.stop(3 * time.Second)
			r.run(StallGrace + 8*time.Second)
			got := r.failing()
			if len(got) == 0 {
				t.Fatal("no failing verdict")
			}
			v := got[len(got)-1]
			since, ok := r.silentSince(t, v)
			if !ok || !since.Equal(stoppedAt) {
				t.Fatalf("the run beginning at %v is recorded silent since %s (%v); the observer has seen no answer since %s",
					v.lastSeen, wallStamp(since), ok, wallStamp(stoppedAt))
			}
		})
	}
}

// An answer between two stops ends the silence: the run after the second is
// silent only since the second.
//
// Mutation: keep silentFrom across an answer — the run is recorded silent
// since the first stop and this goes red.
func TestCheckHost_AnAnswerBetweenTwoStallsEndsTheSilence(t *testing.T) {
	r := newRunStartRig(t)
	r.run(10 * time.Second)
	firstStop := r.clock()
	r.answer = "down"
	r.stop(40 * time.Second)
	r.run(1 * time.Second) // one probe, unanswered, inside the grace window
	r.answer = "up"
	r.run(4 * time.Second) // answered
	answeredBy := r.clock()
	r.answer = "down"
	r.stop(3 * time.Second)
	r.run(StallGrace + 8*time.Second)
	got := r.failing()
	if len(got) == 0 {
		t.Fatal("no failing verdict")
	}
	v := got[len(got)-1]
	since, ok := r.silentSince(t, v)
	if !ok || since.Equal(firstStop) || since.Before(answeredBy.Add(-time.Second)) {
		t.Fatalf("the run beginning at %v is recorded silent since %s (%v); the target answered up to %s",
			v.lastSeen, wallStamp(since), ok, wallStamp(answeredBy))
	}
}
