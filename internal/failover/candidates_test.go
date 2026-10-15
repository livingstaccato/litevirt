package failover

import (
	"context"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// candInputs is a cluster-scope input set over voters, at now.
func candInputs(now time.Time, voters ...string) CandidateInputs {
	vr := corrosion.VoterRegionSets{Voters: map[string]bool{}, RegionOf: map[string]string{}}
	for _, v := range voters {
		vr.Voters[v] = true
		vr.RegionOf[v] = "default"
	}
	return CandidateInputs{Self: voters[0], Voters: vr, Now: now, UpgradingTimeout: upgradingTimeout}
}

func failing(target, observer string, at time.Time) HealthObservation {
	return HealthObservation{Target: target, Observer: observer, Failures: offlineThreshold,
		UpdatedAt: at.UTC().Format(time.RFC3339Nano)}
}

func targets(cands []FenceCandidate) []string {
	out := []string{}
	for _, c := range cands {
		out = append(out, c.Target)
	}
	return out
}

// FenceCandidates, the pure count, over the fixtures the coordinator's quorum,
// freshness, active-since and region-scope tests use.
//
// Mutation: drop the future bound — the future-dated row counts and the
// "future" case goes red (as does quorum_freshness_test's).
func TestFenceCandidates_Table(t *testing.T) {
	now := time.Unix(1_900_000_000, 0)
	five := []string{"coordinator", "h1", "h2", "h3", "bad"}
	cases := []struct {
		name string
		in   func() CandidateInputs
		want []string
	}{
		{"quorum of fresh voters", func() CandidateInputs {
			in := candInputs(now, five...)
			in.Observations = []HealthObservation{failing("bad", "h1", now), failing("bad", "h2", now), failing("bad", "h3", now)}
			return in
		}, []string{"bad"}},
		{"stale observers do not count", func() CandidateInputs {
			in := candInputs(now, five...)
			in.Observations = []HealthObservation{failing("bad", "h1", now), failing("bad", "h2", now.Add(-2*healthFreshness)),
				failing("bad", "h3", now.Add(-2*healthFreshness))}
			return in
		}, []string{}},
		{"future-dated observations do not count", func() CandidateInputs {
			in := candInputs(now, five...)
			in.Observations = []HealthObservation{failing("bad", "h1", now), failing("bad", "h2", now.Add(2*healthFreshness)),
				failing("bad", "h3", now.Add(2*healthFreshness))}
			return in
		}, []string{}},
		{"a non-voter and the target itself do not vote", func() CandidateInputs {
			in := candInputs(now, five...)
			in.Observations = []HealthObservation{failing("bad", "h1", now), failing("bad", "stranger", now),
				failing("bad", "bad", now), failing("bad", "h2", now)}
			return in
		}, []string{}},
		{"observations from before the host turned active", func() CandidateInputs {
			in := candInputs(now, five...)
			in.ActiveSince = map[string]time.Time{"bad": now.Add(-time.Second)}
			old := now.Add(-5 * time.Second)
			in.Observations = []HealthObservation{failing("bad", "h1", old), failing("bad", "h2", old), failing("bad", "h3", old)}
			return in
		}, []string{}},
	}
	for _, tc := range cases {
		got, _ := FenceCandidates(tc.in())
		if g := targets(got); !reflect.DeepEqual(g, tc.want) {
			t.Errorf("%s: candidates %v, want %v", tc.name, g, tc.want)
		}
	}

	// Region scope: a cluster-wide quorum from the wrong region is declined.
	in := candInputs(now, "coordinator", "e1", "e2", "w1", "w2", "w3")
	in.RegionScope = true
	for h, r := range map[string]string{"coordinator": "east", "e1": "east", "e2": "east", "w1": "west", "w2": "west", "w3": "west"} {
		in.Voters.RegionOf[h] = r
	}
	in.Observations = []HealthObservation{failing("w3", "coordinator", now), failing("w3", "e1", now),
		failing("w3", "e2", now), failing("w3", "w1", now)}
	cands, declined := FenceCandidates(in)
	if len(cands) != 0 || len(declined) != 1 || declined[0] != (RegionDecline{Target: "w3", ClusterObservers: 4, RegionObservers: 1}) {
		t.Fatalf("region scope: candidates %v declined %+v", cands, declined)
	}
}

// The function records no metric: a decline it reports is the caller's to
// count.
func TestFenceCandidates_RecordsNothing(t *testing.T) {
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	downObservers(t, db, "w3", "coordinator", "e1", "e2", "w1")
	c := newTestCoordinator("coordinator", db)
	fm := newFakeMetrics()
	c.Metrics = fm
	got, err := CurrentFenceCandidates(context.Background(), db, "e1", time.Now(), upgradingTimeout)
	if err != nil || len(got) != 0 {
		t.Fatalf("CurrentFenceCandidates: %v %v", got, err)
	}
	if len(fm.attempts) != 0 || len(c.regionDeclined) != 0 {
		t.Fatalf("the pure count recorded something: metrics %v declined %v", fm.attempts, c.regionDeclined)
	}
}

// A node that does not hold the lease lists the same fence candidates as the
// lease holder's cycle, from the same rows (re-review 2 R2-I3).
func TestCurrentFenceCandidates_MatchesTheLeaseHoldersCycle(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeCluster)
	ensureObserverHost(t, db, "x9")
	downObservers(t, db, "w3", "coordinator", "e1", "e2", "w1")
	downObservers(t, db, "x9", "w1", "w2", "e1", "e2")
	downObservers(t, db, "w2", "e1") // one observer: no quorum
	c := newTestCoordinator("coordinator", db)
	c.run(ctx)
	lease := map[string]bool{}
	for h := range c.cycleCandidates {
		lease[h] = true
	}
	other, err := CurrentFenceCandidates(ctx, db, "e2", c.now(), c.upgradingTimeout())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, h := range other {
		got[h] = true
	}
	if !reflect.DeepEqual(got, lease) || len(lease) != 2 {
		t.Fatalf("non-lease-holder lists %v, the lease holder's cycle %v (want w3 and x9 in both)", got, lease)
	}
}

// The pure function may be called from any goroutine while the coordinator
// runs. Run under -race.
func TestFenceCandidates_Concurrent(t *testing.T) {
	ctx := context.Background()
	db := regionFixture(t, corrosion.FailoverScopeRegion)
	downObservers(t, db, "w3", "w1", "w2", "e1")
	c := newTestCoordinator("coordinator", db)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 5; i++ {
			c.RunOnce(ctx)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 20; i++ {
			if _, err := CurrentFenceCandidates(ctx, db, "e1", time.Now(), upgradingTimeout); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()
}
