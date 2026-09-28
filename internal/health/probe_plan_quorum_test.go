package health_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// The recovery quorum counts fresh healthy rows from voters about a host that
// is offline, and an offline host is not itself a voter. A plan that sampled
// the observers of non-voters would therefore starve exactly this quorum:
// fourteen nodes, six of them offline, eight voters and a quorum of five, and a
// sample of three observers per offline host could never bring one back. Runs
// the real checkers against the real coordinator and the real
// corrosion.VoterSet.
func TestProbePlan_OfflineHostsAreStillRecovered(t *testing.T) {
	var names []string
	for i := 1; i <= 14; i++ {
		names = append(names, fmt.Sprintf("node-%02d", i))
	}
	sc := newStallCluster(t, names...)
	ctx := context.Background()
	offline := names[8:]
	for _, n := range offline {
		if err := corrosion.UpdateHostState(ctx, sc.db, n, "offline"); err != nil {
			t.Fatalf("UpdateHostState: %v", err)
		}
	}
	voters, err := corrosion.VoterSet(ctx, sc.db)
	if err != nil || len(voters) != 8 {
		t.Fatalf("precondition: the six offline hosts must be the non-voters, got voters %v (err %v)", voters, err)
	}

	// One cycle. Hosts recovered by it become voters and probe everyone, so a
	// later cycle can mask a plan that starved the first: the property is that
	// no offline host has to wait for another to come back first.
	sc.tick()
	for _, n := range offline {
		h, err := corrosion.GetHost(ctx, sc.db, n)
		if err != nil || h == nil {
			t.Fatalf("GetHost %s: %v", n, err)
		}
		if h.State != "active" {
			t.Errorf("%s is %q after a clean cycle, want active: fewer voters observe it than the recovery quorum needs", n, h.State)
		}
	}
}

// failingVoterRows counts the fence-eligible rows (consecutive_failures at the
// fence threshold, not unready) from members of voters about target — the
// predicate the coordinator's fence quorum applies, less freshness, which every
// row here meets.
func failingVoterRows(t *testing.T, db *corrosion.Client, voters map[string]bool, target string) int {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT observer FROM host_health WHERE target = ? AND consecutive_failures >= ? AND status != ?`,
		target, health.FailuresToFence, health.StatusUnready)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	n := 0
	for _, r := range rows {
		if o := r.String("observer"); o != target && voters[o] {
			n++
		}
	}
	return n
}

// With an explicit voter set, a dead voter and a dead non-voter both reach the
// fence quorum on the same probe cycle a full mesh does — the FailuresToFence-th
// — and not one cycle later. Every voter observes every host, so sampling the
// non-voters' own probes changes nothing the quorum counts.
//
// The coordinator is not run: its voter set is corrosion.VoterSet, which today
// is every active host, so the quorum is computed here over the plan's voters.
func TestProbePlan_DeadHostsReachFenceQuorumOnSchedule(t *testing.T) {
	var names []string
	for i := 1; i <= 12; i++ {
		names = append(names, fmt.Sprintf("node-%02d", i))
	}
	sc := newStallCluster(t, names...)
	voters := map[string]bool{"node-01": true, "node-02": true, "node-03": true}
	for _, n := range sc.nodes {
		n.checker.SetVoterSetForTest(func(context.Context) (map[string]bool, error) { return voters, nil })
	}
	quorum := len(voters)/2 + 1
	ctx := context.Background()
	cycle := func() {
		for _, n := range sc.nodes {
			stepNormally(n, 2*time.Second)
		}
		for _, n := range sc.nodes {
			n.checker.ProbeAllForTest(ctx)
		}
	}
	cycle() // one clean cycle

	sc.setDead("node-02", true) // a voter
	sc.setDead("node-09", true) // a non-voter
	for i := 1; i <= health.FailuresToFence; i++ {
		cycle()
		for _, target := range []string{"node-02", "node-09"} {
			got := failingVoterRows(t, sc.db, voters, target)
			switch {
			case i < health.FailuresToFence && got >= quorum:
				t.Fatalf("cycle %d: %s already has %d fence votes; the threshold is %d failures", i, target, got, health.FailuresToFence)
			case i == health.FailuresToFence && got < quorum:
				t.Fatalf("cycle %d: %s has %d fence votes from voters, want at least %d", i, target, got, quorum)
			}
		}
	}
}
