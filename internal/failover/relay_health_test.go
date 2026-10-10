package failover

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// relayFixture is a lease-holding coordinator over hosts h1..hN, all active
// workers (and so all voters), with the demotion gates open unless latched is
// false. Verdicts are written at the fixture's clock, so a cycle is "write
// this evaluation's probes, then run".
type relayFixture struct {
	t     *testing.T
	db    *corrosion.Client
	c     *Coordinator
	clk   time.Time
	hosts []string
}

const relayPoll = 5 * time.Second // the production pollInterval

func newRelayFixture(t *testing.T, n int, latched bool) *relayFixture {
	t.Helper()
	db := newTestDB(t)
	f := &relayFixture{t: t, db: db, clk: time.Now().UTC().Truncate(time.Second)}
	for i := 1; i <= n; i++ {
		name := fmt.Sprintf("h%d", i)
		ensureObserverHost(t, db, name)
		f.hosts = append(f.hosts, name)
	}
	if latched {
		db.SetClusterPolicyGate(func() bool { return true })
		db.SetRelayHealthGate(func() bool { return true })
	}
	f.c = newTestCoordinator(f.hosts[n-1], db)
	f.c.Now = func() time.Time { return f.clk }
	f.c.RelayConfig = corrosion.RelayConfig{BaseRelays: 2}
	return f
}

// probe records observer's verdict on target at the fixture's clock: failures
// consecutive failed probes (0 is healthy). Below offlineThreshold, so no
// fence quorum ever forms from it.
func (f *relayFixture) probe(observer, target string, failures int) {
	f.t.Helper()
	status := "healthy"
	if failures > 0 {
		status = "suspect"
	}
	if err := f.db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, ?, ?, ?, NULL, ?)`,
		observer, target, status, failures, f.clk.Format(time.RFC3339Nano)); err != nil {
		f.t.Fatalf("probe %s→%s: %v", observer, target, err)
	}
}

// verdicts writes one evaluation's probes of target: the observers in failing
// report one failure, every other host reports it healthy.
func (f *relayFixture) verdicts(target string, failing ...string) {
	f.t.Helper()
	bad := map[string]bool{}
	for _, o := range failing {
		bad[o] = true
	}
	for _, o := range f.hosts {
		if o == target {
			continue
		}
		if bad[o] {
			f.probe(o, target, 1)
		} else {
			f.probe(o, target, 0)
		}
	}
}

// cycle advances the clock one poll and runs the coordinator.
func (f *relayFixture) cycle() {
	f.clk = f.clk.Add(relayPoll)
	f.c.run(context.Background())
}

func (f *relayFixture) demoted(host string) bool {
	f.t.Helper()
	d, err := corrosion.ListRelayDemotions(context.Background(), f.db)
	if err != nil {
		f.t.Fatalf("ListRelayDemotions: %v", err)
	}
	_, ok := d[host]
	return ok
}

func (f *relayFixture) demotionRows() int {
	f.t.Helper()
	rows, err := f.db.Query(context.Background(), `SELECT key FROM cluster_policies WHERE key LIKE 'relay_demoted/%'`)
	if err != nil {
		f.t.Fatal(err)
	}
	return len(rows)
}

// A third of the fresh voter observers (2 of 4) failing on every evaluation
// for the whole window demotes the host, and not one poll sooner.
func TestRelayHealth_DemotesAfterTheStableWindow(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	start := f.clk
	for f.clk.Sub(start) < RelayDemoteWindow {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
		if f.clk.Sub(start) < RelayDemoteWindow && f.demoted("h1") {
			t.Fatalf("h1 demoted after %s, before the %s window", f.clk.Sub(start), RelayDemoteWindow)
		}
	}
	for i := 0; i < 2 && !f.demoted("h1"); i++ {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatalf("h1 not demoted after %s of 2/4 observers failing on every evaluation", f.clk.Sub(start))
	}
	// One failing observer of four is below the bar: h2 is never demoted.
	if f.demoted("h2") {
		t.Fatal("h2 demoted with no failing observer")
	}
}

// A host that fails on one evaluation and passes on the next is a flaky link,
// not a bad relay. It must never be demoted, however long it goes on.
//
// Mutation: keep the failing window open across a passing evaluation (drop
// the stable-window requirement) — h1 is demoted, red.
func TestRelayHealth_AlternatingProbesNeverDemote(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	for i := 0; i < int(3*RelayRestoreWindow/relayPoll); i++ {
		if i%2 == 0 {
			f.verdicts("h1", "h2", "h3")
		} else {
			f.verdicts("h1")
		}
		f.cycle()
		if f.demoted("h1") {
			t.Fatalf("h1 demoted after %d alternating fail/ok evaluations", i+1)
		}
	}
}

// Fewer than a third of the observers failing — one of four — never demotes.
func TestRelayHealth_BelowAThirdNeverDemotes(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	for i := 0; i < int(2*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h2")
		f.cycle()
	}
	if f.demoted("h1") {
		t.Fatal("h1 demoted with 1 of 4 observers failing; the bar is a third (2)")
	}
}

// A demoted host is restored only after RelayRestoreWindow with no failing
// observer, and one failing evaluation inside it starts it again.
//
// Mutation: restore on the first clean evaluation (ignore the restore
// window) — h1 is restored early, red.
func TestRelayHealth_RestoreOnlyAfterTheHealthyWindow(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	for i := 0; i < int(RelayDemoteWindow/relayPoll)+2 && !f.demoted("h1"); i++ {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatal("precondition: h1 demoted")
	}

	// Half the window clean, then one failing evaluation: the window restarts.
	start := f.clk
	for f.clk.Sub(start) < RelayRestoreWindow/2 {
		f.verdicts("h1")
		f.cycle()
	}
	f.verdicts("h1", "h4")
	f.cycle()

	clean := f.clk
	for f.clk.Sub(clean) < RelayRestoreWindow {
		f.verdicts("h1")
		f.cycle()
		if f.clk.Sub(clean) < RelayRestoreWindow && !f.demoted("h1") {
			t.Fatalf("h1 restored %s after the failing evaluation that restarted the window (%s after the first clean one), before the %s window",
				f.clk.Sub(clean), f.clk.Sub(start), RelayRestoreWindow)
		}
	}
	for i := 0; i < 2 && f.demoted("h1"); i++ {
		f.verdicts("h1")
		f.cycle()
	}
	if f.demoted("h1") {
		t.Fatalf("h1 still demoted after %s with no failing observer", f.clk.Sub(clean))
	}
	if !corrosion.RelayEligibleHosts(context.Background(), f.db)["h1"] {
		t.Fatal("restored h1 must be relay-eligible again")
	}
}

// Demotion never takes the eligible count below BaseRelays: with three hosts
// and BaseRelays 3, nothing is demoted however its probes fail.
//
// Mutation: drop the BaseRelays floor — h1 is demoted, red.
func TestRelayHealth_NeverBelowBaseRelays(t *testing.T) {
	f := newRelayFixture(t, 3, true)
	f.c.RelayConfig = corrosion.RelayConfig{BaseRelays: 3}
	for i := 0; i < int(2*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h2")
		f.cycle()
	}
	if f.demoted("h1") {
		t.Fatal("h1 demoted with 3 eligible hosts and BaseRelays 3")
	}
}

// Two hosts qualify in the same cycle: one change per cycle, so one is
// demoted on that cycle and the other on the next.
//
// Mutation: carry on after the first change — both rows land in one cycle,
// red.
func TestRelayHealth_AtMostOneChangePerCycle(t *testing.T) {
	f := newRelayFixture(t, 7, true)
	both := func() {
		f.verdicts("h1", "h3", "h4")
		f.verdicts("h2", "h3", "h4")
	}
	for i := 0; i < int(RelayDemoteWindow/relayPoll)+2 && f.demotionRows() == 0; i++ {
		both()
		f.cycle()
	}
	if got := f.demotionRows(); got != 1 {
		t.Fatalf("%d demotion rows on the first qualifying cycle, want exactly 1", got)
	}
	if !f.demoted("h1") {
		t.Fatal("name order is the tie-break: h1 first")
	}
	both()
	f.cycle()
	if !f.demoted("h2") {
		t.Fatal("h2 not demoted on the next cycle")
	}
}

// Before relay_health_v1 has latched, no demotion row is written however long
// a host's probes fail.
//
// Mutation: SetRelayDemotion without its gate check (corrosion) together with
// the evaluator's early return — a row lands, red.
func TestRelayHealth_NoRowBeforeTheLatch(t *testing.T) {
	f := newRelayFixture(t, 5, false)
	f.db.SetClusterPolicyGate(func() bool { return true }) // failover_scope_v1 latched, relay_health_v1 not
	for i := 0; i < int(2*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
	}
	if got := f.demotionRows(); got != 0 {
		t.Fatalf("%d demotion row(s) written before relay_health_v1 latched", got)
	}
}

// A gap in evaluation longer than RelayEvalGap — the lease was elsewhere —
// restarts the window: failures nobody evaluated are not counted.
func TestRelayHealth_EvaluationGapRestartsTheWindow(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	start := f.clk
	for f.clk.Sub(start) < RelayDemoteWindow-relayPoll {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
	}
	f.clk = f.clk.Add(RelayEvalGap + time.Second)
	f.verdicts("h1", "h2", "h3")
	f.cycle()
	if f.demoted("h1") {
		t.Fatal("h1 demoted on the first evaluation after a gap; the window must start again")
	}
}

// A fence candidate is fenced, not demoted: the evaluator is told which hosts
// a quorum sees dead and leaves them to the fence, however long their probes
// fail.
//
// Mutation: ignore the fence candidates — h1 is demoted, red.
func TestRelayHealth_FenceCandidateIsNotDemoted(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	ctx := context.Background()
	voters, err := corrosion.VoterSet(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < int(2*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h2", "h3")
		f.clk = f.clk.Add(relayPoll)
		f.c.evaluateRelayHealth(ctx, voters, map[string]bool{"h1": true})
	}
	if f.demoted("h1") {
		t.Fatal("a fence candidate was demoted; it is the fence's to handle")
	}
	// The same evaluations without the candidacy do demote: the test is not
	// vacuous.
	for i := 0; i < int(2*RelayDemoteWindow/relayPoll) && !f.demoted("h1"); i++ {
		f.verdicts("h1", "h2", "h3")
		f.clk = f.clk.Add(relayPoll)
		f.c.evaluateRelayHealth(ctx, voters, nil)
	}
	if !f.demoted("h1") {
		t.Fatal("control: h1 not demoted once it is no longer a fence candidate")
	}
}
