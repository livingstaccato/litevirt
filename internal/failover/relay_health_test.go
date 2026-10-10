package failover

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// relayFixture is a lease-holding coordinator over hosts h1..hN, all active
// workers (and so all voters), with the demotion gates open unless latched is
// false.
//
// Verdicts are written the way health.Checker writes them, because the
// evaluator's correctness depends on it: a HEALTHY verdict is written once,
// on a change, and then stands, aging past the freshness window; a FAILING
// verdict is re-written on every probe with its count climbing, so it stays
// fresh. A fixture that re-stamped every verdict every cycle could not tell
// "one failing observer of four" from "one of one".
type relayFixture struct {
	t     *testing.T
	db    *corrosion.Client
	c     *Coordinator
	clk   time.Time
	hosts []string
	last  map[[2]string]int // (observer, target) → last published failure count
}

const relayPoll = 5 * time.Second // the production pollInterval

func newRelayFixture(t *testing.T, n int, latched bool) *relayFixture {
	t.Helper()
	db := newTestDB(t)
	f := &relayFixture{t: t, db: db, clk: time.Now().UTC().Truncate(time.Second), last: map[[2]string]int{}}
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
	f.members(f.hosts...)
	f.steady()
	return f
}

// members sets the gossip membership the coordinator's floor counts over
// (self excluded, as Members() reports it).
func (f *relayFixture) members(names ...string) {
	var ps []corrosion.PeerInfo
	for _, n := range names {
		if n != f.c.hostName {
			ps = append(ps, corrosion.PeerInfo{Name: n})
		}
	}
	f.db.SetMembersForTests(func() []corrosion.PeerInfo { return ps })
}

// down takes hosts out of service (fenced), as a multi-host incident does:
// every live observer keeps failing them with a climbing count, and gossip
// no longer lists them.
func (f *relayFixture) down(hosts ...string) {
	f.t.Helper()
	isDown := map[string]bool{}
	for _, h := range hosts {
		isDown[h] = true
		if err := corrosion.UpdateHostState(context.Background(), f.db, h, "fenced"); err != nil {
			f.t.Fatalf("fence %s: %v", h, err)
		}
	}
	var up []string
	for _, h := range f.hosts {
		if !isDown[h] {
			up = append(up, h)
		}
	}
	f.members(up...)
}

// failDown is one probe round of the down hosts by every live host.
func (f *relayFixture) failDown(down ...string) {
	f.t.Helper()
	for _, d := range down {
		var live []string
		for _, h := range f.hosts {
			if !contains(down, h) {
				live = append(live, h)
			}
		}
		f.verdicts(d, live...)
	}
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

// steady is the cluster's first probe round — every observer publishes a
// healthy verdict on every peer, once — followed by a minute of nothing
// changing, so every one of those verdicts is older than healthFreshness.
func (f *relayFixture) steady() {
	f.t.Helper()
	for _, o := range f.hosts {
		for _, t := range f.hosts {
			if o != t {
				f.publish(o, t, 0)
			}
		}
	}
	f.clk = f.clk.Add(time.Minute)
}

func (f *relayFixture) publish(observer, target string, failures int) {
	f.t.Helper()
	status := "healthy"
	if failures >= 3 {
		status = "suspect"
	}
	if err := f.db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, ?, ?, ?, NULL, ?)`,
		observer, target, status, failures, f.clk.Format(time.RFC3339Nano)); err != nil {
		f.t.Fatalf("publish %s→%s: %v", observer, target, err)
	}
	f.last[[2]string{observer, target}] = failures
}

// verdicts is one probe of target by every other host: the observers in
// failing fail it (their count climbs and is re-published), every other one
// answers — published only if that is a change.
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
		k := [2]string{o, target}
		if bad[o] {
			f.publish(o, target, f.last[k]+1)
		} else if f.last[k] != 0 {
			f.publish(o, target, 0)
		}
	}
}

// cycle advances the clock one poll and runs the coordinator.
func (f *relayFixture) cycle() {
	f.clk = f.clk.Add(relayPoll)
	f.c.run(context.Background())
}

// demoteH1 drives h1 to demotion with h2 and h3 failing it.
func (f *relayFixture) demoteH1() {
	f.t.Helper()
	for i := 0; i < int(RelayDemoteWindow/relayPoll)+2 && !f.demoted("h1"); i++ {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
	}
	if !f.demoted("h1") {
		f.t.Fatal("precondition: h1 demoted")
	}
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

// A third of the voter observers (2 of 4) failing on every evaluation for the
// whole window demotes the host, and not one poll sooner — with the two
// healthy observers' verdicts long past healthFreshness, as in production.
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
}

// One failing observer of four is below the bar (a third: 2). In steady state
// the three healthy verdicts are older than healthFreshness, and must still
// count: they are standing verdicts the checker does not re-publish.
//
// Mutation: count only FRESH verdicts in the denominator (the round-0 code) —
// h1 reads 1/1 and is demoted, red.
func TestRelayHealth_OneFailingObserverInSteadyStateNeverDemotes(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	for i := 0; i < int(3*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h2")
		f.cycle()
	}
	if f.demoted("h1") {
		t.Fatal("h1 demoted with 1 of 4 observers failing; the bar is a third (2)")
	}
}

// A voter whose verdict has not reached the lease holder's replica yet — its
// first probe has not replicated, or it has not probed — is not evidence of
// failure. One failing observer with only three verdicts on the replica is
// still one of FOUR voters, below the bar. (The fleet run caught this under
// load: "1 of 3 voter observers".)
//
// Mutation: count the verdicts held instead of the voters — 1/3 reaches the
// bar and h1 is demoted, red.
func TestRelayHealth_AVoterWithNoVerdictYetIsNotMissingFromTheBar(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	if err := f.db.Execute(context.Background(),
		`DELETE FROM host_health WHERE observer = 'h4' AND target = 'h1'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < int(3*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h2")
		f.cycle()
		if err := f.db.Execute(context.Background(),
			`DELETE FROM host_health WHERE observer = 'h4' AND target = 'h1'`); err != nil {
			t.Fatal(err)
		}
	}
	if f.demoted("h1") {
		t.Fatal("h1 demoted with 1 failing observer of 4 voters, one of them not yet heard from")
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

// After the link heals, each observer publishes ONE healthy verdict and then
// nothing; those verdicts age past healthFreshness long before the window
// ends, and the host must still be restored after RelayRestoreWindow — and
// not sooner. An evaluation at the bar inside the window starts it again.
//
// Mutations: (1) count only fresh verdicts (the round-0 code) — the healed
// verdicts age out, no observer is left, and h1 is never restored, red;
// (2) restore without the window — red; (3) a failing evaluation does not
// restart the window — red.
func TestRelayHealth_RestoreAfterTheWindowFromStandingVerdicts(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	f.demoteH1()

	start := f.clk
	for f.clk.Sub(start) < RelayRestoreWindow/2 {
		f.verdicts("h1")
		f.cycle()
	}
	f.verdicts("h1", "h3", "h4") // at the bar again: the window restarts
	f.cycle()

	clean := f.clk
	for f.clk.Sub(clean) < RelayRestoreWindow {
		f.verdicts("h1")
		f.cycle()
		if f.clk.Sub(clean) < RelayRestoreWindow && !f.demoted("h1") {
			t.Fatalf("h1 restored %s after the evaluation that restarted the window (%s after the heal), before the %s window",
				f.clk.Sub(clean), f.clk.Sub(start), RelayRestoreWindow)
		}
	}
	for i := 0; i < 2 && f.demoted("h1"); i++ {
		f.verdicts("h1")
		f.cycle()
	}
	if f.demoted("h1") {
		t.Fatalf("h1 still demoted %s after the link healed", f.clk.Sub(clean))
	}
	if !corrosion.RelayEligibleHosts(context.Background(), f.db)["h1"] {
		t.Fatal("restored h1 must be relay-eligible again")
	}
}

// One observer that keeps failing a demoted host — below the demotion bar —
// must not hold the demotion in place for good.
//
// Mutation: restore only with ZERO failing observers — h1 stays demoted, red.
func TestRelayHealth_OneFlakyObserverDoesNotHoldADemotion(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	f.demoteH1()
	for i := 0; i < int(RelayRestoreWindow/relayPoll)+3 && f.demoted("h1"); i++ {
		f.verdicts("h1", "h2")
		f.cycle()
	}
	if f.demoted("h1") {
		t.Fatal("h1 still demoted with 1 of 4 observers failing for the whole restore window")
	}
}

// Silence is not health: with no verdict on a demoted host from any active
// observer, it is not restored.
//
// Mutation: drop the active-observer requirement — h1 is restored on nothing,
// red.
func TestRelayHealth_NoRestoreWithoutALiveObserver(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	f.demoteH1()
	if err := f.db.Execute(context.Background(), `DELETE FROM host_health WHERE target = 'h1'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < int(2*RelayRestoreWindow/relayPoll); i++ {
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatal("h1 restored with no observer vouching for it")
	}
}

// Two hosts whose OWN outbound probes fail (a client-side fault) fail every
// peer. Counted, they put every healthy host at 2/6 — the bar — and the lease
// holder would demote healthy hosts down to the floor while the faulty ones
// stay relays. An observer failing more than half of what it observes is
// discounted.
//
// Mutation: no discount — a healthy host is demoted, red.
func TestRelayHealth_AnObserverFaultIsNotBlamedOnItsTargets(t *testing.T) {
	f := newRelayFixture(t, 7, true)
	for i := 0; i < int(2*RelayDemoteWindow/relayPoll); i++ {
		for _, target := range f.hosts {
			var failing []string
			for _, bad := range []string{"h6", "h7"} {
				if bad != target {
					failing = append(failing, bad)
				}
			}
			f.verdicts(target, failing...)
		}
		f.cycle()
	}
	if got := f.demotionRows(); got != 0 {
		d, _ := corrosion.ListRelayDemotions(context.Background(), f.db)
		t.Fatalf("%d host(s) demoted for two observers' own fault: %v", got, d)
	}
}

// Demotion never takes the eligible count below BaseRelays: with three hosts
// and BaseRelays 3, nothing is demoted however its probes fail.
//
// Mutation: drop the floor — h1 is demoted, red.
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

// The floor is R, the relay count of the election, not BaseRelays: with five
// members and the default base of 3, R is 4. A second demotion would leave 3
// eligible, and the election would fill the fourth relay slot back from the
// demoted hosts in name order — the row written, the WARN logged, and
// nothing changed. The first demotion goes ahead; the second does not.
//
// Mutation: floor at BaseRelays only — h2 is demoted too, red.
func TestRelayHealth_NeverBelowTheRelayCount(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	f.c.RelayConfig = corrosion.RelayConfig{} // production defaults: base 3, 50 per relay
	f.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "h1"}, {Name: "h2"}, {Name: "h3"}, {Name: "h4"}}
	})
	for i := 0; i < int(3*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h3", "h4")
		f.verdicts("h2", "h3", "h4")
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatal("h1 not demoted: 5 eligible, R = 4, one demotion fits")
	}
	if f.demoted("h2") {
		t.Fatal("h2 demoted too: 3 eligible is below R = 4, so the election would re-elect a demoted host")
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
//
// Mutation: no gap reset — h1 is demoted on the first evaluation after the
// gap, red.
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

// A demotion row for a host that has been removed is cleared, so a host later
// added under the same name does not start out demoted.
//
// Mutation: skip removed hosts' rows — the row stays demoted, red.
func TestRelayHealth_RemovedHostsDemotionIsCleared(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	if err := corrosion.SetRelayDemotion(context.Background(), f.db, "ghost",
		corrosion.RelayDemotion{Demoted: true, Since: f.clk.Format(time.RFC3339), Reason: "test"}, "h5"); err != nil {
		t.Fatal(err)
	}
	f.cycle()
	if f.demoted("ghost") {
		t.Fatal("a removed host's demotion row was left demoted")
	}
}

// An operator's restore with a hold (`lv cluster relay-restore --hold`) keeps
// the lease holder from demoting the host again until the hold runs out —
// the stand-down when the evaluator keeps re-deriving a demotion from a fault
// that is not the host's. After the hold, the ordinary window applies.
//
// Mutation: ignore the hold — h1 is demoted again inside it, red.
func TestRelayHealth_OperatorHoldPreventsDemotion(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	hold := 5 * time.Minute
	if err := corrosion.SetRelayHold(context.Background(), f.db, "h1", corrosion.RelayHold{
		Until: f.clk.Add(hold).Format(time.RFC3339), Since: f.clk.Format(time.RFC3339), By: "admin",
	}, "admin"); err != nil {
		t.Fatal(err)
	}
	start := f.clk
	for f.clk.Sub(start) < hold-relayPoll {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
		if f.demoted("h1") {
			t.Fatalf("h1 demoted %s into a %s operator hold", f.clk.Sub(start), hold)
		}
	}
	for i := 0; i < int(2*RelayDemoteWindow/relayPoll) && !f.demoted("h1"); i++ {
		f.verdicts("h1", "h2", "h3")
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatal("h1 not demoted after the hold ran out")
	}
	var h corrosion.RelayHold
	rows, _ := f.db.Query(context.Background(), `SELECT value FROM cluster_policies WHERE key = 'relay_hold/h1'`)
	if len(rows) != 1 || json.Unmarshal([]byte(rows[0].String("value")), &h) != nil || h.By != "admin" {
		t.Fatalf("the operator's hold row must be untouched by the evaluator: %v", rows)
	}
}

// The evaluator's demotion row and an operator's hold are different rows, so
// the evaluator's last-writer-wins write can never erase a hold: a demotion
// that raced the hold's replication (written after it, by a lease holder
// that had not seen it) leaves the hold in place, and the next evaluation
// restores the host because a hold is in force.
//
// Mutation: do not restore a host found demoted under a hold — it stays
// demoted for the whole hold, red.
func TestRelayHealth_AHoldSurvivesARacingDemotion(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	ctx := context.Background()
	if err := corrosion.SetRelayHold(ctx, f.db, "h1", corrosion.RelayHold{
		Until: f.clk.Add(time.Hour).Format(time.RFC3339), By: "admin",
	}, "admin"); err != nil {
		t.Fatal(err)
	}
	// The racing lease holder's demotion, written after the hold.
	if err := corrosion.SetRelayDemotion(ctx, f.db, "h1",
		corrosion.RelayDemotion{Demoted: true, Since: f.clk.Format(time.RFC3339), Reason: "raced"}, "h5"); err != nil {
		t.Fatal(err)
	}
	f.verdicts("h1", "h2", "h3")
	f.cycle()
	if f.demoted("h1") {
		t.Fatal("h1 left demoted under an operator hold")
	}
	holds, _ := corrosion.ListRelayHolds(ctx, f.db)
	if !holds["h1"].Active(f.clk) || holds["h1"].By != "admin" {
		t.Fatalf("the hold did not survive the evaluator: %+v", holds["h1"])
	}
}

// A multi-host incident: two hosts are fenced (every live observer fails them,
// freshly, every probe), and two more, X and Y, have degraded links that
// observers h3 and h4 fail. h3 and h4 then fail 4 of the 6 hosts they hold a
// verdict on — but two of those are DOWN, which says nothing about h3 and h4.
// Counted, the discount removes exactly the observers that see the fault and
// X is never demoted.
//
// Mutation: count verdicts about every host in the discount (round 1) — h3
// and h4 are discounted and X is not demoted, red.
func TestRelayHealth_HostsDownDoNotDiscountTheirObservers(t *testing.T) {
	f := newRelayFixture(t, 7, true) // the lease holder is h7
	f.down("h5", "h6")
	for i := 0; i < int(3*RelayDemoteWindow/relayPoll) && !f.demoted("h1"); i++ {
		f.failDown("h5", "h6")
		f.verdicts("h1", "h3", "h4")
		f.verdicts("h2", "h3", "h4")
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatal("h1 not demoted: 2 of 4 live voter observers fail it, while two other hosts are down")
	}
}

// The same with three hosts down, and with stale tombstoned rows and rows
// about removed hosts in the observers' history: none of them is a host the
// evaluator judges, so none counts toward an observer's discount.
//
// Mutations: as above — red; and counting tombstoned rows about live hosts
// in the discount — h3 is discounted, red.
func TestRelayHealth_TombstonedAndRemovedRowsDoNotDiscount(t *testing.T) {
	f := newRelayFixture(t, 8, true) // the lease holder is h8
	f.down("h5", "h6", "h7")
	ctx := context.Background()
	// h3 once observed hosts since removed (rows left behind, some
	// tombstoned), and its last verdicts on them were failing.
	for i, ghost := range []string{"g1", "g2", "g3", "g4"} {
		deleted := "NULL"
		if i%2 == 0 {
			deleted = "'" + f.clk.Format(time.RFC3339) + "'"
		}
		if err := f.db.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at, deleted_at)
			 VALUES ('h3', ?, 'suspect', 9, NULL, ?, `+deleted+`)`, ghost, f.clk.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	// Tombstoned failing verdicts about two live hosts, too: counted, they
	// alone put h3 over half of the live hosts it observes.
	if err := f.db.Execute(ctx, `UPDATE host_health SET consecutive_failures = 7, updated_at = ?, deleted_at = ?
		WHERE observer = 'h3' AND target IN ('h2', 'h4')`, f.clk.Format(time.RFC3339Nano), f.clk.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < int(3*RelayDemoteWindow/relayPoll) && !f.demoted("h1"); i++ {
		f.failDown("h5", "h6", "h7")
		f.verdicts("h1", "h3", "h4")
		// Those rows stay fresh, as a previous-release receiver's copy of a
		// live verdict marked deleted does (observation_replace.go).
		if err := f.db.Execute(ctx, `UPDATE host_health SET updated_at = ?
			WHERE observer = 'h3' AND (target LIKE 'g%' OR target IN ('h2', 'h4'))`, f.clk.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatal("h1 not demoted: 2 of 4 live voter observers fail it")
	}
}

// Under a small voter set — an adopted generation of 3 in a 6-host cluster —
// a third of the observers is a single voter's view. The bar is never below
// 2, and with 4 or fewer voters it is a majority of them; the same rule for
// a voter and a non-voter target.
//
// Mutation: the bar without its floors (a third, minimum one) — h5 and h2 are
// demoted on one voter's word, red.
func TestRelayHealth_ASmallVoterSetNeedsAMajority(t *testing.T) {
	f := newRelayFixture(t, 6, true)
	ctx := context.Background()
	voters := map[string]bool{"h1": true, "h2": true, "h3": true}
	run := func(target string, failing ...string) {
		for i := 0; i < int(3*RelayDemoteWindow/relayPoll) && !f.demoted(target); i++ {
			f.verdicts(target, failing...)
			f.clk = f.clk.Add(relayPoll)
			f.c.evaluateRelayHealth(ctx, voters, nil)
		}
	}
	run("h5", "h1") // non-voter target, one voter failing
	if f.demoted("h5") {
		t.Fatal("non-voter h5 demoted on one of three voters' word")
	}
	run("h2", "h1") // voter target, one voter failing
	if f.demoted("h2") {
		t.Fatal("voter h2 demoted on one of three voters' word")
	}
	run("h4", "h1", "h2") // control: a majority of the voters
	if !f.demoted("h4") {
		t.Fatal("control: h4 not demoted with 2 of 3 voters failing it")
	}
}

// The floor counts only hosts the election can see: an active host missing
// from gossip membership is never elected, so counting it toward the floor
// let a demotion through that the election then filled back in.
//
// Mutation: count every active host toward the floor — h2 is demoted too, red.
func TestRelayHealth_TheFloorCountsOnlyMembers(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	f.members("h1", "h2", "h3") // h4 active but not in membership; self h5
	for i := 0; i < int(3*RelayDemoteWindow/relayPoll); i++ {
		f.verdicts("h1", "h3", "h4")
		f.verdicts("h2", "h3", "h4")
		f.cycle()
	}
	if !f.demoted("h1") {
		t.Fatal("h1 not demoted: 4 member hosts eligible, R = 3, one demotion fits")
	}
	if f.demoted("h2") {
		t.Fatal("h2 demoted too: 2 member hosts left eligible is below R = 3")
	}
}

// Never on one observer's word, whatever the cluster size: with two of five
// voters discounted (they fail every host), three are counted, a third of the
// two observers a voter host has is one — and one failing observer is still
// not enough.
//
// Mutation: drop the floor of 2 — h1 is demoted on h3's word alone, red.
func TestRelayHealth_NeverOnOneObserversWord(t *testing.T) {
	f := newRelayFixture(t, 5, true)
	ctx := context.Background()
	voters, err := corrosion.VoterSet(ctx, f.db)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < int(3*RelayDemoteWindow/relayPoll); i++ {
		for _, target := range f.hosts {
			var failing []string
			for _, bad := range []string{"h4", "h5"} {
				if bad != target {
					failing = append(failing, bad)
				}
			}
			if target == "h1" {
				failing = append(failing, "h3")
			}
			f.verdicts(target, failing...)
		}
		f.clk = f.clk.Add(relayPoll)
		f.c.evaluateRelayHealth(ctx, voters, nil)
	}
	if f.demoted("h1") {
		t.Fatal("h1 demoted on one counted observer's word")
	}
}
