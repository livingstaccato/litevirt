// Fleet scenarios: retiring the hosts copy of a host's state and isolation
// (host_membership_retire_v1, colonelpanik/litevirt#267).
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// retireMembership is host_membership_split_v1 latched and its pass run, then
// host_membership_retire_v1 latched, on n.
func retireMembership(t *testing.T, n *Node) {
	t.Helper()
	splitMembership(t, n)
	n.DB.SetHostMembershipRetireGate(func() bool { return true })
}

// TestFleet_HostMembershipRetire_ConcurrentFenceAndVersionBothSurvive: after
// the retire latch a state change on node A and a version report on node B,
// made concurrently, both survive on every replica — in the resolved view AND
// in the hosts row itself, which a state change no longer writes. With the
// hosts copy still written (the dual-write build), the hosts row stays
// divergent: that half is TestFleet_HostMembership_ConcurrentStateAndVersionBothSurvive,
// which has to wait for convergence with hosts excluded.
func TestFleet_HostMembershipRetire_ConcurrentFenceAndVersionBothSurvive(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2671})
	a, b, subject := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		retireMembership(t, n)
	}
	settleByAntiEntropy(t, c, true)

	c.Isolate(a)
	c.Isolate(b)
	if err := corrosion.RecordFenceWithState(ctx, a.DB, corrosion.FenceLogRecord{
		ID: "f-retire", HostName: subject.Name, Method: "ipmi", Result: "fenced",
	}, "fenced"); err != nil {
		t.Fatalf("fence on %s: %v", a.Name, err)
	}
	time.Sleep(5 * time.Millisecond) // b's write is the newer one on every clock
	if err := corrosion.UpdateHostVersion(ctx, b.DB, subject.Name, "v-retire"); err != nil {
		t.Fatalf("version report on %s: %v", b.Name, err)
	}
	c.ClearLinkFaults()

	// Every table converges, hosts included.
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		h := hostOn(t, n, subject.Name)
		if h.State != "fenced" || h.Version != "v-retire" {
			t.Errorf("%s holds state=%q version=%q, want fenced and v-retire", n.Name, h.State, h.Version)
		}
		if got := oldColumn(t, n, `SELECT version FROM hosts WHERE name = ?`, subject.Name); got != "v-retire" {
			t.Errorf("%s: hosts.version = %q; the version report was lost to the fence", n.Name, got)
		}
	}
}

// TestFleet_HostMembershipRetire_APreviousBuildNodeReadsStateCorrectly: b
// stands for a host on the dual-write build (split latched and live, retire
// not). Retired a's state change and isolation, which no longer touch hosts, reach b
// through host_membership, and b's own dual-written state change reaches a.
func TestFleet_HostMembershipRetire_APreviousBuildNodeReadsStateCorrectly(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2672})
	a, b, subject := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	retireMembership(t, a)
	splitMembership(t, b)
	splitMembership(t, subject)
	settleByAntiEntropy(t, c, true)

	if err := corrosion.UpdateHostState(ctx, a.DB, subject.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := hostOn(t, b, subject.Name).State; got != "maintenance" {
		t.Errorf("%s (previous build) reads %s as %q after a retired state change, want maintenance", b.Name, subject.Name, got)
	}
	if votes(t, b, subject.Name) {
		t.Errorf("%s still counts %s, in maintenance, as a voter", b.Name, subject.Name)
	}

	if err := corrosion.IsolateHost(ctx, a.DB, a.Name, subject.Name, "manual"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if epoch, _, err := corrosion.HostIsolation(ctx, b.DB, subject.Name); err != nil || epoch == 0 {
		t.Errorf("%s does not see the retired isolation of %s (epoch %d, err %v)", b.Name, subject.Name, epoch, err)
	}

	if err := corrosion.UpdateHostState(ctx, b.DB, subject.Name, "active"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := hostOn(t, a, subject.Name).State; got != "active" {
		t.Errorf("%s reads %q after the previous build's dual-written change, want active", a.Name, got)
	}
}

// TestFleet_HostMembershipRetire_AMissedRowNeverUndoesAFence (review H1). With
// the hosts copy retired, a fence moves only host_membership, while unrelated
// writes (a region change) keep moving the hosts row's clock over a hosts.state
// that still says 'active'. A node that holds the hosts row but has lost or
// not yet received the host's membership row must not copy that stale state
// back — at the hosts row's newer time it would beat the fence everywhere. It
// reads the host as unknown until anti-entropy brings the row, and every node
// keeps reading it fenced.
func TestFleet_HostMembershipRetire_AMissedRowNeverUndoesAFence(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2673})
	a, b, n := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	h := n.Name
	for _, node := range c.Nodes {
		retireMembership(t, node)
	}
	settleByAntiEntropy(t, c, true)

	if err := corrosion.RecordFenceWithState(ctx, a.DB, corrosion.FenceLogRecord{
		ID: "f-h1", HostName: h, Method: "ipmi", Result: "fenced",
	}, "fenced"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.UpdateHostRegion(ctx, b.DB, h, "eu-west"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := oldColumn(t, n, `SELECT state FROM hosts WHERE name = ?`, h); got == "fenced" {
		t.Fatalf("hosts.state follows the fence (%q); the scenario needs the retired copy", got)
	}

	// n misses the row (a merge that brought hosts but not host_membership).
	n.DB.Mu().Lock()
	_, err := n.DB.DB().Exec(`DELETE FROM host_membership WHERE host_name = ?`, h)
	n.DB.Mu().Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := n.DB.SplitHostMembership(ctx); err != nil {
		t.Fatal(err)
	}
	if got := hostOn(t, n, h).State; got == "active" {
		t.Errorf("%s reads the fenced host as active from the frozen hosts copy", n.Name)
	}
	time.Sleep(time.Second) // let anything the pass wrote replicate
	for _, node := range []*Node{a, b} {
		if got := hostOn(t, node, h).State; got != "fenced" {
			t.Errorf("%s reads %s as %q after %s's pass, want fenced: a copy undid the fence", node.Name, h, got, n.Name)
		}
	}
	corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	if got := hostOn(t, n, h).State; got != "fenced" {
		t.Errorf("%s reads %q after anti-entropy, want fenced", n.Name, got)
	}
}

// TestFleet_HostMembershipRetire_ANotLiveNodeReadsTheRetiredFence (review M1):
// a node whose own split latch has not formed must still read a fence made
// after the retire latch, from the membership row it received — not the
// frozen hosts copy.
func TestFleet_HostMembershipRetire_ANotLiveNodeReadsTheRetiredFence(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2674})
	a, d, h := c.Nodes[0], c.Nodes[3], c.Nodes[2].Name
	c.WaitConverged(t, convergeTimeout)
	for _, node := range c.Nodes[:3] {
		retireMembership(t, node)
	}
	settleByAntiEntropy(t, c, true)
	if err := corrosion.RecordFenceWithState(ctx, a.DB, corrosion.FenceLogRecord{
		ID: "f-m1", HostName: h, Method: "ipmi", Result: "fenced",
	}, "fenced"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if d.DB.HostMembershipLive() {
		t.Fatal("the fourth node is live; the scenario needs one that is not")
	}
	if got := oldColumn(t, d, `SELECT state FROM hosts WHERE name = ?`, h); got == "fenced" {
		t.Fatalf("hosts.state on %s says fenced; the scenario needs the retired copy", d.Name)
	}
	if got := hostOn(t, d, h).State; got != "fenced" {
		t.Errorf("%s (not live) reads %s as %q, want fenced: it read the frozen hosts copy", d.Name, h, got)
	}
}

// TestFleet_HostMembershipRetire_ANotLiveNeighboursDrainReachesARetiredNode
// backs keeping the absorb (review L5): latches form per node, so a neighbour
// whose split latch has not formed writes a drain to hosts alone, and a
// retired node must take it into its membership row.
func TestFleet_HostMembershipRetire_ANotLiveNeighboursDrainReachesARetiredNode(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2675})
	a, b, h := c.Nodes[0], c.Nodes[1], c.Nodes[2].Name
	c.WaitConverged(t, convergeTimeout)
	retireMembership(t, a)
	settleByAntiEntropy(t, c, true)
	if err := corrosion.UpdateHostState(ctx, b.DB, h, "draining"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := hostOn(t, a, h).State; got != "draining" {
		t.Errorf("%s (retired) reads %s as %q after a not-live neighbour's drain, want draining", a.Name, h, got)
	}
}

// TestFleet_HostMembershipRetire_TheCoordinatorNeverFencesAnUnknownHost
// (re-review I2): a coordinator that has no membership row for a failed host —
// on a retired node it reads the host as unknown — neither fences nor recovers
// it until the row arrives. It may be in maintenance or still joining, and a
// fence is irrevocable. Once anti-entropy brings the row back (active), the
// next cycle fences it as usual.
func TestFleet_HostMembershipRetire_TheCoordinatorNeverFencesAnUnknownHost(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2676})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	insertVM(t, a, "vm-unknown", victim.Name)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		retireMembership(t, n)
	}
	settleByAntiEntropy(t, c, true)

	// The observations come after the host's current life began (its
	// membership row dates it from its hosts row, HostFenceLife).
	clock := NewVirtualClock(time.Now().UTC())
	c.Isolate(victim)
	PublishHealthRun(t, a, victim.Name, 5, clock.Now(), clock.Now())
	PublishHealthRun(t, b, victim.Name, 5, clock.Now(), clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)

	// a misses victim's membership row (a merge that brought hosts but not
	// host_membership), after everything else has converged.
	a.DB.Mu().Lock()
	_, err := a.DB.DB().Exec(`DELETE FROM host_membership WHERE host_name = ?`, victim.Name)
	a.DB.Mu().Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if got := hostOn(t, a, victim.Name).State; got != corrosion.HostStateUnknown {
		t.Fatalf("precondition: %s reads %s as %q, want unknown", a.Name, victim.Name, got)
	}
	cs := c.NewCoordinators(clock)
	cs.Tick(ctx, a)
	if f := cs.Fences(); len(f) != 0 {
		t.Fatalf("%s fenced %+v while it could not read %s's state", a.Name, f, victim.Name)
	}

	corrosion.NewAntiEntropy(a.DB, a.PKIDir, 0).RunOnce(ctx)
	if got := hostOn(t, a, victim.Name).State; got != "active" {
		t.Fatalf("the membership row did not come back by anti-entropy (%q)", got)
	}
	cs.Tick(ctx, a)
	if f := cs.Fences(); len(f) != 1 || f[0].Target != victim.Name {
		t.Errorf("once the row arrived, expected one fence of %s, got %+v", victim.Name, f)
	}
}
