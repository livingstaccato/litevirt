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
	c.WaitConverged(t, convergeTimeout)

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
	c.WaitConverged(t, convergeTimeout)

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
