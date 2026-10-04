// Fleet scenarios: host state and isolation on a row of their own
// (colonelpanik/litevirt#267).
//
// hosts is one row with one updated_at and many writers. Two of them — the
// coordinator or an operator moving a host's state, and that host's daemon
// reporting its version — are different columns under the same clock, so a
// replica that applies the newer write first refuses the older one and loses
// it. The failure is multi-node by construction: it needs two writers and a
// replica that sees them in the opposite order to the one that wrote last. So
// it is driven here, over real replication between independent replicas.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// splitMembership is host_membership_split_v1 latching on n: the gate opens
// and the node runs its first pass, as the daemon's split loop would.
func splitMembership(t *testing.T, n *Node) corrosion.HostMembershipReport {
	t.Helper()
	n.DB.SetHostMembershipGate(func() bool { return true })
	rep, err := n.DB.SplitHostMembership(context.Background())
	if err != nil {
		t.Fatalf("%s: split pass: %v", n.Name, err)
	}
	if !n.DB.HostMembershipLive() {
		t.Fatalf("%s: a complete split pass did not make the node live", n.Name)
	}
	return rep
}

func hostOn(t *testing.T, n *Node, name string) *corrosion.HostRecord {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), n.DB, name)
	if err != nil || h == nil {
		t.Fatalf("%s: GetHost %s: %+v %v", n.Name, name, h, err)
	}
	return h
}

func votes(t *testing.T, n *Node, host string) bool {
	t.Helper()
	voters, err := corrosion.VoterSet(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("%s: VoterSet: %v", n.Name, err)
	}
	return voters[host]
}

func assertNoMembershipStatements(t *testing.T, n *Node) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", n.Name, err)
	}
	for _, r := range rows {
		if strings.Contains(r.String("stmts"), "host_membership") {
			t.Fatalf("%s put a host_membership statement on its replication stream before the latch. "+
				"A previous-release peer has no ledger entry for it, so its apply fails closed and its "+
				"watermark stalls:\n%s", n.Name, r.String("stmts"))
		}
	}
}

// concurrentStateAndVersion has a write the coordinator owns (a's drain of
// subject) and one the subject's daemon owns (b's version report) cross on the
// wire: every link is down while both are made, b's strictly later, and then
// the links heal. It returns each node's resulting (state, version) of subject.
func concurrentStateAndVersion(t *testing.T, split bool) map[string][2]string {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 267})
	a, b, subject := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	if split {
		for _, n := range c.Nodes {
			splitMembership(t, n)
		}
		c.WaitConverged(t, convergeTimeout)
	}

	// No relay either: with three nodes every node relays, so a's drain could
	// reach b through subject before b writes.
	c.Isolate(a)
	c.Isolate(b)
	if err := corrosion.UpdateHostState(ctx, a.DB, subject.Name, "draining"); err != nil {
		t.Fatalf("drain on %s: %v", a.Name, err)
	}
	time.Sleep(5 * time.Millisecond) // b's write is the newer one on every clock
	if err := corrosion.UpdateHostVersion(ctx, b.DB, subject.Name, "v-267"); err != nil {
		t.Fatalf("version report on %s: %v", b.Name, err)
	}
	c.ClearLinkFaults()

	if split {
		// hosts itself still diverges: its state column is the previous
		// release's copy, dual-written for a rolled-back reader, and it keeps
		// the previous release's shared clock and the #267 loss with it. The
		// membership copy is the one that must converge.
		c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	} else {
		// Without the split the replicas never converge — that is the bug — so
		// wait for both writes to have been delivered everywhere instead: the
		// version is the newer write, and a node holding it has applied or
		// refused the drain.
		eventually(t, convergeTimeout, "the version report everywhere", func() bool {
			for _, n := range c.Nodes {
				if hostOn(t, n, subject.Name).Version != "v-267" {
					return false
				}
			}
			return true
		})
		time.Sleep(500 * time.Millisecond)
	}
	out := map[string][2]string{}
	for _, n := range c.Nodes {
		h := hostOn(t, n, subject.Name)
		out[n.Name] = [2]string{h.State, h.Version}
	}
	return out
}

// TestFleet_HostMembership_ConcurrentStateAndVersionBothSurvive: a state
// change and a version report made concurrently on two nodes both survive on
// every replica once host state has its own row.
//
// The first subtest is the RED half and must keep failing to reproduce the
// loss: without it the second could pass on a scenario that never raced.
func TestFleet_HostMembership_ConcurrentStateAndVersionBothSurvive(t *testing.T) {
	t.Run("before the split one replica loses the drain", func(t *testing.T) {
		got := concurrentStateAndVersion(t, false)
		lost := 0
		for _, sv := range got {
			if sv[0] != "draining" {
				lost++
			}
		}
		if lost == 0 {
			t.Fatalf("every replica kept both writes with the shared hosts clock: %v. The scenario "+
				"did not race, so the post-split half proves nothing", got)
		}
	})

	t.Run("after the split both survive on every replica", func(t *testing.T) {
		for node, sv := range concurrentStateAndVersion(t, true) {
			if sv[0] != "draining" || sv[1] != "v-267" {
				t.Errorf("%s holds state=%q version=%q, want draining and v-267: a write to one "+
					"column of the host was lost to a concurrent write to another", node, sv[0], sv[1])
			}
		}
	})
}

// TestFleet_HostMembership_ARollKeepsFencingAndTheVoterSet: host state and the
// voter set stay right at every stage of a roll, and a fence works at the end.
//
// Stage 1, nothing latched — the state for as long as any previous-release
// host is listening. Nothing naming host_membership may reach any replication
// stream, and state lives in hosts.state where that host reads it.
//
// Stage 2, one node latched and its neighbour not yet. An operator drains the
// victim through the UNLATCHED node, which writes hosts.state only — an entry
// with no host_membership statement in it. The latched node absorbs that write
// into its own host_membership row as it applies the entry, so its voter set
// drops the victim at once. A latched node that ignored hosts-only writes would
// keep counting a host in maintenance as a voter. The absorbed row is local; the
// nodes that latch later learn it by anti-entropy.
//
// Stage 3, the roll completes. The victim fails and a coordinator fences it:
// every node reads it fenced and out of the voter set, and hosts.state — still
// written, for a node rolled back one release — says fenced too.
func TestFleet_HostMembership_ARollKeepsFencingAndTheVoterSet(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2671})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	insertVM(t, a, "vm-victim", victim.Name)

	// Stage 1.
	if err := corrosion.UpdateHostState(ctx, b.DB, victim.Name, "draining"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(a).UndrainHost(ctx, &pb.UndrainHostRequest{Name: victim.Name}); err != nil {
		t.Fatalf("undrain via %s: %v", a.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		assertNoMembershipStatements(t, n)
		if got := oldColumn(t, n, `SELECT state FROM hosts WHERE name = ?`, victim.Name); got != "active" {
			t.Fatalf("%s: hosts.state = %q; a previous-release node would read the wrong state", n.Name, got)
		}
	}

	// Stage 2: a latches; b has not yet.
	if rep := splitMembership(t, a); rep.Copied != len(c.Nodes) {
		t.Fatalf("a's first pass copied %d hosts, want %d", rep.Copied, len(c.Nodes))
	}
	c.WaitConverged(t, convergeTimeout)
	if err := corrosion.UpdateHostState(ctx, b.DB, victim.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	// host_membership is apart by design here: a's row is its own absorbed copy.
	c.WaitConvergedExcept(t, convergeTimeout, []string{"host_membership"})
	if got := hostOn(t, a, victim.Name).State; got != "maintenance" {
		t.Fatalf("latched %s reads the victim %q after the unlatched %s put it in maintenance", a.Name, got, b.Name)
	}
	if votes(t, a, victim.Name) {
		t.Fatalf("latched %s still counts the victim as a voter after it went into maintenance", a.Name)
	}
	if _, err := c.SelfClient(b).UndrainHost(ctx, &pb.UndrainHostRequest{Name: victim.Name}); err != nil {
		t.Fatalf("undrain via %s: %v", b.Name, err)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"host_membership"})
	if got := hostOn(t, a, victim.Name).State; got != "active" {
		t.Fatalf("latched %s reads the victim %q after the unlatched %s undrained it", a.Name, got, b.Name)
	}

	// Stage 3: b and the victim latch, and anti-entropy brings them a's
	// absorbed row.
	splitMembership(t, b)
	splitMembership(t, victim)
	b.DB.MergeStateBytesLWW(pullDump(t, c, a))
	victim.DB.MergeStateBytesLWW(pullDump(t, c, a))
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	for _, n := range c.Nodes {
		if got := hostOn(t, n, victim.Name).State; got != "active" {
			t.Fatalf("%s reads the victim %q after the roll, want active", n.Name, got)
		}
		if !votes(t, n, victim.Name) {
			t.Fatalf("%s does not count the active victim as a voter", n.Name)
		}
	}

	c.Isolate(victim)
	// The victim fails now, after the undrain made it active: its
	// observations are stamped after that, or the coordinator rightly reads
	// them as about the host before it turned active (HostsActiveSince).
	clock = NewVirtualClock(time.Now().UTC())
	PublishHealth(t, a, victim.Name, 5, clock.Now())
	PublishHealth(t, b, victim.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)
	cs := c.NewCoordinators(clock)
	cs.Tick(ctx, a)
	if fences := cs.Fences(); len(fences) != 1 || fences[0].Target != victim.Name {
		t.Fatalf("expected one fence of %s, got %+v", victim.Name, fences)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		if got := hostOn(t, n, victim.Name).State; got != "fenced" {
			t.Errorf("%s reads the fenced victim as %q", n.Name, got)
		}
		if votes(t, n, victim.Name) {
			t.Errorf("%s still counts the fenced victim as a voter", n.Name)
		}
		if got := oldColumn(t, n, `SELECT state FROM hosts WHERE name = ?`, victim.Name); got != "fenced" {
			t.Errorf("%s: hosts.state = %q after the fence; a node rolled back one release reads "+
				"only that column and would count the fenced victim as live", n.Name, got)
		}
	}
}

// oldVoters is the voter set a PREVIOUS-RELEASE node computes: its VoterSet
// read name and state from hosts and nothing else. This harness runs one
// binary, so that reader is stood in for by the exact query it ran.
func oldVoters(t *testing.T, n *Node) map[string]bool {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT name, state FROM hosts WHERE deleted_at IS NULL`)
	if err != nil {
		t.Fatalf("%s: old voter query: %v", n.Name, err)
	}
	out := map[string]bool{}
	for _, r := range rows {
		if corrosion.VotingEligible(r.String("state")) {
			out[r.String("name")] = true
		}
	}
	return out
}

// TestFleet_HostMembership_ARollbackOneReleaseStillReadsTheOldColumns: after
// host_membership_split_v1 has latched on every node, a node rolled back to the
// previous release — which reads state and isolation from hosts and nothing
// else — still sees every state change and isolation made through latched
// nodes. That holds only because every live writer ALSO writes the hosts
// columns, in their previous-release shapes; nothing in this release clears or
// freezes them.
func TestFleet_HostMembership_ARollbackOneReleaseStillReadsTheOldColumns(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2672})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	// Every node's hosts rows must have arrived before the latch. The harness
	// registers each host on every node with a hosts-only INSERT. One that
	// reaches a node before that node holds ANY membership row for the host is
	// not absorbed there, and when a peer's older copy arrives afterwards the
	// two nodes' rows differ in updated_at until anti-entropy, which this
	// harness does not run on a timer (host_membership.go names the gap). The
	// state is the same on both; only the digest differs.
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})

	check := func(stage, wantState string, wantIsolated bool) {
		t.Helper()
		for _, n := range c.Nodes {
			if got := oldColumn(t, n, `SELECT state FROM hosts WHERE name = ?`, victim.Name); got != wantState {
				t.Errorf("%s: %s: a rolled-back reader sees the victim %q, want %q", n.Name, stage, got, wantState)
			}
			if got := oldVoters(t, n)[victim.Name]; got != corrosion.VotingEligible(wantState) {
				t.Errorf("%s: %s: a rolled-back reader's voter set has the victim voting=%v", n.Name, stage, got)
			}
			rows, err := n.DB.Query(ctx, `SELECT isolation_epoch AS e FROM hosts WHERE name = ?`, victim.Name)
			if err != nil || len(rows) != 1 {
				t.Fatalf("%s: read hosts.isolation_epoch: %v", n.Name, err)
			}
			if got := rows[0].Int64("e") != 0; got != wantIsolated {
				t.Errorf("%s: %s: a rolled-back reader sees the victim isolated=%v, want %v — it "+
					"refuses or accepts that host's replication from this column alone", n.Name, stage, got, wantIsolated)
			}
			if got := hostOn(t, n, victim.Name).State; got != wantState {
				t.Errorf("%s: %s: this build reads the victim %q, want %q", n.Name, stage, got, wantState)
			}
		}
	}

	if err := corrosion.UpdateHostState(ctx, a.DB, victim.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	check("after a maintenance through a", "maintenance", false)

	if _, err := c.SelfClient(b).UndrainHost(ctx, &pb.UndrainHostRequest{Name: victim.Name}); err != nil {
		t.Fatalf("undrain via %s: %v", b.Name, err)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	check("after an undrain through b", "active", false)

	if err := corrosion.IsolateHost(ctx, a.DB, a.Name, victim.Name, corrosion.IsolationManual); err != nil {
		t.Fatal(err)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	check("after an isolation through a", "active", true)

	epoch, _, err := corrosion.HostIsolation(ctx, b.DB, victim.Name)
	if err != nil || epoch == 0 {
		t.Fatalf("%s: HostIsolation = %d %v", b.Name, epoch, err)
	}
	if err := corrosion.ClearHostIsolation(ctx, b.DB, victim.Name, epoch); err != nil {
		t.Fatal(err)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	check("after the isolation is cleared through b", "active", false)
}

// TestFleet_HostMembership_AStaleDualWrittenStateNeverComesBack: the hosts copy
// of state is dual-written and still shares the hosts row's clock, so a
// replica can hold an OLD state there on a NEWER hosts row. No reader, and no
// pass, may take it for a write made through an unlatched node.
//
// Replica c receives, in this order: a's drain (both halves), b's version
// report (newer than everything a wrote), then a's fence — whose hosts half c
// refuses as older than the version report, while its membership half
// applies. c's hosts row now says draining, newer than the membership row that
// says fenced, with no pass in between. A rule that took a moved hosts value
// on a newer row would turn the fenced host back into a draining one; every
// entry here was written by a live node, so nothing is noted and the
// membership row stands.
func TestFleet_HostMembership_AStaleDualWrittenStateNeverComesBack(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2673})
	a, b, r := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	// Every node's hosts rows must have arrived before the latch. The harness
	// registers each host on every node with a hosts-only INSERT. One that
	// reaches a node before that node holds ANY membership row for the host is
	// not absorbed there, and when a peer's older copy arrives afterwards the
	// two nodes' rows differ in updated_at until anti-entropy, which this
	// harness does not run on a timer (host_membership.go names the gap). The
	// state is the same on both; only the digest differs.
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})

	// Only a→r and b→r carry anything until the end, so r sees the three
	// writes in exactly the order they are released.
	block := LinkFault{Block: true}
	c.SetLinkFaultBoth(a, b, block)
	c.SetLinkFault(r, a, block)
	c.SetLinkFault(r, b, block)

	if err := corrosion.UpdateHostState(ctx, a.DB, r.Name, "draining"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "the drain on "+r.Name, func() bool {
		return oldColumn(t, r, `SELECT state FROM hosts WHERE name = ?`, r.Name) == "draining"
	})
	c.SetLinkFault(a, r, block)
	if err := corrosion.UpdateHostState(ctx, a.DB, r.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	time.Sleep(5 * time.Millisecond) // the version report is newer than the fence
	if err := corrosion.UpdateHostVersion(ctx, b.DB, r.Name, "v-stale"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "the version report on "+r.Name, func() bool {
		return hostOn(t, r, r.Name).Version == "v-stale"
	})
	c.SetLinkFault(a, r, LinkFault{})
	eventually(t, convergeTimeout, "the fence's membership half on "+r.Name, func() bool {
		rows, err := r.DB.Query(ctx, `SELECT state FROM host_membership WHERE host_name = ?`, r.Name)
		return err == nil && len(rows) == 1 && rows[0].String("state") == "fenced"
	})
	if got := oldColumn(t, r, `SELECT state FROM hosts WHERE name = ?`, r.Name); got != "draining" {
		t.Fatalf("%s: hosts.state = %q; the scenario needs the fence's hosts half refused there", r.Name, got)
	}

	c.ClearLinkFaults()
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	for _, n := range c.Nodes {
		if _, err := n.DB.SplitHostMembership(ctx); err != nil {
			t.Fatalf("%s: pass: %v", n.Name, err)
		}
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	for _, n := range c.Nodes {
		if got := hostOn(t, n, r.Name).State; got != "fenced" {
			t.Errorf("%s reads the fenced host as %q: a stale dual-written hosts.state came back", n.Name, got)
		}
		if votes(t, n, r.Name) {
			t.Errorf("%s counts the fenced host as a voter", n.Name)
		}
	}
}

// TestFleet_HostMembership_AntiEntropyCarriesAnAbsorbedWrite: a latched node
// that missed the entry of a hosts-only write — made by a node not yet writing
// host_membership — learns the absorbed row from a peer by anti-entropy. The
// absorption is local and never re-emitted, so this is the only way it gets
// there; every latched receiver of the entry computes the same row, so the
// merge converges rather than conflicting.
func TestFleet_HostMembership_AntiEntropyCarriesAnAbsorbedWrite(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2674})
	u, a, r := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	// Every node's hosts rows must have arrived before the latch. The harness
	// registers each host on every node with a hosts-only INSERT. One that
	// reaches a node before that node holds ANY membership row for the host is
	// not absorbed there, and when a peer's older copy arrives afterwards the
	// two nodes' rows differ in updated_at until anti-entropy, which this
	// harness does not run on a timer (host_membership.go names the gap). The
	// state is the same on both; only the digest differs.
	c.WaitConverged(t, convergeTimeout)
	splitMembership(t, a)
	splitMembership(t, r)
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})

	// r hears nothing, directly or relayed.
	c.SetLinkFault(u, r, LinkFault{Block: true})
	c.SetLinkFault(a, r, LinkFault{Block: true})
	if err := corrosion.UpdateHostState(ctx, u.DB, r.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	eventually(t, convergeTimeout, "the absorbed drain on "+a.Name, func() bool {
		return hostOn(t, a, r.Name).State == "maintenance"
	})
	if got := hostOn(t, r, r.Name).State; got != "active" {
		t.Fatalf("%s saw the drain although every link into it is blocked (%q)", r.Name, got)
	}

	r.DB.MergeStateBytesLWW(pullDump(t, c, a))
	if got := hostOn(t, r, r.Name).State; got != "maintenance" {
		t.Fatalf("%s reads %q after anti-entropy from %s; the absorbed row did not travel", r.Name, got, a.Name)
	}
	if votes(t, r, r.Name) {
		t.Fatalf("%s still counts the host in maintenance as a voter", r.Name)
	}
	c.ClearLinkFaults()
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"}, a, r)
}

// TestFleet_HostMembership_TheNodeThatFencedReadsItsFenceAfterItsLatch: a node
// that has not latched yet fences a host — a hosts-only write — while it
// already holds a latched peer's copy of that host's membership row. When it
// latches it must read the host as fenced at once, not as the active the
// peer's copy says until anti-entropy catches up. The local write path absorbs
// the node's own write into the row it holds.
func TestFleet_HostMembership_TheNodeThatFencedReadsItsFenceAfterItsLatch(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2675})
	a, u, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	splitMembership(t, a)
	eventually(t, convergeTimeout, "a's copy of the victim's row on "+u.Name, func() bool {
		rows, err := u.DB.Query(ctx, `SELECT 1 FROM host_membership WHERE host_name = ?`, victim.Name)
		return err == nil && len(rows) == 1
	})
	// u hears nothing more from a, so nothing but its own write can move its row.
	c.SetLinkFault(a, u, LinkFault{Block: true})
	if err := corrosion.UpdateHostState(ctx, u.DB, victim.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	if n := rowCount(t, u, `SELECT count(*) AS n FROM mutation_log WHERE stmts LIKE '%host_membership%' AND origin = ?`, u.Name); n != 0 {
		t.Fatalf("unlatched %s logged %d host_membership statements", u.Name, n)
	}
	splitMembership(t, u)
	if got := hostOn(t, u, victim.Name).State; got != "fenced" {
		t.Fatalf("%s fenced %s and, once latched, reads it as %q", u.Name, victim.Name, got)
	}
	if votes(t, u, victim.Name) {
		t.Fatalf("%s counts the host it fenced as a voter", u.Name)
	}
}
