// Fleet scenarios: retiring the hosts copy of a host's runtime reports
// (host_runtime_retire_v1, colonelpanik/litevirt#267).
package fleet

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// retireRuntime is host_runtime_split_v1 latched and its pass run, then
// host_runtime_retire_v1 latched, on n.
func retireRuntime(t *testing.T, n *Node) {
	t.Helper()
	splitRuntime(t, n)
	n.DB.SetHostRuntimeRetireGate(func() bool { return true })
}

// concurrentConfigAndReport has the operator's write (a's region change for
// subject) and the subject's own version report cross on the wire, the report
// strictly later. subject is the replica that sees them in the opposite
// order: it holds its newer report when the older region change arrives. It
// waits for every write to be delivered and returns each node's resolved
// (version, region) of subject, and whether every table, hosts included,
// converged.
func concurrentConfigAndReport(t *testing.T, retire, boot bool, seed int64) (map[string][2]string, bool) {
	t.Helper()
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	a, subject := c.Nodes[0], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if boot {
			// The production report: the daemon's boot report, which also
			// carries the boot state until host_membership_retire_v1 has
			// latched, so both copies are retired here.
			retireMembership(t, n)
		}
		if retire {
			retireRuntime(t, n)
		} else {
			splitRuntime(t, n)
		}
	}
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(a)
	c.Isolate(subject)
	if err := corrosion.UpdateHostRegion(ctx, a.DB, subject.Name, "eu-267"); err != nil {
		t.Fatalf("region change on %s: %v", a.Name, err)
	}
	time.Sleep(5 * time.Millisecond) // the report is the newer write on every clock
	if boot {
		if err := corrosion.UpdateHostStartup(ctx, subject.DB, subject.Name, "active", "v-267-retire", 32, 65536, 640, true); err != nil {
			t.Fatalf("boot report on %s: %v", subject.Name, err)
		}
	} else if err := corrosion.UpdateHostVersion(ctx, subject.DB, subject.Name, "v-267-retire"); err != nil {
		t.Fatalf("version report on %s: %v", subject.Name, err)
	}
	c.ClearLinkFaults()

	// The report is the newer write: once every node reads it, each has
	// applied or refused the region change.
	eventually(t, convergeTimeout, "the version report everywhere", func() bool {
		for _, n := range c.Nodes {
			if hostOn(t, n, subject.Name).Version != "v-267-retire" {
				return false
			}
		}
		return true
	})
	converged := true
	deadline := time.Now().Add(5 * time.Second)
	for {
		apart, err := divergence(c.Nodes)
		if err != nil {
			t.Fatal(err)
		}
		if len(apart) == 0 {
			break
		}
		if time.Now().After(deadline) {
			converged = false
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	out := map[string][2]string{}
	for _, n := range c.Nodes {
		h := hostOn(t, n, subject.Name)
		out[n.Name] = [2]string{h.Version, h.Region}
	}
	return out, converged
}

// TestFleet_HostRuntimeRetire_AReportNeverCostsAConcurrentConfigChange: with
// the hosts copy of the runtime columns retired, a host's version report no
// longer moves the hosts row's clock, so an operator's concurrent region
// change survives on every replica — the replica that applied the newer
// report first included — and the hosts table itself converges.
//
// The first subtest is the RED half: with the split alone (the hosts copy
// still written) the report is safe but the region change is lost on the
// replica that held the newer report, and the hosts rows stay apart under one
// clock. It must keep failing to reproduce that, or the second proves nothing.
func TestFleet_HostRuntimeRetire_AReportNeverCostsAConcurrentConfigChange(t *testing.T) {
	t.Run("with the hosts copy still written the region change is lost on a replica", func(t *testing.T) {
		got, _ := concurrentConfigAndReport(t, false, false, 2677)
		lost := 0
		for _, vr := range got {
			if vr[1] != "eu-267" {
				lost++
			}
		}
		if lost == 0 {
			t.Fatalf("every replica kept the region change while reports still wrote hosts: %v. "+
				"The scenario did not race, so the retired half proves nothing", got)
		}
	})

	t.Run("retired, both survive on every replica and hosts converges", func(t *testing.T) {
		got, converged := concurrentConfigAndReport(t, true, false, 2678)
		for node, vr := range got {
			if vr[0] != "v-267-retire" || vr[1] != "eu-267" {
				t.Errorf("%s holds version=%q region=%q, want v-267-retire and eu-267: a host's own "+
					"report cost the operator's concurrent change", node, vr[0], vr[1])
			}
		}
		if !converged {
			t.Error("the replicas did not converge: a report still shares the hosts row's clock")
		}
	})

	// The daemon's boot report is the production runtime writer (review m-3).
	t.Run("both copies retired, the boot report never costs it either", func(t *testing.T) {
		got, converged := concurrentConfigAndReport(t, true, true, 2681)
		for node, vr := range got {
			if vr[0] != "v-267-retire" || vr[1] != "eu-267" {
				t.Errorf("%s holds version=%q region=%q, want v-267-retire and eu-267: the boot report "+
					"cost the operator's concurrent change", node, vr[0], vr[1])
			}
		}
		if !converged {
			t.Error("the replicas did not converge: the boot report still shares the hosts row's clock")
		}
	})
}

// TestFleet_HostRuntimeRetire_ADualWriteNodeAndARetiredNodeReadEachOther: b
// stands for a host on which the retire latch has not formed yet (split and
// live, not retired). A retired node's report, which no longer touches hosts,
// reaches b through host_runtime, and b's dual-written report reaches the
// retired node.
func TestFleet_HostRuntimeRetire_ADualWriteNodeAndARetiredNodeReadEachOther(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2679})
	a, b, subject := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	retireRuntime(t, a)
	splitRuntime(t, b)
	retireRuntime(t, subject)
	c.WaitConverged(t, convergeTimeout)

	if err := corrosion.UpdateHostStartup(ctx, subject.DB, subject.Name, "active", "v-retired-boot", 12, 24, 36, true); err != nil {
		t.Fatal(err)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	if h := hostOn(t, b, subject.Name); h.Version != "v-retired-boot" || h.DiskTotal != 36 {
		t.Errorf("%s (dual-write build) reads %s as %+v after a retired report", b.Name, subject.Name, h)
	}
	if err := corrosion.UpdateHostVersion(ctx, b.DB, b.Name, "v-dual"); err != nil {
		t.Fatal(err)
	}
	c.WaitConvergedExcept(t, convergeTimeout, []string{"hosts"})
	for _, n := range []*Node{a, subject} {
		if v := hostOn(t, n, b.Name).Version; v != "v-dual" {
			t.Errorf("%s reads %s at %q after its dual-written report, want v-dual", n.Name, b.Name, v)
		}
	}
}
