package fleet

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// forcedCondition reads ha.voter.forced on n after one lease-holder health
// pass, reporting whether it is raised and its evidence.
func forcedCondition(t *testing.T, n *Node) (bool, string) {
	t.Helper()
	ctx := context.Background()
	n.Server.RecoveryClaimHealthTick(ctx)
	cond, found, err := corrosion.GetHealthCondition(ctx, n.DB, "voter_config", "ha.voter.forced", "cluster", "voters")
	if err != nil {
		t.Fatal(err)
	}
	return found && cond.Lifecycle != corrosion.ConditionResolved, cond.Evidence
}

// TestFleet_VoterForced_ConditionClearsWhenALostHostIsRebuilt: ha.voter.forced
// is raised until each lost voter is gone (docs/design/recovery-claims.md §4.6
// step 5). A lost voter is a member ENTRY — a name and the incarnation it was
// admitted as — so a machine rebuilt under the same name after
// `lv host rm --dead` is not the lost voter coming back, even though the name
// has a live hosts row again and the old machine's certificate serial went
// with the tombstone AdmitHost replaced. On the kvm003 lab the condition stayed
// raised for good after node-2,3,4 were rebuilt.
//
// The condition still holds while the name answers as the OLD incarnation, or
// cannot say which incarnation it is.
//
// Mutations, each red: judge a live hosts row as the lost voter whatever its
// incarnation (the old rule) — raised after the rebuild; count a host that
// cannot be asked as a new machine — cleared while node-3 is unreachable;
// count any answering host as gone, whatever incarnation it answers as —
// node-2 back as it left is not named.
func TestFleet_VoterForced_ConditionClearsWhenALostHostIsRebuilt(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 2542})
	n0, n1, n2, n3, n4 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	c.WaitConverged(t, convergeTimeout)
	runGenesis(t, c)

	for _, n := range []*Node{n2, n3, n4} {
		c.Kill(n)
	}
	for _, n := range []*Node{n2, n3, n4} {
		fenceConfirm(t, c, n0, n)
	}
	c.WaitConverged(t, convergeTimeout, n0, n1)
	if resp, err := forceErr(t, c, n0, false, n2, n3, n4); err != nil || resp.GetGeneration() != 2 {
		t.Fatalf("force-reconfigure: %+v %v", resp, err)
	}
	adoptAll(t, c, 2, n0, n1)
	if raised, ev := forcedCondition(t, n0); !raised || !strings.Contains(ev, n4.Name) {
		t.Fatalf("ha.voter.forced is not raised for the lost hosts before their removal: raised=%v %q", raised, ev)
	}
	// The lost node-2 itself comes back, as it left, and is unfenced by hand
	// rather than removed: it answers as the incarnation generation 1
	// counted, so it is the lost voter.
	if err := corrosion.UpdateHostState(ctx, n0.DB, n2.Name, "active"); err != nil {
		t.Fatal(err)
	}
	c.SetLinkFaultBoth(n0, n2, LinkFault{})
	if raised, ev := forcedCondition(t, n0); !raised || !strings.Contains(ev, n2.Name+"'s vote") {
		t.Fatalf("ha.voter.forced does not name the lost %s answering as its old incarnation: raised=%v %q", n2.Name, raised, ev)
	}
	c.Kill(n2)
	if err := corrosion.UpdateHostState(ctx, n0.DB, n2.Name, "fenced"); err != nil {
		t.Fatal(err)
	}

	withOperatorPKI(t, n0)
	for _, n := range []*Node{n2, n3, n4} {
		if err := cli.HostRemoveDead(ctx, c.SelfClient(n0), n.Name, false); err != nil {
			t.Fatalf("lv host rm --dead %s: %v", n.Name, err)
		}
	}
	c.WaitConverged(t, convergeTimeout, n0, n1)
	syncCRL(t, n0, n1)
	if raised, ev := forcedCondition(t, n0); raised {
		t.Fatalf("ha.voter.forced is still raised once every lost host is removed and revoked: %q", ev)
	}

	// node-4 is rebuilt under its old name and admitted again: a live hosts
	// row, a new certificate, a new incarnation. Not yet a voter.
	reimage(t, c, n4, n0, n0, n1)
	if raised, ev := forcedCondition(t, n0); raised {
		t.Fatalf("ha.voter.forced is raised again by a machine rebuilt under a lost voter's name: %q", ev)
	}

	// node-3 rebuilt too, but n0 cannot ask it which incarnation it is: that
	// is no evidence the lost voter is gone.
	reimage(t, c, n3, n0, n0, n1, n4)
	c.SetLinkFault(n0, n3, LinkFault{BlockClaims: true})
	raised, ev := forcedCondition(t, n0)
	if !raised || !strings.Contains(ev, n3.Name) || strings.Contains(ev, n4.Name+"'s vote") {
		t.Fatalf("ha.voter.forced must name only %s, which cannot say which machine it is: raised=%v %q", n3.Name, raised, ev)
	}
	c.SetLinkFault(n0, n3, LinkFault{})
	if raised, ev := forcedCondition(t, n0); raised {
		t.Fatalf("ha.voter.forced is still raised once %s answers as a new machine: %q", n3.Name, ev)
	}
}
