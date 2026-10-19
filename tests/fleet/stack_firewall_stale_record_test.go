package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

const staleEdgeV1 = `name: edge

images:
  test:
    source: file:///dev/null

vms:
  edge-1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
`

const staleEdgeV2 = staleEdgeV1 + `
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
firewall:
  default-deny: true
`

// TestFleet_StackFirewall_AnOlderRecordCannotAuthorizeTearingItDown: the
// entry node of `lv compose down` holds an OLDER record of the stack, with no
// firewall, and none of the firewall rows a newer Admin deploy wrote on
// node-0. It authorizes the teardown on what it sees, and the teardown is
// applied by the stack's name on every peer. Its member's delete fails, so
// the stack is left "deleting" for the reconcilers, and node-0's reconciler
// takes it up once replication resumes.
//
// An Operator without sg.write at the root: node-0 keeps the security group
// and the cluster default-deny, keeps the stack "deleting", and raises
// stack.firewall_teardown_held naming `lv compose down --name edge`, which an
// Admin then runs to finish it. An Admin: node-0's reconciler removes them.
//
// Mutation: remove the firewall whatever the teardown's authority
// (stackFirewallHold returns "") — the Operator case loses the group and the
// deny, red. Record every teardown as one without sg.write — the Admin case
// keeps them, red.
func TestFleet_StackFirewall_AnOlderRecordCannotAuthorizeTearingItDown(t *testing.T) {
	for _, tc := range []struct {
		name  string
		admin bool
	}{{"operator without sg.write", false}, {"admin", true}} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7204})
			a, b := c.Nodes[0], c.Nodes[2]
			for _, n := range c.Nodes {
				openNICGuards(t, n)
			}
			if err := corrosion.InsertImage(ctx, a.DB, corrosion.ImageRecord{Name: "test", Format: "qcow2",
				SourceURL: "file:///dev/null", Checksum: "deadbeef", SizeBytes: 1024}); err != nil {
				t.Fatal(err)
			}
			if err := writeEmptyImageFile(a.Server.ImagePathForTests("test")); err != nil {
				t.Fatal(err)
			}
			tok := scopedOperatorToken(t, c, a, "opal", "acme")
			admin := c.SelfClient(a)
			deployAndDrain(t, ctx, admin, &pb.DeployStackRequest{ComposeYaml: staleEdgeV1})
			c.WaitConverged(t, convergeTimeout)
			// Every node's engine sees opal's binding, so none falls back to
			// the cluster-wide legacy role for her.
			for _, n := range c.Nodes {
				e := auth.NewEngine(n.DB)
				if err := e.Reload(ctx); err != nil {
					t.Fatal(err)
				}
				n.Server.SetAuthEngine(e)
			}
			if vm, _ := corrosion.GetVM(ctx, b.DB, "edge-1"); vm == nil {
				t.Fatalf("fixture: edge-1 did not reach %s", b.Name)
			}

			// An Admin adds the firewall while b lags.
			c.Isolate(b)
			deployAndDrain(t, ctx, admin, &pb.DeployStackRequest{ComposeYaml: staleEdgeV2})
			if g, _ := corrosion.ListSecurityGroups(ctx, a.DB, "edge"); len(g) != 1 {
				t.Fatalf("fixture: the stack's group is not on %s: %+v", a.Name, g)
			}
			if st, _ := corrosion.GetStack(ctx, b.DB, "edge"); st == nil || strings.Contains(st.ComposeYAML, "security-groups") {
				t.Fatalf("fixture: %s does not hold the older record: %+v", b.Name, st)
			}
			if owns, _ := corrosion.StackOwnsFirewall(ctx, b.DB, "edge"); owns {
				t.Fatalf("fixture: %s holds the stack's firewall rows", b.Name)
			}

			// The member's delete fails (an operation holds it), so the
			// teardown is left "deleting" for the reconcilers.
			for _, n := range c.Nodes {
				if err := localExec(ctx, n.DB, `UPDATE vms SET active_operation_id = 'op-held' WHERE name = 'edge-1'`); err != nil {
					t.Fatal(err)
				}
			}
			client := c.bearerClient(b, tok)
			if tc.admin {
				client = c.SelfClient(b)
			}
			stream, err := client.DeleteStack(ctx, &pb.DeleteStackRequest{Name: "edge"})
			for err == nil {
				_, err = stream.Recv()
			}
			if err != io.EOF {
				t.Fatalf("compose down on %s, which sees no firewall: %v, want it to run", b.Name, err)
			}
			if st, _ := corrosion.GetStack(ctx, b.DB, "edge"); st == nil || st.State != "deleting" {
				t.Fatalf("fixture: the teardown on %s was not left \"deleting\": %+v", b.Name, st)
			}

			c.ClearLinkFaults()
			eventually(t, convergeTimeout, "the teardown reaches "+a.Name, func() bool {
				st, _ := corrosion.GetStack(ctx, a.DB, "edge")
				return st != nil && st.State == "deleting"
			})
			eventually(t, convergeTimeout, "the firewall rows reach "+b.Name, func() bool {
				owns, _ := corrosion.StackOwnsFirewall(ctx, b.DB, "edge")
				return owns
			})
			for _, n := range c.Nodes {
				if err := localExec(ctx, n.DB, `UPDATE vms SET active_operation_id = '' WHERE name = 'edge-1'`); err != nil {
					t.Fatal(err)
				}
			}

			r := health.NewStackReconciler(a.Name, a.DB)
			r.SetCleaner(a.Server)
			r.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) }) // past the in-flight grace
			r.ReconcileOnce(ctx)

			groups, _ := corrosion.ListSecurityGroups(ctx, a.DB, "edge")
			deny, _ := corrosion.GetFirewallDefault(ctx, a.DB, "cluster")
			st, _ := corrosion.GetStack(ctx, a.DB, "edge")
			if vm, _ := corrosion.GetVM(ctx, a.DB, "edge-1"); vm != nil {
				t.Errorf("the reconciler did not delete the member: %+v", vm)
			}
			if tc.admin {
				if len(groups) != 0 || (deny != nil && deny.DefaultDeny) || st != nil {
					t.Fatalf("an Admin's teardown on %s left groups %+v, default %+v, stack %+v", a.Name, groups, deny, st)
				}
				return
			}
			if len(groups) != 1 {
				t.Errorf("%s: the teardown of a caller without sg.write removed the stack's group: %+v", a.Name, groups)
			}
			if deny == nil || !deny.DefaultDeny {
				t.Errorf("%s: the teardown of a caller without sg.write removed the cluster default-deny: %+v", a.Name, deny)
			}
			if st == nil || st.State != "deleting" {
				t.Errorf("%s: stack = %+v, want it kept \"deleting\" with its firewall", a.Name, st)
			}
			cond, found, err := corrosion.GetHealthCondition(ctx, a.DB, "stack_reconciler", "stack.firewall_teardown_held", "stack", "edge")
			if err != nil || !found || cond.Lifecycle == corrosion.ConditionResolved {
				t.Fatalf("no open stack.firewall_teardown_held for edge: %+v (found %v, err %v)", cond, found, err)
			}
			if !strings.Contains(cond.Evidence, "lv compose down --name edge") {
				t.Errorf("the condition does not name the remedy: %s", cond.Evidence)
			}

			// What it names finishes it: an Admin's compose down.
			stream, err = c.SelfClient(a).DeleteStack(ctx, &pb.DeleteStackRequest{Name: "edge"})
			for err == nil {
				_, err = stream.Recv()
			}
			if err != io.EOF {
				t.Fatalf("an Admin's compose down: %v", err)
			}
			// stacks is left out: the lagging node's "deleting" write (an
			// UPDATE of state and updated_at) is newer than the Admin's
			// redeploy, so that node keeps the older compose_yaml and
			// compose_hash under the same updated_at, and so does its
			// tombstone. Every other table converges.
			c.WaitConvergedExcept(t, convergeTimeout, []string{"stacks"})
			for _, n := range c.Nodes {
				if g, _ := corrosion.ListSecurityGroups(ctx, n.DB, "edge"); len(g) != 0 {
					t.Errorf("%s: groups %+v after the Admin's compose down", n.Name, g)
				}
				if st, _ := corrosion.GetStack(ctx, n.DB, "edge"); st != nil {
					t.Errorf("%s: stack %+v after the Admin's compose down", n.Name, st)
				}
			}
		})
	}
}

// TestFleet_StackFirewall_ATeardownThatCompletesOnAnOlderRecordLeavesItSaid:
// as above, but the teardown on the lagging node completes there and
// tombstones the stack. node-0 receives the tombstone with the stack's newer
// security group still in place: it stays in force, and node-0's reconciler
// says so (stack.firewall_teardown_held) until an Admin's compose down
// removes it.
//
// Mutation: drop reportTornDownFirewalls from the reconcile pass — no
// condition, red.
func TestFleet_StackFirewall_ATeardownThatCompletesOnAnOlderRecordLeavesItSaid(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 7205})
	a, b := c.Nodes[0], c.Nodes[2]
	for _, n := range c.Nodes {
		openNICGuards(t, n)
	}
	tok := scopedOperatorToken(t, c, a, "opal", "acme")
	admin := c.SelfClient(a)
	deployAndDrain(t, ctx, admin, &pb.DeployStackRequest{ComposeYaml: "name: edge\n"})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		e := auth.NewEngine(n.DB)
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		n.Server.SetAuthEngine(e)
	}

	c.Isolate(b)
	deployAndDrain(t, ctx, admin, &pb.DeployStackRequest{ComposeYaml: `name: edge
security-groups:
  web:
    rules:
      - {direction: ingress, proto: tcp, port: "80", action: accept}
`})
	if g, _ := corrosion.ListSecurityGroups(ctx, a.DB, "edge"); len(g) != 1 {
		t.Fatalf("fixture: the stack's group is not on %s: %+v", a.Name, g)
	}
	stream, err := c.bearerClient(b, tok).DeleteStack(ctx, &pb.DeleteStackRequest{Name: "edge"})
	for err == nil {
		_, err = stream.Recv()
	}
	if err != io.EOF {
		t.Fatalf("compose down on %s, which sees no firewall: %v", b.Name, err)
	}
	if st, _ := corrosion.GetStack(ctx, b.DB, "edge"); st != nil {
		t.Fatalf("fixture: the teardown on %s did not complete: %+v", b.Name, st)
	}

	c.ClearLinkFaults()
	eventually(t, convergeTimeout, "the tombstone reaches "+a.Name, func() bool {
		st, _ := corrosion.GetStack(ctx, a.DB, "edge")
		return st == nil
	})
	r := health.NewStackReconciler(a.Name, a.DB)
	r.SetCleaner(a.Server)
	r.ReconcileOnce(ctx)
	if g, _ := corrosion.ListSecurityGroups(ctx, a.DB, "edge"); len(g) != 1 {
		t.Fatalf("%s: the stack's group did not survive the teardown: %+v", a.Name, g)
	}
	cond, found, err := corrosion.GetHealthCondition(ctx, a.DB, "stack_reconciler", "stack.firewall_teardown_held", "stack", "edge")
	if err != nil || !found || cond.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no open stack.firewall_teardown_held for the torn-down edge: %+v (found %v, err %v)", cond, found, err)
	}
	if !strings.Contains(cond.Evidence, "lv compose down --name edge") {
		t.Errorf("the condition does not name the remedy: %s", cond.Evidence)
	}

	stream, err = c.SelfClient(a).DeleteStack(ctx, &pb.DeleteStackRequest{Name: "edge"})
	for err == nil {
		_, err = stream.Recv()
	}
	if err != io.EOF {
		t.Fatalf("an Admin's compose down of the torn-down stack: %v", err)
	}
	if g, _ := corrosion.ListSecurityGroups(ctx, a.DB, "edge"); len(g) != 0 {
		t.Fatalf("the Admin's compose down left the group: %+v", g)
	}
	r.ReconcileOnce(ctx)
	cond, _, _ = corrosion.GetHealthCondition(ctx, a.DB, "stack_reconciler", "stack.firewall_teardown_held", "stack", "edge")
	if cond.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("the condition did not resolve once the group was removed: %+v", cond)
	}
}
