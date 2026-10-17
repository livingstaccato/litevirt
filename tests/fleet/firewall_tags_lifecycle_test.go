// Fleet scenarios for a workload's firewall tags across its lifecycle
// (firewall extras spec §4.3, plan D3): `lv firewall tag set` through the
// real RPC on a latched cluster; a plain delete clears the tags row cluster-
// wide; a rebuild, a rolling recreate, an inline compose recreate, a
// container migrate and a replica promotion keep it (D2b review I-4): the
// re-created or moved workload keeps its identity, and the row keyed by it.
package fleet

import (
	"context"
	"maps"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

var webTags = map[string]string{"role": "web"}

// tagVia tags workload name through n's SetFirewallTags RPC (it mints the
// identity on the owner) and waits until every replica has the result.
func tagVia(t *testing.T, c *Cluster, n *Node, kind, name, host string) string {
	t.Helper()
	for _, m := range c.Nodes {
		m.DB.SetRepointReady(func(context.Context) bool { return true })
	}
	out, err := c.SelfClient(n).SetFirewallTags(context.Background(), &pb.SetFirewallTagsRequest{
		Kind: kind, Workload: name, Host: host, Set: webTags})
	if err != nil || !corrosion.ValidFirewallID(out.GetFwId()) {
		t.Fatalf("tag set %s %s via %s: %+v %v", kind, name, n.Name, out, err)
	}
	c.WaitConverged(t, convergeTimeout)
	return out.GetFwId()
}

// tagsRowOn is identity id's tags row as n's replica holds it.
func tagsRowOn(t *testing.T, n *Node, kind, id string) (corrosion.FirewallTagsRecord, bool) {
	t.Helper()
	rec, ok, err := corrosion.ResolveFirewallTags(context.Background(), n.DB, kind, id)
	if err != nil {
		t.Fatal(err)
	}
	return rec, ok
}

// assertTagsKept: every replica holds identity id's tags row with webTags.
func assertTagsKept(t *testing.T, c *Cluster, kind, id string) {
	t.Helper()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if rec, ok := tagsRowOn(t, n, kind, id); !ok || !maps.Equal(rec.Tags, webTags) {
			t.Errorf("the tags row of %s/%s on %s's replica = %+v (present %v), want %v kept", kind, id, n.Name, rec, ok, webTags)
		}
	}
}

// A plain delete entered on a node that does not own the VM clears the tags
// row on every replica: the entry clears, the owner it forwarded to does not
// need to. (Control for the keep tests below: the clear is live, so a row
// that survives them survived a delete that would have cleared it.)
func TestFirewallTags_APlainDeleteClearsThem(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	latchRelease(t, c)
	id := tagVia(t, c, n1, "vm", "web", "")
	if _, err := c.SelfClient(n2).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "web"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if rec, ok := tagsRowOn(t, n, corrosion.TagMemberVM, id); !ok || len(rec.Tags) != 0 {
			t.Errorf("after the delete, %s's replica holds the tags row %+v (present %v), want it cleared", n.Name, rec, ok)
		}
	}
}

// A rebuild forwarded to a host behind keeps the tags row with the identity.
func TestFirewallTags_ARebuildKeepsThem(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	before := seedVM(t, c, n0, &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name},
	})
	latchRelease(t, c)
	id := tagVia(t, c, n0, "vm", "web", "")
	lagFrom(c, n0, c.Nodes[1:]...)
	if _, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
	if got := vmFWIDOn(t, n1, "web"); got != id {
		t.Fatalf("the rebuilt VM's identity = %q, want %q", got, id)
	}
	assertTagsKept(t, c, corrosion.TagMemberVM, id)
}

// A rolling recreate run from a third node: its delete (a deleted-VM sink,
// forwarded to the owner) clears nothing, so the tags stay.
//
// Mutations: clear on any delete whatever its sink — red; clear on the owner
// of a forwarded delete (ignore the entry's marker) — red.
func TestFirewallTags_ARollingRecreateKeepsThem(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	before := seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	latchRelease(t, c)
	id := tagVia(t, c, n0, "vm", "web", "")
	desired := &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}
	if err := recreateOn(t, n2, c.SelfClient(n2), "web", desired); err != nil {
		t.Fatalf("rolling recreate: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
	if got := vmFWIDOn(t, n1, "web"); got != id {
		t.Fatalf("the recreated VM's identity = %q, want %q", got, id)
	}
	assertTagsKept(t, c, corrosion.TagMemberVM, id)
}

// A compose deploy entered on a non-owner re-creates web inline: its delete
// carries the report-only sink, so the tags stay.
//
// Mutation: skip the clear only for a non-report sink (isRecreateDelete) —
// red.
func TestFirewallTags_AnInlineRecreateKeepsThem(t *testing.T) {
	c, before := newRecreateRemoteFleet(t, 1, "node-0")
	n0, n1 := c.Nodes[0], c.Nodes[1]
	latchRelease(t, c)
	id := tagVia(t, c, n0, "vm", "web", "")
	msgs := deployCollect(t, context.Background(), c.SelfClient(n1), recreateRemoteYAML("node-0", "second"))
	if p := errorPhaseFor(msgs, "web"); p != nil {
		t.Fatalf("deploy: %s; %s", p.Error, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n0)
	if got := vmFWIDOn(t, n0, "web"); got != id {
		t.Fatalf("the re-created VM's identity = %q, want %q", got, id)
	}
	assertTagsKept(t, c, corrosion.TagMemberVM, id)
}

// A container's cold migrate keeps the tags row with the identity it carries.
func TestFirewallTags_AContainerMigrateKeepsThem(t *testing.T) {
	c := gatedMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	const name = "ct-move"
	createContainer(t, c, src, name)
	id := tagVia(t, c, dst, "container", name, src.Name)
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := ctFWIDOn(t, dst, dst.Name, name); got != id {
		t.Fatalf("the migrated container's identity = %q, want %q", got, id)
	}
	assertTagsKept(t, c, corrosion.TagMemberCT, id)
}

// A failover promotion of a container's replica (a relocation under the
// coordinator's token) keeps the tags row with the identity it carries. The
// release gate here grants every write (grantAllGate) and the feature is
// recorded used, so a clear on any path the promotion takes would land.
func TestFirewallTags_AReplicaPromotionKeepsThem(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	dead, target, coord := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	const name = "web"
	replCT(t, c, dead, name)
	for _, n := range c.Nodes {
		openNICGuards(t, n) // the cluster-policy gate open, every release write granted
	}
	info, _ := capabilities.LookupFeature(capabilities.FeatureFirewallTagGroups)
	if err := corrosion.RecordReleaseFeatureUse(ctx, coord.DB, info.Token, string(capabilities.FeatureFirewallTagGroups), coord.Name, true); err != nil {
		t.Fatal(err)
	}
	id := tagVia(t, c, coord, "container", name, dead.Name)
	drRepo(t, target)
	sched := ctSchedule(t, c, dead, name, target.Name, 3, true)
	dead.CT.Seed(name, "replicated")
	if err := dead.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if outcome, err := promoteVia(t, coord, dead, target, name, "tok-fw-tags"); err != nil || outcome != corrosion.RestoreLanded {
		t.Fatalf("promotion: (%v, %v)", outcome, err)
	}
	if got := ctFWIDOn(t, target, target.Name, name); got != id {
		t.Fatalf("the promoted container's identity = %q, want %q", got, id)
	}
	assertTagsKept(t, c, corrosion.TagMemberCT, id)
}
