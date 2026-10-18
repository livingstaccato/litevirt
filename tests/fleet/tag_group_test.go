// Fleet scenarios for tag groups (firewall extras spec §4, plan D7): each
// node builds its plan through the production loader (nodePlan), and the
// group's set, lv_tg_<name>, is read from that plan. Membership is decided by
// the workload's firewall identity and its tags row alone, cluster-wide; an
// address comes only from a live allocator lease the member owns on a live
// NIC of its own.
//
// A VM leases an address only on a NetBox-bound network (allocatorFor), and
// the harness proves nothing more by binding one, so a VM's lease here is
// taken through the builtin allocator (network.AllocateIP) on the owner, a
// replicated write like the allocator's. A container's lease is its real
// IPAM reservation at create.
package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/qcow2"
)

const (
	tgNet    = "tgnet"
	tgSubnet = "10.78.0.0/24"
)

// tgFleet is a three-node fleet whose replicas move on their own, with the
// release latched, the tgnet network on every replica and group web
// (role=web) set through the real RPC.
func tgFleet(t *testing.T, sgs ...string) *Cluster {
	t.Helper()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
	}
	latchRelease(t, c)
	tgSeedNetwork(t, c, c.Nodes[0])
	tgGroup(t, c, c.Nodes[0], "web", sgs...)
	return c
}

// tgSeedNetwork registers tgnet, a managed bridge network with a subnet,
// through the replicated writer on n.
func tgSeedNetwork(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	if err := corrosion.UpsertNetwork(context.Background(), n.DB, corrosion.NetworkRecord{
		Name: tgNet, Type: "bridge", Config: `{"type":"bridge","interface":"br-tgnet","subnet":"` + tgSubnet + `"}`,
	}); err != nil {
		t.Fatalf("seed network %s on %s: %v", tgNet, n.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
}

// tgGroup sets group name (role=web, binding sgs) through n's RPC.
func tgGroup(t *testing.T, c *Cluster, n *Node, name string, sgs ...string) {
	t.Helper()
	if _, err := c.SelfClient(n).SetFirewallTagGroup(context.Background(), &pb.SetFirewallTagGroupRequest{
		Group: &pb.FirewallTagGroup{Name: name, Match: map[string]string{"role": "web"}, SecurityGroups: sgs},
	}); err != nil {
		t.Fatalf("tag-group set %s via %s: %v", name, n.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
}

// tgVM creates VM name on owner over the real CreateVM, with one NIC on
// tgnet with mac, leases that NIC an address on the owner and returns it.
func tgVM(t *testing.T, c *Cluster, owner *Node, name, mac string) string {
	t.Helper()
	ctx := context.Background()
	if _, err := c.SelfClient(owner).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: owner.Name},
		Network: []*pb.NetworkAttachment{{Name: tgNet, Mac: mac}},
	}}); err != nil {
		t.Fatalf("CreateVM %s on %s: %v", name, owner.Name, err)
	}
	return tgLease(t, c, owner, name, mac)
}

// tgLease leases VM name's NIC mac an address on tgnet, on n.
func tgLease(t *testing.T, c *Cluster, n *Node, name, mac string) string {
	t.Helper()
	ip, err := network.AllocateIP(context.Background(), n.DB, tgNet, tgSubnet, mac, name)
	if err != nil || ip == "" {
		t.Fatalf("lease %s's NIC %s an address: %q %v", name, mac, ip, err)
	}
	c.WaitConverged(t, convergeTimeout)
	return ip
}

// tgSet is group's set in n's plan, built by the production loader.
func tgSet(t *testing.T, n *Node, group string) []string {
	t.Helper()
	for _, s := range nodePlan(t, n).IPSets {
		if s.Name == firewall.TagGroupSetPrefix+group {
			return s.CIDRs
		}
	}
	return nil
}

// tgEverywhere waits, bounded, until every node's plan holds ip in group's
// set (want) or no node's does.
func tgEverywhere(t *testing.T, c *Cluster, group, ip string, want bool) {
	t.Helper()
	for _, n := range c.Nodes {
		eventually(t, convergeTimeout, n.Name+"'s lv_tg_"+group+" to hold "+ip+" = "+boolWord(want), func() bool {
			return slices.Contains(tgSet(t, n, group), ip) == want
		})
	}
}

func boolWord(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// tgNoneHolds fails unless, now, no node's plan holds ip in group's set.
func tgNoneHolds(t *testing.T, c *Cluster, group, ip string) {
	t.Helper()
	for _, n := range c.Nodes {
		if set := tgSet(t, n, group); slices.Contains(set, ip) {
			t.Errorf("%s's plan holds %s in lv_tg_%s (%v)", n.Name, ip, group, set)
		}
	}
}

// tgMembers names group's members ("kind host/name") on n's replica.
func tgMembers(t *testing.T, n *Node, group string) []string {
	t.Helper()
	m, err := corrosion.ListTagGroupMembers(context.Background(), n.DB)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, g := range m.Groups {
		if g.Group.Name != group {
			continue
		}
		for _, mb := range g.Members {
			out = append(out, mb.Kind+" "+mb.Host+"/"+mb.Name)
		}
	}
	return out
}

// tagRm removes key from workload name's tags through n's RPC.
func tagRm(t *testing.T, c *Cluster, n *Node, kind, name, host, key string) {
	t.Helper()
	if _, err := c.SelfClient(n).SetFirewallTags(context.Background(), &pb.SetFirewallTagsRequest{
		Kind: kind, Workload: name, Host: host, Remove: []string{key}}); err != nil {
		t.Fatalf("tag rm %s %s via %s: %v", name, key, n.Name, err)
	}
}

// Membership crosses nodes: a VM on node-0, tagged through node-1 (which
// forwards to the owner), is in lv_tg_web in every node's plan once the tags
// row replicates. Untagged, it is in none.
//
// Mutation: read tags from local VMs only (readTagWorkloads keeps a VM row
// only when it is on this replica's host) — node-1 and node-2 never hold the
// address: red.
func TestTagGroup_MembershipCrossesNodes(t *testing.T) {
	c := tgFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	ip := tgVM(t, c, n0, "app-1", "52:54:00:7a:00:01")
	tgNoneHolds(t, c, "web", ip)

	tagVia(t, c, n1, "vm", "app-1", "")
	tgEverywhere(t, c, "web", ip, true)
}

// SetVMIP records another address on the NIC row; the set keeps the lease's
// address and never takes the recorded one: membership addresses come from
// the allocator's lease alone.
//
// Mutation: also take a VM's NIC-row ip (vm_interfaces.ip) as a member
// address — the recorded address joins the set: red.
func TestTagGroup_SetVMIPDoesNotChangeTheSet(t *testing.T) {
	c := tgFleet(t)
	n0, n2 := c.Nodes[0], c.Nodes[2]
	ip := tgVM(t, c, n0, "app-1", "52:54:00:7a:00:02")
	tagVia(t, c, n0, "vm", "app-1", "")
	tgEverywhere(t, c, "web", ip, true)

	const moved = "10.78.0.200"
	if _, err := c.SelfClient(n2).SetVMIP(context.Background(), &pb.SetVMIPRequest{Name: "app-1", Ip: moved, NetworkName: tgNet}); err != nil {
		t.Fatalf("SetVMIP: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := liveNIC(t, n0, "app-1", tgNet).IP; !strings.HasPrefix(got, moved) {
		t.Fatalf("premise: the NIC row records %q after SetVMIP, want %s", got, moved)
	}
	for _, n := range c.Nodes {
		if set := tgSet(t, n, "web"); !slices.Equal(set, []string{ip}) {
			t.Errorf("%s's lv_tg_web = %v after SetVMIP to %s, want only the leased %s", n.Name, set, moved, ip)
		}
	}
}

// tag rm removes the member from every node's set.
//
// Mutation: tag rm drops no key (SetFirewallTags ignores remove) — the
// address stays: red.
func TestTagGroup_TagRmRemovesTheMember(t *testing.T) {
	c := tgFleet(t)
	n0, n2 := c.Nodes[0], c.Nodes[2]
	ip := tgVM(t, c, n0, "app-1", "52:54:00:7a:00:03")
	tagVia(t, c, n0, "vm", "app-1", "")
	tgEverywhere(t, c, "web", ip, true)

	tagRm(t, c, n2, "vm", "app-1", "", "role")
	tgEverywhere(t, c, "web", ip, false)
}

// R1-I1: node-1 is cut off. node-0 (the owner) removes role=web from app-1;
// node-1, still holding the tagged view, runs SetVMLabels on app-1. Once
// replication resumes, node-1's label is kept everywhere, yet no node holds
// app-1's address in lv_tg_web, and the tags row still says removed: no spec
// write carries membership back.
//
// A spec edit entered off the owner is made on the owner while it can be
// reached (grpcapi/spec_owner.go), so the owner is cut off from node-1
// entirely: that is what still makes the edit over node-1's own, lagging
// view. `lv update` is not part of it any more: UpdateVM always runs on the
// owner and refuses when it cannot reach it, so it never writes over a
// lagging view, and an update the owner made during the cut, an operation
// at the next generation, outranks the lagging label edit, which is then
// dropped and proves nothing here.
//
// Mutation: SetVMLabels writes the tags its replica holds back with the
// spec (tags stored with the spec) — node-1's write re-admits app-1: red.
func TestTagGroup_ALaggingSpecWriteDoesNotReAdmitARemovedMember(t *testing.T) {
	c := tgFleet(t)
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	ip := tgVM(t, c, a, "app-1", "52:54:00:7a:00:04")
	id := tagVia(t, c, a, "vm", "app-1", "")
	tgEverywhere(t, c, "web", ip, true)

	c.Isolate(b)
	tagRm(t, c, a, "vm", "app-1", "", "role")
	if !slices.Contains(tgSet(t, b, "web"), ip) {
		t.Fatalf("premise: %s, cut off, still holds app-1 in lv_tg_web", b.Name)
	}
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true, BlockAll: true})
	if _, err := c.SelfClient(b).SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "app-1", Labels: map[string]string{"tier": "front"}}); err != nil {
		t.Fatalf("SetVMLabels via %s: %v", b.Name, err)
	}

	if vm, _ := corrosion.GetVM(ctx, b.DB, "app-1"); vm == nil || !strings.Contains(vm.Spec, `"tier"`) {
		t.Fatalf("premise: node-1 wrote the label over its own, tagged view: %+v", vm)
	}

	c.ClearLinkFaults()
	// node-1's lagging write is kept everywhere: what follows is about a spec
	// write that landed, not one that was dropped on the way.
	for _, n := range c.Nodes {
		eventually(t, convergeTimeout, n.Name+" to hold node-1's label", func() bool {
			vm, _ := corrosion.GetVM(ctx, n.DB, "app-1")
			return vm != nil && strings.Contains(vm.Spec, `"tier"`)
		})
	}
	for _, n := range c.Nodes {
		eventually(t, convergeTimeout, n.Name+" to hold app-1 out of lv_tg_web and its tags row removed", func() bool {
			rec, ok := tagsRowOn(t, n, corrosion.TagMemberVM, id)
			return ok && len(rec.Tags) == 0 && !slices.Contains(tgSet(t, n, "web"), ip)
		})
	}
	// Past the bound, still so: nothing written meanwhile brings it back.
	time.Sleep(2 * time.Second)
	for _, n := range c.Nodes {
		if rec, ok := tagsRowOn(t, n, corrosion.TagMemberVM, id); !ok || len(rec.Tags) != 0 {
			t.Errorf("%s's tags row for app-1 = %+v (present %v), want it to say removed", n.Name, rec, ok)
		}
		if set := tgSet(t, n, "web"); slices.Contains(set, ip) {
			t.Errorf("%s's plan holds app-1's %s in lv_tg_web again (%v)", n.Name, ip, set)
		}
	}
}

// Track D final review I-1: app-1 has no identity yet and node-1 is cut off,
// from node-0 (the owner) entirely, so its spec edits are made on its own
// view rather than forwarded to the owner (grpcapi/spec_owner.go). A tag set
// on node-0 mints the identity into the spec; node-1, which never saw that
// write, runs SetVMLabels over its own view twice. Once replication resumes,
// node-1's line of edits reaches the later generation and is kept, so the
// identity is gone cluster-wide. (One edit no longer erases it: a sibling of
// the mint at its generation keeps the minted identity, spec_conflict.) app-1
// is then held at drop on the network its group binds security groups on,
// the identity_lost condition is critical, and the orphan sweep keeps its
// tags row past the 24 h grace.
//
// Mutations: no hold for a lost identity (tagPass.hold) — red; raise
// identity_lost as a warning — red; sweep a row whose name a live workload
// with no identity holds — red at +25 h.
func TestTagGroup_ALabelEditThroughALaggingNodeHoldsTheVMWhoseIdentityItErased(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
	}
	latchRelease(t, c)
	a, b, sw := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	tgSeedNetwork(t, c, a)
	mustCreateSG(t, c, a, "web-in", "8443")
	c.WaitConverged(t, convergeTimeout)
	tgGroup(t, c, a, "web", "web-in")
	const mac = "52:54:00:7a:00:0e"
	tgVM(t, c, a, "app-1", mac)
	tap := mustTap(t, a, "app-1", mac)
	tgHoldFailoverLease(t, sw)
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(b)
	id := tagViaCutOff(t, c, a, "vm", "app-1", "")
	if vm, _ := corrosion.GetVM(ctx, b.DB, "app-1"); vm == nil || corrosion.FirewallIDOf(corrosion.TagMemberVM, vm.Spec) != "" {
		t.Fatalf("premise: %s, cut off, has not seen the mint: %+v", b.Name, vm)
	}
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true, BlockAll: true})
	for _, labels := range []map[string]string{{"tier": "front"}, {"tier": "front", "zone": "z1"}} {
		if _, err := c.SelfClient(b).SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "app-1", Labels: labels}); err != nil {
			t.Fatalf("SetVMLabels %v via %s: %v", labels, b.Name, err)
		}
	}
	if vm, _ := corrosion.GetVM(ctx, b.DB, "app-1"); vm == nil || !strings.Contains(vm.Spec, `"zone"`) {
		t.Fatalf("premise: %s made both label edits over its own view: %+v", b.Name, vm)
	}
	c.ClearLinkFaults()
	time.Sleep(2 * time.Second)
	// node-1's line of two edits reaches a later generation than the mint, so
	// it is kept on both lanes.
	for _, n := range c.Nodes {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	for _, n := range c.Nodes {
		eventually(t, convergeTimeout, n.Name+" to hold node-1's spec, with no identity", func() bool {
			vm, _ := corrosion.GetVM(ctx, n.DB, "app-1")
			return vm != nil && strings.Contains(vm.Spec, `"zone"`) && corrosion.FirewallIDOf(corrosion.TagMemberVM, vm.Spec) == ""
		})
	}
	if rec, ok := tagsRowOn(t, a, corrosion.TagMemberVM, id); !ok || !maps.Equal(rec.Tags, webTags) {
		t.Fatalf("premise: the erased identity's tags row holds %v: %+v (present %v)", webTags, rec, ok)
	}

	plan := nodePlan(t, a)
	held := false
	for _, nb := range plan.NICs {
		if nb.NICDev == tap {
			held = len(nb.SecurityGroups) == 0 && len(nb.ExtraRules) == 2 &&
				nb.ExtraRules[0].Action == firewall.Drop && strings.Contains(nb.ExtraRules[0].Comment, "firewall identity lost")
		}
	}
	if !held {
		t.Errorf("app-1's NIC %s on %s is not held at drop", tap, a.Name)
	}
	if chain := nicChain(renderPlan(t, plan), tap); strings.Contains(chain, "tcp dport 8443 accept") {
		t.Errorf("app-1's chain on %s carries the bound group's rule:\n%s", a.Name, chain)
	}
	if got := plan.TagGroups.IdentityLost; len(got) != 1 || got[0].Name != "app-1" || got[0].FWID != id || !slices.Equal(got[0].NICs, []string{tap}) {
		t.Errorf("%s reports %+v, want app-1 (fw_id %s) with %s held", a.Name, got, id, tap)
	}
	a.Server.RecordFirewallState(ctx, firewall.AppliedState{TagGroups: plan.TagGroups})
	cond, ok, err := corrosion.GetHealthCondition(ctx, a.DB, grpcapi.FirewallEvaluator, grpcapi.CondFirewallTagIdentityLost, "host", a.Name)
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || cond.Severity != corrosion.SeverityCritical {
		t.Errorf("identity_lost on %s = %+v (present %v, %v), want it raised critical", a.Name, cond, ok, err)
	}

	sw.Server.SweepFirewallTagOrphansForTest(ctx, time.Now().Add(25*time.Hour))
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if rec, ok := tagsRowOn(t, n, corrosion.TagMemberVM, id); !ok || !maps.Equal(rec.Tags, webTags) {
			t.Errorf("the erased identity's tags row on %s = %+v (present %v) at +25 h, want %v kept", n.Name, rec, ok, webTags)
		}
	}
}

// tgContainer creates container name on n with one NIC on ctnet (mac "" for
// one IPAM picks) and returns its leased address and its NIC's MAC.
func tgContainer(t *testing.T, c *Cluster, n *Node, name, mac string) (ip, nicMAC string) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateContainer(context.Background(), &pb.CreateContainerRequest{
		HostName: n.Name, Name: name, Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64",
		Cpu: 1, MemoryMib: 256,
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: ctNetName, Mac: mac}},
	}); err != nil {
		t.Fatalf("CreateContainer %s on %s: %v", name, n.Name, err)
	}
	ifaces := containerIfaces(t, n, name)
	if len(ifaces) == 0 || ifaces[0].IP == "" || ifaces[0].MAC == "" {
		t.Fatalf("container %s on %s has no leased managed NIC: %+v", name, n.Name, ifaces)
	}
	return strings.Split(ifaces[0].IP, "/")[0], ifaces[0].MAC
}

// m-2, R2-C1: a container migrated to node-1 keeps its membership (the move
// carries its identity, and its lease goes with it). A new container of the
// same name on node-0, given the member's MAC, is not a member: nothing
// matches on name, host or MAC.
//
// Mutations: clear the tags on migrate — the member drops out: red; match a
// lease to a member by kind and name, not host — the copy's address joins the
// set: red.
func TestTagGroup_AMigratedContainerKeepsItAndANameAndMACCopyDoesNot(t *testing.T) {
	c := gatedMigrateCluster(t)
	src, dst := c.Nodes[0], c.Nodes[1]
	seedContainerNetwork(t, c)
	tgGroup(t, c, src, "web")
	const name = "ct-web"
	ip, mac := tgContainer(t, c, src, name, "")
	id := tagVia(t, c, dst, "container", name, src.Name)
	tgEverywhere(t, c, "web", ip, true)

	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := ctFWIDOn(t, dst, dst.Name, name); got != id {
		t.Fatalf("the migrated container's identity = %q, want %q", got, id)
	}
	tgEverywhere(t, c, "web", ip, true)

	ip2, mac2 := tgContainer(t, c, src, name, mac)
	if !strings.EqualFold(mac2, mac) || ip2 == ip {
		t.Fatalf("premise: the copy on %s has the member's MAC %s and an address of its own: got %s %s", src.Name, mac, mac2, ip2)
	}
	for _, n := range c.Nodes {
		if set := tgSet(t, n, "web"); !slices.Equal(set, []string{ip}) {
			t.Errorf("%s's lv_tg_web = %v, want only the migrated member's %s (the copy's is %s)", n.Name, set, ip, ip2)
		}
		if got := tgMembers(t, n, "web"); !slices.Equal(got, []string{"ct " + dst.Name + "/" + name}) {
			t.Errorf("%s's members of web = %v, want the migrated container alone", n.Name, got)
		}
	}
}

// m-2: a rebuilt VM keeps its membership, on every node: the rebuild carries
// its identity, and the row keyed by it.
//
// Mutation: drop the carry token on rebuild — the rebuilt VM has no identity
// and drops out: red.
func TestTagGroup_ARebuiltVMKeepsItsMembership(t *testing.T) {
	c := tgFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	ip := tgVM(t, c, n0, "app-1", "52:54:00:7a:00:05")
	id := tagVia(t, c, n0, "vm", "app-1", "")
	tgEverywhere(t, c, "web", ip, true)

	if _, err := c.SelfClient(n1).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "app-1"}); err != nil {
		t.Fatalf("rebuild: %v; %s", err, whereIs(c, "app-1"))
	}
	c.WaitConverged(t, convergeTimeout)
	if got := vmFWIDOn(t, n0, "app-1"); got != id {
		t.Fatalf("the rebuilt VM's identity = %q, want %q", got, id)
	}
	tgEverywhere(t, c, "web", ip, true)
}

// R2-I1: node-1's replication is cut. web is tagged on node-0 (its owner),
// then deleted through node-1, which never saw the identity, so nobody
// clears the tags row. Replication resumes; a new web is cloned. No node's
// plan holds the new web's lease in lv_tg_web: the orphan row names web, but
// nothing matches on a name.
//
// Mutation: a workload with no identity takes the tags of an orphan row that
// names it (match on name) — the clone joins the set: red.
func TestTagGroup_ACloneIntoADeletedMembersNameIsNotAMember(t *testing.T) {
	c := tgFleet(t)
	a, b := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	tgCloneSource(t, c, a, "tpl")
	tgVM(t, c, a, "web", "52:54:00:7a:00:06")

	c.Isolate(b)
	id := tagViaCutOff(t, c, a, "vm", "web", "")
	if _, err := c.SelfClient(b).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("delete web via %s: %v", b.Name, err)
	}
	c.ClearLinkFaults()
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if rec, ok := tagsRowOn(t, n, corrosion.TagMemberVM, id); !ok || rec.Tags["role"] != "web" {
			t.Fatalf("premise: the deleted web's tags row is left on %s (%+v, present %v)", n.Name, rec, ok)
		}
	}

	if _, err := c.SelfClient(a).CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "web"}); err != nil {
		t.Fatalf("clone a new web: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := vmFWIDOn(t, a, "web"); got != "" {
		t.Fatalf("the new web holds identity %q", got)
	}
	ip := tgLease(t, c, a, "web", liveNIC(t, a, "web", tgNet).MAC)
	for _, n := range c.Nodes {
		eventually(t, convergeTimeout, n.Name+" to see the new web's lease", func() bool {
			_, ok := tgLeaseOn(t, n, "web")
			return ok
		})
	}
	tgNoneHolds(t, c, "web", ip)
}

// tagViaCutOff is tagVia that waits for no replica: some are cut off.
func tagViaCutOff(t *testing.T, c *Cluster, n *Node, kind, name, host string) string {
	t.Helper()
	for _, m := range c.Nodes {
		m.DB.SetRepointReady(func(context.Context) bool { return true })
	}
	out, err := c.SelfClient(n).SetFirewallTags(context.Background(), &pb.SetFirewallTagsRequest{
		Kind: kind, Workload: name, Host: host, Set: webTags})
	if err != nil || !corrosion.ValidFirewallID(out.GetFwId()) {
		t.Fatalf("tag set %s %s via %s: %+v %v", kind, name, n.Name, out, err)
	}
	return out.GetFwId()
}

// tgLeaseOn is VM name's live lease on tgnet in n's replica.
func tgLeaseOn(t *testing.T, n *Node, name string) (string, bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT ip FROM ip_allocations WHERE network = ? AND vm_name = ? AND owner_kind = 'vm' AND deleted_at IS NULL`, tgNet, name)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		return "", false
	}
	return rows[0].String("ip"), true
}

// tgCloneSource stages a clonable template on n with one NIC on tgnet. The
// disk is real because the clone engine is.
func tgCloneSource(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	seedCloneSourceOn(t, c, n, name, &pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256,
		Network: []*pb.NetworkAttachment{{Name: tgNet}}})
	c.WaitConverged(t, convergeTimeout)
}

// seedCloneSourceOn stages template name on n with spec and a real disk in
// n's image store.
func seedCloneSourceOn(t *testing.T, c *Cluster, n *Node, name string, spec *pb.VMSpec) {
	t.Helper()
	store := image.NewStore(filepath.Join(c.tmpRoot, n.Name, "data"))
	if err := store.Init(); err != nil {
		t.Fatalf("init image store on %s: %v", n.Name, err)
	}
	diskPath := store.DiskPath(name, "root")
	if err := mkdirAll(filepath.Dir(diskPath)); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(diskPath, 64<<20, nil); err != nil {
		t.Fatalf("create template disk: %v", err)
	}
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: n.Name, State: "stopped", IsTemplate: true, Spec: string(b), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: name, DiskName: "root", HostName: n.Name, Path: diskPath, SizeBytes: 64 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// The orphan sweep, on the failover lease holder (node-2): a tags row whose
// identity no live workload holds is cleared only once the grace has passed
// (fake clock) — after its newest tombstone, or, with no row holding it at
// all, after the row's own write (m-4).
//
// Mutations: sweep without the grace — red at an hour; drop the no-row case —
// the second row is never cleared: red.
func TestTagGroup_TheOrphanSweepWaitsOutTheGrace(t *testing.T) {
	c := tgFleet(t)
	a, sw := c.Nodes[0], c.Nodes[2]
	ctx := context.Background()
	tgVM(t, c, a, "app-1", "52:54:00:7a:00:07")
	id := tagVia(t, c, a, "vm", "app-1", "")
	a.Server.SetClearFirewallTagsForTest(func(context.Context, string, string) error {
		return errors.New("simulated clear failure")
	})
	if _, err := c.SelfClient(a).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "app-1", Force: true}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	// A row no workload ever held, on the sweeper's replica alone (its
	// clear then replicates the row everywhere).
	const noRow = "00000000000000000000000000000abc"
	seedTagsRow(t, sw, corrosion.TagMemberVM, noRow, `{"tags":{"role":"web"},"name":"ghost"}`)
	tgHoldFailoverLease(t, sw)

	left := func(fwID string) bool {
		rec, ok := tagsRowOn(t, sw, corrosion.TagMemberVM, fwID)
		return ok && len(rec.Tags) > 0
	}
	if !left(id) {
		t.Fatal("premise: the deleted VM's tags row is left (its clear failed)")
	}
	for _, after := range []time.Duration{time.Hour, 23 * time.Hour} {
		sw.Server.SweepFirewallTagOrphansForTest(ctx, time.Now().Add(after))
		if !left(id) || !left(noRow) {
			t.Fatalf("an orphan row was cleared %v after its tombstone or write, inside the grace", after)
		}
	}
	sw.Server.SweepFirewallTagOrphansForTest(ctx, time.Now().Add(25*time.Hour))
	if left(id) {
		t.Error("the deleted VM's row survives 25 h after its tombstone")
	}
	if left(noRow) {
		t.Error("a row no workload ever held survives 25 h after its write")
	}
	c.WaitConverged(t, convergeTimeout)
	if rec, ok := tagsRowOn(t, a, corrosion.TagMemberVM, id); !ok || len(rec.Tags) != 0 {
		t.Errorf("the sweep's clear did not reach %s: %+v (present %v)", a.Name, rec, ok)
	}
}

// tgHoldFailoverLease makes n the failover lease holder, the one host that
// sweeps.
func tgHoldFailoverLease(t *testing.T, n *Node) {
	t.Helper()
	held, _, err := corrosion.AcquireLeaseWithTerm(context.Background(), n.DB, corrosion.LeaseKeyFailover, n.Name, time.Hour, time.Now())
	if err != nil || !held {
		t.Fatalf("%s takes the failover lease: %v %v", n.Name, held, err)
	}
}

// A container migrated node-0 -> node-1 while the lease holder (node-2) has
// applied the source's tombstone but not yet the target's row: on node-2 no
// live row holds the identity, only a fresh tombstone. Its tags row survives
// the sweep there inside the grace and, once the target's row arrives, past
// it.
//
// Replication relays a host's writes through its peers, so cutting the one
// link from node-1 did not hold the target's row back. node-2 is cut off for
// the move instead, and the tombstone alone is applied to its replica, under
// the row's own clock, so the real one still wins when replication resumes.
//
// Mutation: sweep without the grace — the moving container's row is cleared:
// red.
// Mutation of the +48h block alone (seen): FirewallTagsOrphans ignores a live
// holder (`case false && h != nil && h.live`) — red at the +48h assertion, the
// +1h one still green.
func TestTagGroup_TheOrphanSweepSparesAContainerMidMove(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	src, dst, sw := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()
	probeCTRuntimes(c)
	c.WaitConverged(t, convergeTimeout)
	gatedLatch(t, c)
	const name = "ct-move"
	createContainer(t, c, src, name)
	c.WaitConverged(t, convergeTimeout)
	id := tagVia(t, c, src, "container", name, src.Name)
	tgHoldFailoverLease(t, sw)
	c.WaitConverged(t, convergeTimeout)

	c.Isolate(sw)
	if err := runMigrate(t, c, src, dst, name, stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := ctFWIDOn(t, dst, dst.Name, name); got != id {
		t.Fatalf("premise: the target holds %q, want %q", got, id)
	}
	if err := localExec(ctx, sw.DB, `UPDATE containers SET deleted_at = ? WHERE host_name = ? AND name = ? AND deleted_at IS NULL`,
		time.Now().UTC().Format(time.RFC3339Nano), src.Name, name); err != nil {
		t.Fatal(err)
	}
	if host := containerHostOn(t, sw, name); host != "" {
		t.Fatalf("premise: %s holds a live row of %s on %s", sw.Name, name, host)
	}
	sw.Server.SweepFirewallTagOrphansForTest(ctx, time.Now().Add(time.Hour))
	if rec, ok := tagsRowOn(t, sw, corrosion.TagMemberCT, id); !ok || len(rec.Tags) == 0 {
		t.Fatalf("the moving container's tags row was cleared inside the grace: %+v (present %v)", rec, ok)
	}

	c.ClearLinkFaults()
	waitForRepl(t, sw.Name+" to see the target's row", func() bool { return containerHostOn(t, sw, name) == dst.Name })
	sw.Server.SweepFirewallTagOrphansForTest(ctx, time.Now().Add(48*time.Hour))
	for _, n := range c.Nodes {
		if rec, ok := tagsRowOn(t, n, corrosion.TagMemberCT, id); !ok || !maps.Equal(rec.Tags, webTags) {
			t.Errorf("the moved container's tags row on %s = %+v (present %v), want %v kept", n.Name, rec, ok, webTags)
		}
	}
}

// gatedLatch latches the release on c, and the split-brain gate at quorum: a
// migrate then mints its relocation proof.
func gatedLatch(t *testing.T, c *Cluster) {
	t.Helper()
	gates := latchRelease(t, c)
	qctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	for _, n := range c.Nodes {
		go gates[n.Name].Start(qctx)
	}
	for _, n := range c.Nodes {
		eventually(t, 20*time.Second, "quorum on "+n.Name, func() bool {
			state, _, _ := gates[n.Name].QuorumProof(context.Background())
			return state == health.QuorumYes
		})
	}
}

// R3-I1: a tagged container is deleted through the real RPC with its tags
// clear failing, so its row is left. RestoreContainerReplica into the freed
// name yields a container with no identity, which no node counts a member,
// and the restore says which tags were left and how to set them again.
//
// Mutation: an insert keeps an incoming identity (the archived create spec
// carries the deleted one's) — the restored container is a member: red.
// Also red (seen): an operator restore that seeds its FirewallCarry from the
// same-name tombstone's create spec (the identity comes back, line 685).
func TestTagGroup_AReplicaRestoreIntoAFreedNameIsNotAMember(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	a, tg := c.Nodes[0], c.Nodes[2]
	ctx := context.Background()
	probeCTRuntimes(c)
	c.WaitConverged(t, convergeTimeout)
	gatedLatch(t, c)
	tgGroup(t, c, a, "web")
	const name = "web"
	replCT(t, c, a, name)
	repo := drRepo(t, tg)
	c.WaitConverged(t, convergeTimeout)
	id := tagVia(t, c, a, "container", name, a.Name)
	for _, n := range c.Nodes {
		if got := tgMembers(t, n, "web"); !slices.Equal(got, []string{"ct " + a.Name + "/" + name}) {
			t.Fatalf("premise: %s counts %v members of web, want the tagged container", n.Name, got)
		}
	}
	sched := ctSchedule(t, c, a, name, tg.Name, 2, true)
	c.WaitConverged(t, convergeTimeout)
	a.CT.Seed(name, "replicated")
	if err := a.Server.RunReplication(ctx, sched, time.Now().UTC().Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	ms := replicas(t, repo, name)
	if len(ms) != 1 {
		t.Fatalf("premise: one replica, got %d", len(ms))
	}

	for _, n := range c.Nodes {
		n.Server.SetClearFirewallTagsForTest(func(context.Context, string, string) error {
			return errors.New("simulated clear failure")
		})
	}
	if _, err := c.SelfClient(a).DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: a.Name, Name: name, Force: true}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	for _, n := range c.Nodes {
		waitForRepl(t, n.Name+" to apply the tombstone", func() bool { return containerHostOn(t, n, name) == "" })
	}
	c.WaitConverged(t, convergeTimeout)
	if rec, ok := tagsRowOn(t, tg, corrosion.TagMemberCT, id); !ok || rec.Tags["role"] != "web" {
		t.Fatalf("premise: the failed clear left the tags row: %+v (present %v)", rec, ok)
	}

	var hdr metadata.MD
	if _, err := c.SelfClient(tg).RestoreContainerReplica(ctx, &pb.RestoreContainerReplicaRequest{
		Repo: "dr", Project: "_default", Name: name, Timestamp: ms[0].Timestamp,
	}, grpc.Header(&hdr)); err != nil {
		t.Fatalf("restore the replica into the freed name: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := ctFWIDOn(t, tg, tg.Name, name); got != "" {
		t.Fatalf("the restored container holds identity %q (the deleted one's was %q)", got, id)
	}
	for _, n := range c.Nodes {
		if got := tgMembers(t, n, "web"); len(got) != 0 {
			t.Errorf("%s counts %v members of web after the restore, want none", n.Name, got)
		}
	}
	note := strings.Join(hdr.Get("x-litevirt-firewall-tags-left"), "\n")
	if want := "lv firewall tag set " + name + " --container --host " + tg.Name + " role=web"; !strings.Contains(note, want) {
		t.Errorf("the restore's note %q does not say %q", note, want)
	}
}

// R3-I1: the same for a VM restored into a freed name. The deleted VM's tags
// row is left (its clear failed), and the backup's spec carries the deleted
// VM's identity; the restored VM has none, so its lease is in no node's set,
// and the restore says which tags were left.
//
// Mutation: an insert keeps an incoming identity — the restored VM is a
// member: red.
// Also red (seen): RestoreLive's vmRecord takes its FirewallCarry from the
// same-name tombstone's spec (the identity comes back).
func TestTagGroup_AVMRestoredIntoAFreedNameIsNotAMember(t *testing.T) {
	c := tgFleet(t)
	a := c.Nodes[0]
	ctx := context.Background()
	const mac = "52:54:00:7a:00:08"
	tgVM(t, c, a, "web", mac)
	id := tagVia(t, c, a, "vm", "web", "")
	repo, ts := seedVMBackupWithSpec(t, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, FirewallId: id,
		Network: []*pb.NetworkAttachment{{Name: tgNet, Mac: mac}}})
	for _, n := range c.Nodes {
		n.Server.SetClearFirewallTagsForTest(func(context.Context, string, string) error {
			return errors.New("simulated clear failure")
		})
	}
	if _, err := c.SelfClient(a).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if rec, ok := tagsRowOn(t, a, corrosion.TagMemberVM, id); !ok || rec.Tags["role"] != "web" {
		t.Fatalf("premise: the failed clear left the tags row: %+v (present %v)", rec, ok)
	}

	notes, err := tgRestoreLive(c, a, repo, "web", ts)
	if err != nil {
		t.Fatalf("restore into the freed name: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	if got := vmFWIDOn(t, a, "web"); got != "" {
		t.Fatalf("the restored VM holds identity %q (the deleted one's was %q)", got, id)
	}
	ip, ok := tgLeaseOn(t, a, "web")
	if !ok {
		ip = tgLease(t, c, a, "web", mac)
	}
	tgNoneHolds(t, c, "web", ip)
	if want := "lv firewall tag set web role=web"; !strings.Contains(notes, want) {
		t.Errorf("the restore's progress %q does not say %q", notes, want)
	}
}

// tgRestoreLive runs an auto-starting live restore of vm into its own name
// on n and returns every status line it sent.
func tgRestoreLive(c *Cluster, n *Node, repo, vm, ts string) (string, error) {
	st, err := c.SelfClient(n).RestoreLive(context.Background(), &pb.RestoreLiveRequest{
		RepoPath: repo, VmName: vm, DiskName: "root", Timestamp: ts,
		TargetPath: vm + ".qcow2", NewName: vm, AutoStart: true, Blockpull: true,
	})
	if err != nil {
		return "", err
	}
	var lines []string
	for {
		p, err := st.Recv()
		if err == io.EOF {
			return strings.Join(lines, "\n"), nil
		}
		if err != nil {
			return strings.Join(lines, "\n"), err
		}
		lines = append(lines, p.GetStatus())
	}
}

// A group binding web-in reaches its member's NIC chain: before the tag, the
// VM's chain carries none of web-in's rule; tagged, it does.
//
// Mutation: bind no group's security groups to its members (bound returns
// the NIC's own) — red.
func TestTagGroup_TheBoundGroupAppearsInTheMembersChain(t *testing.T) {
	c := New(t, Options{Nodes: 3, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
	}
	latchRelease(t, c)
	host := c.Nodes[1]
	tgSeedNetwork(t, c, c.Nodes[0])
	mustCreateSG(t, c, c.Nodes[0], "web-in", "8443")
	c.WaitConverged(t, convergeTimeout)
	tgGroup(t, c, c.Nodes[0], "web", "web-in")
	tgVM(t, c, host, "app-1", "52:54:00:7a:00:09")
	tap := mustTap(t, host, "app-1", "52:54:00:7a:00:09")
	if chain := nicChain(renderPlan(t, nodePlan(t, host)), tap); strings.Contains(chain, "tcp dport 8443 accept") {
		t.Fatalf("control: untagged, app-1's chain carries web-in's rule:\n%s", chain)
	}

	tagVia(t, c, c.Nodes[2], "vm", "app-1", "")
	eventually(t, convergeTimeout, "web-in's rule in app-1's chain", func() bool {
		return strings.Contains(nicChain(renderPlan(t, nodePlan(t, host)), tap), "oifname "+tap+" tcp dport 8443 accept")
	})
}

// With one node quarantined (a host on the previous build), tag set,
// tag-group set and a tag: rule are each refused with the release text, and
// nothing records a use; once every host runs this build, all are accepted.
//
// Mutation: grant firewall_tag_groups without the release latch — the
// mid-roll writes land: red.
func TestTagGroup_RefusedWhileANodeIsQuarantined(t *testing.T) {
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1171)
	a, old := c.Nodes[0], c.Nodes[2]
	for _, n := range c.Nodes {
		n.DB.SetRepointReady(func(context.Context) bool { return true })
	}
	seedVM(t, c, a, &pb.VMSpec{Name: "app-1", Cpu: 1, MemoryMib: 256})
	cl := c.SelfClient(a)
	group := func() error {
		_, err := cl.SetFirewallTagGroup(ctx, &pb.SetFirewallTagGroupRequest{
			Group: &pb.FirewallTagGroup{Name: "web", Match: map[string]string{"role": "web"}}})
		return err
	}
	tag := func() error {
		_, err := cl.SetFirewallTags(ctx, &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "app-1", Set: webTags})
		return err
	}
	rule := func() error {
		_, err := cl.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{
			Direction: "ingress", Proto: "tcp", Port: "5432", Cidr: "tag:web", Action: "accept"}})
		return err
	}
	writes := []struct {
		what string
		do   func() error
	}{{"tag-group set", group}, {"tag set", tag}, {"a tag: rule", rule}}

	old.Server.SetWALQuarantined(func() bool { return true })
	want := "the cluster upgrade must finish first (" + string(capabilities.FeatureFirewallTagGroups) + " needs " + capabilities.ReleaseToken + ")"
	for _, w := range writes {
		if err := w.do(); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
			t.Errorf("%s mid-roll: %v, want the release refusal", w.what, err)
		}
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureFirewallTagGroups)) {
			t.Fatalf("%s holds a firewall_tag_groups use although every write was refused", n.Name)
		}
	}
	if ok, err := corrosion.FirewallTagGroupsDataPresent(ctx, a.DB); err != nil || ok {
		t.Fatalf("tag-group data written mid-roll: %v %v", ok, err)
	}

	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	for _, w := range writes {
		eventually(t, 10*time.Second, w.what+" to be accepted on a uniform fleet", func() bool { return w.do() == nil })
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureFirewallTagGroups)) {
			t.Errorf("%s does not hold the firewall_tag_groups use although its data was written", n.Name)
		}
	}
}

// 0-F: a tag: rule written straight to the replicated store, past the gate
// (as an entry daemon on an older build would store it), records no use; the
// lease holder's use sweep finds it in its next pass and records the use
// cluster-wide. A host that does not hold the lease records nothing.
//
// Mutation: never sweep (sweepReleaseUses returns at once) — red.
func TestTagGroup_TheUseSweepRecordsADirectlyWrittenRow(t *testing.T) {
	ctx := context.Background()
	c, gates := latchedFleet(t, 3, 1172)
	latchReleaseToken(t, c, gates)
	holder, other := c.Nodes[1], c.Nodes[2]
	if err := corrosion.InsertClusterFirewallRuleWithGrant(ctx, c.Nodes[0].DB, capabilities.FeatureGrant{}, capabilities.FeatureGrant{},
		capabilities.GrantForTest(t, capabilities.FeatureFirewallTagGroups), corrosion.FirewallRule{
			ID: "fw-direct", Direction: "ingress", Proto: "tcp", PortRange: "5432", CIDR: "tag:web", Action: "accept"}); err != nil {
		t.Fatal(err)
	}
	tgHoldFailoverLease(t, holder)
	c.WaitConverged(t, convergeTimeout)
	used := func(n *Node) bool {
		return featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureFirewallTagGroups))
	}
	for _, n := range c.Nodes {
		if used(n) {
			t.Fatalf("premise: %s holds a use before any sweep", n.Name)
		}
	}
	other.Server.SweepReleaseUsesForTest(ctx)
	if used(other) {
		t.Fatalf("%s, which does not hold the failover lease, recorded the use", other.Name)
	}
	holder.Server.SweepReleaseUsesForTest(ctx)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if !used(n) {
			t.Errorf("%s holds no firewall_tag_groups use after the lease holder's sweep", n.Name)
		}
	}
}
