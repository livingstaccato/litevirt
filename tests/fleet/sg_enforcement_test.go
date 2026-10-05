// Fleet scenarios: a VM's security groups are enforced on the NIC it actually
// has.
//
// The per-NIC firewall chain is keyed by the host tap device. Three things went
// wrong between the API and nft, and none is visible to a single-package test
// because each needs the real create / lifecycle / hotplug / clone RPCs to
// produce the rows the reconciler reads:
//
//   - the tap was recorded once, at create, and libvirt hands out a new vnetN on
//     every start, so after `lv stop; lv start` the chain matched nothing and the
//     VM ran unfiltered (lab-confirmed on main-c7aa96f9);
//   - a hot-attached NIC's groups were written to vm_nics only, which the
//     reconciler never read, so it got no chain at all;
//   - two live groups with one name made an arbitrary one win silently.
//
// Each node's plan is built by the production loader exactly as the daemon
// builds it, with the node's libvirt fake as the tap resolver. The fake hands
// out a fresh vnetN per domain start, as libvirt does.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// ── helpers ─────────────────────────────────────────────────────────────────

// sgNet is a raw bridge name. The fleet caller is cluster-root, so a raw bridge
// is admitted, and no network row is needed for the firewall path under test.
const sgNet = "br-sg"

// sgCluster is a two-node shared-CRDT fleet whose nodes accept the raw sgNet
// bridge through the network fake instead of `ip link`.
func sgCluster(t *testing.T) *Cluster {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(n.Net.EnsureBridge)
	}
	return c
}

// nodePlan builds node n's firewall plan through the production loader, with
// n's libvirt as the tap resolver — the daemon's wiring.
func nodePlan(t *testing.T, n *Node) firewall.Plan {
	t.Helper()
	plan, err := firewall.CorrosionPlanLoader(n.DB, n.Name, firewall.Plan{},
		firewall.LoaderOptions{ResolveTap: n.Virt.TapDevice})(context.Background())
	if err != nil {
		t.Fatalf("firewall plan on %s: %v", n.Name, err)
	}
	return plan
}

// renderPlan renders a plan, failing the test on a render error.
func renderPlan(t *testing.T, p firewall.Plan) string {
	t.Helper()
	out, err := firewall.Render(p)
	if err != nil {
		t.Fatalf("render firewall plan: %v", err)
	}
	return out
}

// nicChain returns the body of the per-NIC chain for tap in a rendered ruleset,
// or "" when there is none.
func nicChain(rendered, tap string) string {
	head := "chain nic_" + strings.NewReplacer("-", "_", ".", "_").Replace(tap) + " {\n"
	i := strings.Index(rendered, head)
	if i < 0 {
		return ""
	}
	body := rendered[i+len(head):]
	if j := strings.Index(body, "\n    }"); j >= 0 {
		body = body[:j]
	}
	return body
}

// mustCreateSG creates a security group with one ingress tcp accept on port,
// over the real RPCs, and returns its id.
func mustCreateSG(t *testing.T, c *Cluster, n *Node, name, port string) string {
	t.Helper()
	ctx := context.Background()
	sg, err := c.SelfClient(n).CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: name})
	if err != nil {
		t.Fatalf("CreateSecurityGroup %q: %v", name, err)
	}
	if _, err := c.SelfClient(n).AddSecurityGroupRule(ctx, &pb.AddSecurityGroupRuleRequest{
		Rule: &pb.SecurityGroupRule{SgId: sg.Id, Direction: "ingress", Proto: "tcp", Port: port, Action: "accept"},
	}); err != nil {
		t.Fatalf("AddSecurityGroupRule on %q: %v", name, err)
	}
	return sg.Id
}

// liveNIC returns the one NIC of vmName on network netName from the overlay.
func liveNIC(t *testing.T, n *Node, vmName, netName string) corrosion.NICRecord {
	t.Helper()
	nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, vmName)
	if err != nil {
		t.Fatalf("MergedVMNICs %s: %v", vmName, err)
	}
	for _, x := range nics {
		if x.NetworkName == netName {
			return x
		}
	}
	t.Fatalf("%s has no NIC on %q (NICs: %+v)", vmName, netName, nics)
	return corrosion.NICRecord{}
}

// mustTap asks n's libvirt for the tap of vmName's NIC with mac.
func mustTap(t *testing.T, n *Node, vmName, mac string) string {
	t.Helper()
	tap, err := n.Virt.TapDevice(vmName, mac)
	if err != nil {
		t.Fatalf("libvirt has no tap for %s/%s: %v", vmName, mac, err)
	}
	return tap
}

// ── scenarios ───────────────────────────────────────────────────────────────

// TestFleet_SG_ChainFollowsTheTapAcrossARestart is the lab finding: create a VM
// with a group, stop it, start it. libvirt gives the NIC a new vnetN, and the
// chain has to be on that one.
func TestFleet_SG_ChainFollowsTheTapAcrossARestart(t *testing.T) {
	c := sgCluster(t)
	ctx := context.Background()
	host := c.Nodes[1]
	mustCreateSG(t, c, host, "ssh", "22")

	if _, err := c.SelfClient(host).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 512, Placement: &pb.PlacementSpec{Host: host.Name},
		Network: []*pb.NetworkAttachment{{Name: sgNet, SecurityGroups: []string{"ssh"}}},
	}}); err != nil {
		t.Fatalf("CreateVM web: %v", err)
	}
	nic := liveNIC(t, host, "web", sgNet)
	before := mustTap(t, host, "web", nic.MAC)
	if chain := nicChain(renderPlan(t, nodePlan(t, host)), before); !strings.Contains(chain, "tcp dport 22 accept") {
		t.Fatalf("control: before any restart, web's tap %s must carry the ssh rule; chain:\n%s", before, chain)
	}

	if _, err := c.SelfClient(host).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM web: %v", err)
	}
	if _, err := c.SelfClient(host).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM web: %v", err)
	}
	after := mustTap(t, host, "web", nic.MAC)
	if after == before {
		t.Fatalf("harness: the restart must move the NIC to a new tap (still %s), or this proves nothing", after)
	}

	out := renderPlan(t, nodePlan(t, host))
	if chain := nicChain(out, after); !strings.Contains(chain, "oifname "+after+" tcp dport 22 accept") {
		t.Errorf("after stop/start web's NIC is %s, and its chain must carry the ssh rule; chain:\n%s\nruleset:\n%s",
			after, chain, out)
	}
	if nicChain(out, before) != "" {
		t.Errorf("the pre-restart tap %s no longer belongs to web and must have no chain:\n%s", before, out)
	}
}
