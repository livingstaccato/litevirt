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
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
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

// legacyGroups is the security_groups column of vmName's vm_interfaces row on
// netName — what a peer on an older build renders from.
func legacyGroups(t *testing.T, n *Node, vmName, netName string) []string {
	t.Helper()
	ifaces, err := corrosion.GetVMInterfaces(context.Background(), n.DB, vmName)
	if err != nil {
		t.Fatalf("GetVMInterfaces %s: %v", vmName, err)
	}
	for _, i := range ifaces {
		if i.NetworkName == netName {
			return i.SecurityGroups
		}
	}
	return nil
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

// TestFleet_SG_HotAttachedNICIsEnforced: a NIC attached with groups gets a
// chain, before the hardware_v2 latch (vm_nics + legacy dual write) and after
// it (vm_nics only). Pre-latch the legacy row must carry the groups too, both
// for a peer on an older build and so the hardware bridge — which mirrors a
// strictly newer legacy row into vm_nics — cannot copy a group-less legacy row
// over the hot-attach's vm_nics groups.
func TestFleet_SG_HotAttachedNICIsEnforced(t *testing.T) {
	for _, tc := range []struct {
		name    string
		latchV2 bool
	}{
		{"before hardware_v2", false},
		{"after hardware_v2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := sgCluster(t)
			ctx := context.Background()
			gates := gateAll(t, c)
			if tc.latchV2 {
				latchHardwareV2(t, c, gates)
			} else {
				latchOperationProtocol(t, c, gates)
			}
			host := c.Nodes[1]
			mustCreateSG(t, c, host, "web", "443")
			mustCreateNICLessVM(t, c, host, "app")

			if _, err := c.SelfClient(host).AttachDevice(ctx, &pb.AttachDeviceRequest{
				VmName: "app",
				Nic:    &pb.NetworkAttachment{Name: sgNet, SecurityGroups: []string{"web"}},
			}); err != nil {
				t.Fatalf("AttachDevice nic with groups: %v", err)
			}
			nic := liveNIC(t, host, "app", sgNet)
			tap := mustTap(t, host, "app", nic.MAC)

			if chain := nicChain(renderPlan(t, nodePlan(t, host)), tap); !strings.Contains(chain, "oifname "+tap+" tcp dport 443 accept") {
				t.Fatalf("hot-attached NIC %s (tap %s) must carry its web rule; chain:\n%s", nic.MAC, tap, chain)
			}
			if tc.latchV2 {
				return
			}
			if got := legacyGroups(t, host, "app", sgNet); len(got) != 1 || got[0] != "web" {
				t.Errorf("pre-latch the legacy vm_interfaces row must carry the NIC's groups for older peers; got %v", got)
			}
			// One bridge pass, as every node runs every 30s.
			if err := corrosion.BridgeVMNICs(ctx, host.DB, "app"); err != nil {
				t.Fatalf("BridgeVMNICs: %v", err)
			}
			if chain := nicChain(renderPlan(t, nodePlan(t, host)), tap); !strings.Contains(chain, "tcp dport 443 accept") {
				t.Errorf("after a hardware bridge pass the hot-attached NIC lost its web rule; chain:\n%s", chain)
			}
		})
	}
}

// seedCloneSourceWithNIC stages a clonable template on n whose spec has one NIC
// on sgNet bound to groups. The disk is real because the clone engine is.
func seedCloneSourceWithNIC(t *testing.T, c *Cluster, n *Node, name string, groups []string) {
	t.Helper()
	ctx := context.Background()
	store := image.NewStore(filepath.Join(c.tmpRoot, n.Name, "data"))
	if err := store.Init(); err != nil {
		t.Fatalf("init image store on %s: %v", n.Name, err)
	}
	diskPath := store.DiskPath(name, "root")
	if err := mkdirAll(filepath.Dir(diskPath)); err != nil {
		t.Fatalf("mkdir disk dir: %v", err)
	}
	if err := qcow2.Create(diskPath, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: sgNet, SecurityGroups: groups}}})
	if err != nil {
		t.Fatalf("marshal source spec: %v", err)
	}
	if err := corrosion.InsertVM(ctx, n.DB,
		corrosion.VMRecord{Name: name, HostName: n.Name, State: "stopped", IsTemplate: true,
			Spec: string(spec), CPUActual: 1, MemActual: 512},
		nil,
		[]corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: n.Name, Path: diskPath,
			SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// TestFleet_SG_ClonedNICIsEnforced: a clone of a template whose NIC has a
// group must come up with that group enforced on its own tap, and its legacy
// row must carry the group for a peer on an older build. The clone is entered
// on the other node, so it is forwarded to the template's host.
func TestFleet_SG_ClonedNICIsEnforced(t *testing.T) {
	c := sgCluster(t)
	ctx := context.Background()
	entry, host := c.Nodes[0], c.Nodes[1]
	mustCreateSG(t, c, host, "db", "5432")
	seedCloneSourceWithNIC(t, c, host, "tpl", []string{"db"})

	if _, err := c.SelfClient(entry).CloneVM(ctx, &pb.CloneVMRequest{
		Source: "tpl", Target: "db1", Start: true,
	}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	nic := liveNIC(t, host, "db1", sgNet)
	tap := mustTap(t, host, "db1", nic.MAC)
	if chain := nicChain(renderPlan(t, nodePlan(t, host)), tap); !strings.Contains(chain, "oifname "+tap+" tcp dport 5432 accept") {
		t.Errorf("the clone's NIC (tap %s) must carry the db rule; chain:\n%s", tap, chain)
	}
	if got := legacyGroups(t, host, "db1", sgNet); len(got) != 1 || got[0] != "db" {
		t.Errorf("the clone's legacy vm_interfaces row must carry its groups for older peers; got %v", got)
	}
}

// TestFleet_SG_DuplicateNameFailsClosed: a second live group cannot be created
// under a name already held, and where two already exist (written before this
// refusal, or by a peer on an older build) a NIC bound to that name is held at
// drop — neither group's rules are rendered for it, and no other NIC changes.
func TestFleet_SG_DuplicateNameFailsClosed(t *testing.T) {
	c := sgCluster(t)
	ctx := context.Background()
	entry, host := c.Nodes[0], c.Nodes[1]
	mustCreateSG(t, c, entry, "web", "80")
	mustCreateSG(t, c, entry, "ssh", "22")

	_, err := c.SelfClient(entry).CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("creating a second live group named web: got %v, want AlreadyExists", err)
	}

	// The pre-existing duplicate, as an older build could write it.
	if err := corrosion.InsertSecurityGroup(ctx, host.DB, corrosion.SecurityGroup{ID: "zz-legacy-web", Name: "web"}); err != nil {
		t.Fatalf("seed duplicate group: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, host.DB, corrosion.SGRule{ID: "zz-legacy-rule", SGID: "zz-legacy-web",
		Direction: "ingress", Proto: "tcp", PortRange: "8080", Action: "accept"}); err != nil {
		t.Fatalf("seed duplicate group rule: %v", err)
	}

	for _, vm := range []struct {
		name   string
		groups []string
	}{
		{"web1", []string{"web", "ssh"}},
		{"bastion", []string{"ssh"}},
	} {
		if _, err := c.SelfClient(host).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: vm.name, Cpu: 1, MemoryMib: 512, Placement: &pb.PlacementSpec{Host: host.Name},
			Network: []*pb.NetworkAttachment{{Name: sgNet, SecurityGroups: vm.groups}},
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", vm.name, err)
		}
	}
	webTap := mustTap(t, host, "web1", liveNIC(t, host, "web1", sgNet).MAC)
	bastionTap := mustTap(t, host, "bastion", liveNIC(t, host, "bastion", sgNet).MAC)

	out := renderPlan(t, nodePlan(t, host))
	chain := nicChain(out, webTap)
	for _, want := range []string{"oifname " + webTap + " drop", "iifname " + webTap + " drop"} {
		if !strings.Contains(chain, want) {
			t.Errorf("web1 is bound to a name two live groups hold; its chain must drop (%q):\n%s", want, chain)
		}
	}
	for _, leaked := range []string{"dport 80 ", "dport 8080 ", "dport 22 "} {
		if strings.Contains(chain, leaked) {
			t.Errorf("a NIC failed closed must render no group's rules, found %q:\n%s", leaked, chain)
		}
	}
	if bc := nicChain(out, bastionTap); !strings.Contains(bc, "tcp dport 22 accept") || strings.Contains(bc, " drop") {
		t.Errorf("bastion binds only the unambiguous ssh group and must be unaffected:\n%s", bc)
	}
}
