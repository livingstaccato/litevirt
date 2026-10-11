package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

const composeTrunk = `name: trk

images:
  test:
    source: file:///dev/null

networks:
  core:
    external: true

vms:
  web:
    image: test
    cpu: 1
    memory: 512
    network:
      - name: core
        trunk: [10, 11]
    placement:
      host: node-0
    update:
      strategy: rolling
      health-wait: 2s
  keep:
    image: test
    cpu: 1
    memory: 512
    network:
      - name: core
        trunk: [10, 11]
    placement:
      host: node-0
    update:
      strategy: rolling
      health-wait: 2s
`

// planOn is node n's per-NIC plan from its own replica, with libvirt's taps
// from n's fake.
func planOn(t *testing.T, n *Node) firewall.Plan {
	t.Helper()
	plan, err := firewall.CorrosionPlanLoader(n.DB, n.Name, firewall.Plan{}, firewall.LoaderOptions{
		RunningTaps: n.Virt.RunningDomainTaps,
		TapBridge:   func(string) string { return "" },
	})(context.Background())
	if err != nil {
		t.Fatalf("plan on %s: %v", n.Name, err)
	}
	return plan
}

// TestFleet_NICGuard_RecreateCannotWidenAPreGuardTrunk (re-review R3-I1): a
// VM that predates guards has no guard record. Re-created through a stack's
// rolling update with trunk VLANs it never had, its NIC is a new NIC: it is
// guarded, and the new VLANs do not pass — in observe mode too, which every
// upgraded cluster starts in. A re-create that keeps its VLANs stays as it
// ran.
func TestFleet_NICGuard_RecreateCannotWidenAPreGuardTrunk(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetBridgeEnsure(func(string) error { return nil })
	if err := corrosion.UpsertNetwork(ctx, node.DB, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore","External":true}`}); err != nil {
		t.Fatal(err)
	}
	// Before the upgrade: the store is closed, so no record is written.
	if msgs, err := deployRolling(t, ctx, client, composeTrunk, 30*time.Second); err != nil {
		t.Fatalf("deploy: %v (%v)", err, msgs)
	}
	if all, err := corrosion.ListNICGuards(ctx, node.DB); err != nil || len(all) != 0 {
		t.Fatalf("fixture: records before the upgrade = %v, %v", all, err)
	}
	// The upgrade: records can be written, and the trunks in use are recorded.
	openNICGuards(t, node)
	rctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	node.Server.RecordExistingTrunkVLANsLoop(rctx, 50*time.Millisecond)
	cancel()

	// A NIC model change makes the rolling update re-create both VMs (a trunk
	// change alone is not a topology change); web's re-create also brings
	// VLANs 30 and 31, keep's keeps its VLANs.
	widened := strings.Replace(composeTrunk, "        trunk: [10, 11]\n    placement:\n      host: node-0\n    update:\n      strategy: rolling\n      health-wait: 2s\n  keep:",
		"        trunk: [10, 11, 30, 31]\n        model: e1000\n    placement:\n      host: node-0\n    update:\n      strategy: rolling\n      health-wait: 2s\n  keep:", 1)
	widened = strings.Replace(widened, "        trunk: [10, 11]\n", "        trunk: [10, 11]\n        model: e1000\n", 1)
	if strings.Count(widened, "model: e1000") != 2 || !strings.Contains(widened, "[10, 11, 30, 31]") {
		t.Fatalf("fixture: the update is not what it says:\n%s", widened)
	}
	webBefore, _ := corrosion.GetVM(ctx, node.DB, "web")
	keepBefore, _ := corrosion.GetVM(ctx, node.DB, "keep")
	if msgs, err := deployRolling(t, ctx, client, widened, 30*time.Second); err != nil {
		t.Fatalf("redeploy: %v (%v)", err, msgs)
	}

	for name, before := range map[string]*corrosion.VMRecord{"web": webBefore, "keep": keepBefore} {
		if after, _ := corrosion.GetVM(ctx, node.DB, name); before == nil || after == nil || after.CreatedAt == before.CreatedAt {
			t.Fatalf("fixture: %s was not re-created", name)
		}
	}
	nics, err := corrosion.MergedVMNICs(ctx, node.DB, "web")
	if err != nil || len(nics) != 1 {
		t.Fatalf("web's NICs: %v %v", nics, err)
	}
	defer func() {
		if t.Failed() {
			vm, _ := corrosion.GetVM(ctx, node.DB, "web")
			nr, _ := corrosion.GetNetwork(ctx, node.DB, "core")
			t.Logf("web: %+v\ncore: %+v", vm, nr)
		}
	}()
	if rec, err := corrosion.GetNICGuard(ctx, node.DB, "web", nics[0].MAC); err != nil || rec == nil || !rec.Guarded() {
		t.Errorf("the re-created NIC took VLANs it never had and is unguarded: %+v, %v", rec, err)
	}
	plan := planOn(t, node)
	for _, mode := range []string{firewall.NICModeObserve, firewall.NICModeEnforce} {
		plan.NICMode = mode
		var web, keep *firewall.NICBinding
		for i := range plan.NICs {
			switch plan.NICs[i].VMName {
			case "web":
				web = &plan.NICs[i]
			case "keep":
				keep = &plan.NICs[i]
			}
		}
		if web == nil || keep == nil {
			t.Fatalf("NICs rendered: %+v", plan.NICs)
		}
		for _, v := range web.TrunkVIDs {
			if v == 30 || v == 31 {
				t.Errorf("%s: VLAN %d, added by the re-create, passes: %v", mode, v, web.TrunkVIDs)
			}
		}
		if got := keep.TrunkVIDs; len(got) != 2 {
			t.Errorf("%s: a re-create that kept its VLANs lost them: %v", mode, got)
		}
		out, err := firewall.Render(plan)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, web.NICDev+" vlan id != { 10, 11 } drop") {
			t.Errorf("%s: the re-created trunk is not confined to its recorded VLANs:\n%s", mode, out)
		}
	}
	blocked := false
	for _, b := range plan.BlockedTrunks {
		if b.Workload == "web" && len(b.VIDs) == 2 && b.VIDs[0] == 30 && b.VIDs[1] == 31 {
			blocked = true
		}
	}
	if !blocked {
		t.Errorf("the VLANs the re-create added are not reported: %+v", plan.BlockedTrunks)
	}
	all, err := corrosion.ListNICGuards(ctx, node.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, rec := range all {
		if rec.VMName == "keep" {
			t.Errorf("a re-create that kept its VLANs was newly guarded: %+v", rec)
		}
	}
}

// TestFleet_NICGuard_CloneOfATrunkIsGuarded (re-review R3-I1): a clone's NICs
// are new NICs, trunks included: a clone of a VM that predates guards does
// not inherit its source's lack of a record, so cloning is no way to a
// trunk NIC whose VLANs escape its network's list.
func TestFleet_NICGuard_CloneOfATrunkIsGuarded(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	openNICGuards(t, n)
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	setHostCapacity(t, c, n.Name, 64, 65536, nil)
	seedCloneSource(t, c, n, "tpl", "", 1, 256)
	if err := n.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'tpl'`,
		`{"name":"tpl","cpu":1,"memory_mib":256,"network":[{"name":"lan","trunk":[10,11]}]}`); err != nil {
		t.Fatal(err)
	}
	if _, err := cloneAt(t, c, n, "tpl", "copy"); err != nil {
		t.Fatalf("clone: %v", err)
	}
	all, err := corrosion.ListNICGuards(ctx, n.DB)
	if err != nil {
		t.Fatal(err)
	}
	guarded := false
	for _, r := range all {
		if r.VMName == "copy" && r.Guarded() {
			guarded = true
		}
	}
	if !guarded {
		t.Errorf("a clone's trunk NIC got no guard: %+v", all)
	}
}
