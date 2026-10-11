package firewall

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCorrosionPlanLoader_NoRecordTrunkLimitedOnceRecorded (re-review R3-I1):
// lacking a guard record grants a trunk nothing. Once the upgrade recording
// has run, every trunk NIC — recorded or not — carries only the VLANs its
// network allows (the lists recorded at upgrade, plus what an operator
// allows), and the rest are reported. Before that first recording a trunk
// that predates guards keeps its own VLANs, so nothing in use breaks while
// the lists are written.
func TestCorrosionPlanLoader_NoRecordTrunkLimitedOnceRecorded(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: "core", Type: "bridge",
		Config: `{"Type":"bridge","Interface":"brcore","AllowedVLANs":[100]}`}); err != nil {
		t.Fatal(err)
	}
	for _, vm := range []struct{ name, mac, vids string }{
		{"legacy", "52:54:00:00:00:02", "100,102"},
		{"recreated", "52:54:00:00:00:03", "30,31"},
	} {
		spec := `{"name":"` + vm.name + `","uuid":"u-` + vm.name + `","network":[{"name":"core","trunk":[` + vm.vids + `]}]}`
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm.name, HostName: "host-a", State: "running", Spec: spec},
			[]corrosion.InterfaceRecord{{VMName: vm.name, NetworkName: "core", MAC: vm.mac}}, nil); err != nil {
			t.Fatal(err)
		}
	}
	load := func() Plan {
		t.Helper()
		plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
			"legacy": {"52:54:00:00:00:02": "vnet2"}, "recreated": {"52:54:00:00:00:03": "vnet3"},
		}))(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return plan
	}
	vids := func(p Plan) map[string][]int {
		out := map[string][]int{}
		for _, n := range p.NICs {
			out[n.NICDev] = n.TrunkVIDs
		}
		return out
	}

	if got, want := vids(load()), map[string][]int{"vnet2": {100, 102}, "vnet3": {30, 31}}; !reflect.DeepEqual(got, want) {
		t.Errorf("before the upgrade recording: trunk VIDs = %v, want %v (nothing in use breaks)", got, want)
	}

	if err := corrosion.SetClusterPolicy(ctx, db, "firewall_trunk_vlans_recorded", `{"core":[100]}`, "t"); err != nil {
		t.Fatal(err)
	}
	plan := load()
	if got, want := vids(plan), map[string][]int{"vnet2": {100}, "vnet3": nil}; !reflect.DeepEqual(got, want) {
		t.Errorf("once recorded: trunk VIDs = %v, want %v: a NIC with no record carries only what its network allows", got, want)
	}
	blocked := map[string][]int{}
	for _, b := range plan.BlockedTrunks {
		blocked[b.Workload] = b.VIDs
	}
	if want := map[string][]int{"legacy": {102}, "recreated": {30, 31}}; !reflect.DeepEqual(blocked, want) {
		t.Errorf("blocked = %v, want %v", blocked, want)
	}

	// A trunk none of whose VLANs pass drops every tagged frame in either
	// mode: in observe mode the plain VLAN rule only counts, and the VLANs
	// would leave through the uplink.
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		plan.NICMode = mode
		out, err := Render(plan)
		if err != nil {
			t.Fatal(err)
		}
		pre := chainBody(t, nicPart(t, plan), "prerouting")
		if !strings.Contains(pre, "iifname vnet3 ether type { 8021q, 8021ad } drop") {
			t.Errorf("%s: a trunk with no allowed VLAN does not drop its tagged frames:\n%s", mode, out)
		}
	}
}

// TestCorrosionPlanLoader_FlatBridgeTrunkUsesTheRecordedList (re-review
// R3-I1): a NIC on a network with no row (a flat bridge) has no allowed list
// an operator can set; its trunk carries the VLANs recorded for it at
// upgrade.
func TestCorrosionPlanLoader_FlatBridgeTrunkUsesTheRecordedList(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	spec := `{"name":"flat","uuid":"u-flat","network":[{"name":"rawbr","trunk":[7,8,9]}]}`
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "flat", HostName: "host-a", State: "running", Spec: spec},
		[]corrosion.InterfaceRecord{{VMName: "flat", NetworkName: "rawbr", MAC: "52:54:00:00:00:04"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetClusterPolicy(ctx, db, "firewall_trunk_vlans_recorded", `{"rawbr":[7,8]}`, "t"); err != nil {
		t.Fatal(err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"flat": {"52:54:00:00:00:04": "vnet4"},
	}))(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.NICs) != 1 {
		t.Fatalf("NICs = %+v", plan.NICs)
	}
	got := append([]int(nil), plan.NICs[0].TrunkVIDs...)
	sort.Ints(got)
	if !reflect.DeepEqual(got, []int{7, 8}) {
		t.Errorf("flat-bridge trunk VIDs = %v, want the recorded [7 8]", got)
	}
}
