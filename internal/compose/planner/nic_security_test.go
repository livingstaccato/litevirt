package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The stored spec says what the NIC was created with: security group web and
// a guard allowing 10.0.0.250. The file says the same.
const nicSecStored = `{"image":"ubuntu","cpu":1,"memory_mib":512,"guest_agent":true,` +
	`"network":[{"name":"lan","mac":"52:54:00:00:00:01","security_groups":["web"],"spoof_guard":"on","allowed_addresses":["10.0.0.250"]}]}`

func nicSecDef(declared bool) compose.VMDef {
	n := compose.NetworkAttachment{Name: "lan"}
	if declared {
		n.SecurityGroups = []string{"web"}
		n.SpoofGuard = "on"
		n.AllowedAddresses = []string{"10.0.0.250"}
	}
	return compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512, Network: []compose.NetworkAttachment{n}}
}

func nicSecFile(declared bool) *compose.File {
	f := makeFile("mystack", map[string]compose.VMDef{"web": nicSecDef(declared)})
	f.Networks = map[string]compose.NetworkDef{"lan": {External: true}}
	return f
}

// N2: the deploy plan compares the file with the security the NIC is enforced
// with now, not with the stored spec. Runtime `sg bind` and `nic-guard set`
// changes are drift the update applies in place, and the unbind of a group
// bound outside the file is a warning.
func TestResolve_RuntimeNICSecurityDriftIsPlanned(t *testing.T) {
	state := makeState([]corrosion.HostRecord{makeHost("h1", 16, 32768)}, []corrosion.VMRecord{{
		Name: "web", StackName: "mystack", HostName: "h1", State: "running", Spec: nicSecStored, CPUActual: 1, MemActual: 512,
	}}, nil)
	state.NICSecurity = map[string][]compose.LiveNIC{"web": {{
		Network: "lan", MAC: "52:54:00:00:00:01", SecurityGroups: []string{"isolate"},
		Guard: &compose.LiveGuard{Mode: "on"},
	}}}
	plan, err := Resolve(context.Background(), nicSecFile(true), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.VMs) != 1 || plan.VMs[0].Kind != OpUpdate || plan.VMs[0].Apply != compose.ActionLive {
		t.Fatalf("planned %+v, want one live update", plan.VMs)
	}
	got := map[string]bool{}
	for _, d := range plan.VMs[0].Plan.MetadataChanges {
		got[d.Field] = true
	}
	if !got[compose.NICSecurityGroupsFieldPrefix+"0"] || !got[compose.NICGuardFieldPrefix+"0"] {
		t.Errorf("metadata changes %+v, want the binding and the guard", plan.VMs[0].Plan.MetadataChanges)
	}
	if w := strings.Join(plan.Warnings, "\n"); !strings.Contains(w, "isolate") || !strings.Contains(w, "10.0.0.250") {
		t.Errorf("warnings %q do not name the unbound group and the relaxed address", w)
	}

	// The same runtime changes under a file that declares neither are not
	// the file's to revert.
	plan, err = Resolve(context.Background(), nicSecFile(false), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.VMs) != 1 || plan.VMs[0].Kind != OpNoChange {
		t.Errorf("planned %+v over an undeclared binding and guard, want no change", plan.VMs)
	}
}

// LoadClusterState reads each stack VM's live NIC security: the NIC row's
// binding and the guard record of the VM's incarnation. A record written for
// another incarnation guards nothing and is not loaded.
func TestLoadClusterState_LoadsLiveNICSecurity(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	spec := `{"uuid":"u-2","network":[{"name":"lan","mac":"52:54:00:00:00:01"},{"name":"lan2","mac":"52:54:00:00:00:02"}]}`
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", StackName: "mystack", HostName: "h1", State: "running", Spec: spec},
		[]corrosion.InterfaceRecord{
			{VMName: "web", NetworkName: "lan", MAC: "52:54:00:00:00:01", Ordinal: 0},
			{VMName: "web", NetworkName: "lan2", MAC: "52:54:00:00:00:02", Ordinal: 1},
		}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetInterfaceSecurityGroups(ctx, db, "web", "lan", []string{"isolate"}); err != nil {
		t.Fatal(err)
	}
	g := capabilities.GrantForTest(t, capabilities.FeatureNICGuards)
	for _, r := range []corrosion.NICGuardRecord{
		{VMName: "web", MAC: "52:54:00:00:00:01", Mode: corrosion.NICGuardOff, AllowVLANTags: true, VMUUID: "u-2"},
		{VMName: "web", MAC: "52:54:00:00:00:02", Mode: corrosion.NICGuardOn, VMUUID: "u-1"}, // an earlier incarnation's
	} {
		if err := corrosion.PutNICGuard(ctx, db, g, r, "t"); err != nil {
			t.Fatal(err)
		}
	}
	state, err := LoadClusterState(ctx, db, corrosion.CapacityPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	live := state.NICSecurity["web"]
	if len(live) != 2 {
		t.Fatalf("NICSecurity[web] = %+v, want 2 NICs", live)
	}
	if n := live[0]; n.MAC != "52:54:00:00:00:01" || len(n.SecurityGroups) != 1 || n.SecurityGroups[0] != "isolate" ||
		n.Guard == nil || n.Guard.Mode != "off" || !n.Guard.AllowVLANTags {
		t.Errorf("nic 0 = %+v, want the bound group and the off guard", n)
	}
	if n := live[1]; n.Guard != nil {
		t.Errorf("nic 1 guard = %+v, want none (the record is another incarnation's)", n.Guard)
	}
}
