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
	// Without --allow-weaken the rebind and the relaxing guard restore are
	// withheld, and the plan says so.
	plan, err := Resolve(context.Background(), nicSecFile(true), state)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.VMs) != 1 || plan.VMs[0].Kind != OpNoChange {
		t.Fatalf("planned %+v without --allow-weaken, want no change", plan.VMs)
	}
	if w := strings.Join(plan.Warnings, "\n"); !strings.Contains(w, "isolate") || !strings.Contains(w, "--allow-weaken") {
		t.Errorf("warnings %q do not report the withheld restore", w)
	}

	state.NICSecurityGate.AllowWeaken = true
	plan, err = Resolve(context.Background(), nicSecFile(true), state)
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

// LoadStackNICSecurity reads the planned stack's VMs' live NIC security: the NIC row's
// binding and the guard record of the VM's incarnation. A record written for
// another incarnation guards nothing and is not loaded.
func TestLoadStackNICSecurity(t *testing.T) {
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
	// A VM of another stack whose rows are not read: only the planned stack
	// is loaded.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "else", StackName: "other", HostName: "h1", State: "running", Spec: spec}, nil, nil); err != nil {
		t.Fatal(err)
	}
	state, err := LoadClusterState(ctx, db, corrosion.CapacityPolicy{})
	if err != nil {
		t.Fatal(err)
	}
	if err := LoadStackNICSecurity(ctx, db, state, "mystack"); err != nil {
		t.Fatal(err)
	}
	if _, ok := state.NICSecurity["else"]; ok {
		t.Error("another stack's VM was read")
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

// I5: an image change recreates the VM from the file. A NIC the file declares
// no groups for keeps the binding it has now, and the plan says so.
func TestResolve_ARecreateKeepsAnUndeclaredBinding(t *testing.T) {
	state := makeState([]corrosion.HostRecord{makeHost("h1", 16, 32768)}, []corrosion.VMRecord{{
		Name: "web", StackName: "mystack", HostName: "h1", State: "running", Spec: nicSecStored, CPUActual: 1, MemActual: 512,
	}}, nil)
	state.NICSecurity = map[string][]compose.LiveNIC{"web": {{
		Network: "lan", MAC: "52:54:00:00:00:01", SecurityGroups: []string{"isolate"}, Guard: &compose.LiveGuard{Mode: "on"},
	}}}
	f := nicSecFile(false)
	def := f.VMs["web"]
	def.Image = "debian"
	def.Update = &compose.UpdateDef{Strategy: "recreate"}
	f.VMs["web"] = def
	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.VMs) != 1 || plan.VMs[0].Apply != compose.ActionRecreate {
		t.Fatalf("planned %+v, want a recreate", plan.VMs)
	}
	if g := plan.VMs[0].Spec.GetNetwork()[0].GetSecurityGroups(); len(g) != 1 || g[0] != "isolate" {
		t.Errorf("the recreate's NIC groups = %v, want the live isolate binding kept", g)
	}
	if w := strings.Join(plan.Warnings, "\n"); !strings.Contains(w, "keeps the security groups [isolate]") {
		t.Errorf("warnings %q do not say the binding is kept", w)
	}
}

// Round 3, N2: a guard the file declares on a direct NIC is no drift for an
// existing VM, and is left out of a new VM's create (which would refuse it);
// the plan says it is not enforced in both cases.
func TestResolve_AGuardOnADirectNICIsReportedNotPlanned(t *testing.T) {
	stored := `{"image":"ubuntu","cpu":1,"memory_mib":512,"guest_agent":true,"network":[{"name":"wan","mac":"52:54:00:00:00:01","spoof_guard":"on"}]}`
	state := makeState([]corrosion.HostRecord{makeHost("h1", 16, 32768)}, []corrosion.VMRecord{{
		Name: "web", StackName: "mystack", HostName: "h1", State: "running", Spec: stored, CPUActual: 1, MemActual: 512,
	}}, nil)
	state.Networks = []corrosion.NetworkRecord{{Name: "wan", Type: "direct"}}
	state.NICSecurity = map[string][]compose.LiveNIC{"web": {{Network: "wan", MAC: "52:54:00:00:00:01"}}} // no record
	def := compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512, Network: []compose.NetworkAttachment{{Name: "wan", SpoofGuard: "on"}}}
	f := makeFile("mystack", map[string]compose.VMDef{"web": def, "new": def})
	f.Networks = map[string]compose.NetworkDef{"wan": {External: true}}
	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatal(err)
	}
	w := strings.Join(plan.Warnings, "\n")
	for _, a := range plan.VMs {
		switch a.VMName {
		case "web":
			if a.Kind != OpNoChange {
				t.Errorf("web planned %v (%s), want no change", a.Kind, a.Detail)
			}
		case "new":
			if a.Kind != OpCreate || a.Spec.GetNetwork()[0].GetSpoofGuard() != "" {
				t.Errorf("new = %v with guard %q, want a create without the guard", a.Kind, a.Spec.GetNetwork()[0].GetSpoofGuard())
			}
		}
	}
	for _, vm := range []string{"web", "new"} {
		if !strings.Contains(w, vm+": nic 0 (wan) declares a guard that is not enforced") {
			t.Errorf("warnings %q lack the note for %s", w, vm)
		}
	}
}

// Round 4 nit: an existing network's record decides whether a guard can be
// enforced on it, as the executor decides; the file's type counts only for a
// network the deploy creates.
func TestGuardUnenforcedFrom_TheRecordWinsOverTheFile(t *testing.T) {
	f := &compose.File{Name: "st", Networks: map[string]compose.NetworkDef{
		"lan": {Type: "direct"}, "wan": {Type: "direct"}}}
	lan, wan := f.ResolveNetworkName("lan"), f.ResolveNetworkName("wan")
	state := &ClusterState{Networks: []corrosion.NetworkRecord{{Name: lan, Type: "bridge"}}}
	why := guardUnenforcedFrom(state, f)
	if why(lan) != "" {
		t.Errorf("a recorded bridge network judged by the file's type: %q", why(lan))
	}
	if why(wan) == "" {
		t.Error("a network the deploy creates as direct is judged a bridge")
	}
}
