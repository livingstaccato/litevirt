package planner

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The in-place strategy never restarts or deletes a VM, so an update that
// needs either is refused when the plan is made — naming the real reason —
// rather than planned as "recreate — disks are replaced" or "restart — …" and
// then refused by the executor partway through the deploy.
func TestResolve_InPlaceRefusesWhatItCannotApply(t *testing.T) {
	inPlace := &compose.UpdateDef{Strategy: "in-place"}
	for _, c := range []struct {
		name string
		def  compose.VMDef
		spec string // stored
		want []string
	}{
		{"recreate-class change", compose.VMDef{Image: "debian", CPU: 1, Memory: 512, Update: inPlace},
			`{"image":"ubuntu","cpu":1,"memory_mib":512,"guest_agent":true}`,
			[]string{"web", "in-place", "image"}},
		{"stored spec unreadable", compose.VMDef{Image: "ubuntu", CPU: 2, Memory: 512, Update: inPlace},
			`{not json`,
			[]string{"web", "in-place", "stored spec could not be read"}},
		{"restart-class change", compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512, CPUMode: "host-passthrough", Update: inPlace},
			`{"image":"ubuntu","cpu":1,"memory_mib":512,"guest_agent":true,"cpu_mode":"host-model"}`,
			[]string{"web", "in-place", "cpu-mode"}},
	} {
		f := makeFile("mystack", map[string]compose.VMDef{"web": c.def})
		state := makeState([]corrosion.HostRecord{makeHost("h1", 16, 32768)}, []corrosion.VMRecord{{
			Name: "web", StackName: "mystack", HostName: "h1", State: "running", Spec: c.spec, CPUActual: 1, MemActual: 512,
		}}, nil)
		plan, err := Resolve(context.Background(), f, state)
		if err == nil {
			t.Errorf("%s: planned %+v; want the in-place strategy to refuse", c.name, plan.VMs)
			continue
		}
		for _, w := range c.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: error %q does not name %q", c.name, err, w)
			}
		}
	}
}

// A repair of a half-made VM is planned under in-place like under any other
// strategy, and a live change is planned in place.
func TestResolve_InPlacePlansARepairAndALiveChange(t *testing.T) {
	inPlace := &compose.UpdateDef{Strategy: "in-place"}
	stored := `{"image":"ubuntu","cpu":1,"memory_mib":512,"guest_agent":true}`
	for _, c := range []struct {
		name, state string
		def         compose.VMDef
		check       func(VMAction) bool
	}{
		{"repair", "error", compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512, Update: inPlace},
			func(a VMAction) bool { return a.Repair }},
		{"live", "running", compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512, Labels: map[string]string{"a": "b"}, Update: inPlace},
			func(a VMAction) bool { return a.Apply == compose.ActionLive }},
	} {
		f := makeFile("mystack", map[string]compose.VMDef{"web": c.def})
		state := makeState([]corrosion.HostRecord{makeHost("h1", 16, 32768)}, []corrosion.VMRecord{{
			Name: "web", StackName: "mystack", HostName: "h1", State: c.state, Spec: stored, CPUActual: 1, MemActual: 512,
		}}, nil)
		state.RecordedDisks = map[string]int{"web": 1}
		plan, err := Resolve(context.Background(), f, state)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(plan.VMs) != 1 || plan.VMs[0].Kind != OpUpdate || !c.check(plan.VMs[0]) {
			t.Errorf("%s: planned %+v", c.name, plan.VMs)
		}
	}
}

// F2 (lab 2): a changed migrate.on-host-failure on an existing VM is planned as
// an in-place "migrate" change — also for a VM whose stored migrate block
// already matches the file but whose top-level on_host_failure, the one the
// failover coordinator reads, does not (left so by an earlier in-place update
// that stored only the block).
func TestResolve_InPlacePlansAMigratePolicyChange(t *testing.T) {
	def := compose.VMDef{Image: "ubuntu", CPU: 1, Memory: 512,
		Migrate: &compose.MigrateDef{OnHostFailure: "restart-any"}, Update: &compose.UpdateDef{Strategy: "in-place"}}
	for _, c := range []struct{ name, stored string }{
		{"created with none", `{"image":"ubuntu","cpu":1,"memory_mib":512,"guest_agent":true,"on_host_failure":"none","migrate":{"on_host_failure":2}}`},
		{"block updated, policy not", `{"image":"ubuntu","cpu":1,"memory_mib":512,"guest_agent":true,"on_host_failure":"none","migrate":{}}`},
	} {
		f := makeFile("mystack", map[string]compose.VMDef{"web": def})
		state := makeState([]corrosion.HostRecord{makeHost("h1", 16, 32768)}, []corrosion.VMRecord{{
			Name: "web", StackName: "mystack", HostName: "h1", State: "running", Spec: c.stored, CPUActual: 1, MemActual: 512,
		}}, nil)
		state.RecordedDisks = map[string]int{"web": 1}
		plan, err := Resolve(context.Background(), f, state)
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if len(plan.VMs) != 1 || plan.VMs[0].Kind != OpUpdate || plan.VMs[0].Apply != compose.ActionLive {
			t.Errorf("%s: planned %+v, want a live update", c.name, plan.VMs)
			continue
		}
		found := false
		for _, d := range plan.VMs[0].Plan.MetadataChanges {
			found = found || d.Field == "migrate"
		}
		if !found || plan.VMs[0].Spec.GetOnHostFailure() != "restart-any" {
			t.Errorf("%s: plan %+v / desired on_host_failure %q, want a migrate change to restart-any",
				c.name, plan.VMs[0].Plan.MetadataChanges, plan.VMs[0].Spec.GetOnHostFailure())
		}
	}
}
