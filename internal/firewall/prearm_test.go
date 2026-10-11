package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/nictap"
)

// TestCorrosionPlanLoader_PreArmsGuardedNICs (re-review I-10): a guarded NIC
// is rendered under the tap name its MAC fixes even while its domain is not
// running, so its guard is in force from the first frame of a start; a NIC
// with no record (one that predates guards) is rendered only once running, as
// before. An armed VM — one about to start or migrate in here, whose row may
// still name another host — and a NIC whose rows are not written yet
// (Arming.SetPending) are rendered too.
func TestCorrosionPlanLoader_PreArmsGuardedNICs(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	vm := func(name, host, mac, ip string, guard bool) {
		t.Helper()
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: name, HostName: host, State: "stopped"},
			[]corrosion.InterfaceRecord{{VMName: name, NetworkName: "lan", MAC: mac, IP: ip}}, nil); err != nil {
			t.Fatal(err)
		}
		if guard {
			if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: name, MAC: mac, Mode: corrosion.NICGuardOn}, "t"); err != nil {
				t.Fatal(err)
			}
		}
	}
	vm("guarded", "host-a", "52:54:00:00:00:01", "10.0.0.1", true)
	vm("legacy", "host-a", "52:54:00:00:00:02", "10.0.0.2", false)
	vm("incoming", "host-b", "52:54:00:00:00:03", "10.0.0.3", true)
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "creating", MAC: "52:54:00:00:00:04", Mode: corrosion.NICGuardOn}, "t"); err != nil {
		t.Fatal(err)
	}
	arm := NewArming()
	arm.Arm("incoming")
	arm.SetPending("creating", []corrosion.HostVMNIC{{VMName: "creating", NetworkName: "lan", MAC: "52:54:00:00:00:04", IP: "10.0.0.4"}})
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) { return map[string]map[string]string{}, nil },
		TapBridge:   func(string) string { return "" },
		Arming:      arm,
	})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]*NICGuard{}
	for _, n := range plan.NICs {
		got[n.NICDev] = n.Guard
	}
	for _, c := range []struct{ name, mac string }{
		{"a stopped guarded VM", "52:54:00:00:00:01"},
		{"an armed incoming VM", "52:54:00:00:00:03"},
		{"a VM whose rows are not written yet", "52:54:00:00:00:04"},
	} {
		if g, ok := got[nictap.Name(c.mac)]; !ok || g == nil {
			t.Errorf("%s: no guard rendered under %s: %v", c.name, nictap.Name(c.mac), got)
		}
	}
	if _, ok := got[nictap.Name("52:54:00:00:00:02")]; ok {
		t.Errorf("a stopped VM with no guard record was rendered: %v", got)
	}
	arm.ClearPending("creating")
	arm.Disarm("incoming")
	plan, _ = CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		RunningTaps: func() (map[string]map[string]string, error) { return map[string]map[string]string{}, nil },
		TapBridge:   func(string) string { return "" }, Arming: arm,
	})(ctx)
	for _, n := range plan.NICs {
		if n.NICDev == nictap.Name("52:54:00:00:00:03") || n.NICDev == nictap.Name("52:54:00:00:00:04") {
			t.Errorf("%s still rendered once disarmed / written", n.NICDev)
		}
	}
}

// TestReconciler_ArmReportsAFailedApply: Arm puts the VM's NICs in force by a
// reconcile pass, and reports a pass that did not — a refused per-NIC table
// included — so the caller can refuse to start a guarded VM unguarded.
func TestReconciler_ArmReportsAFailedApply(t *testing.T) {
	f := &fakeNft{failNext: errors.New("nft: refused")}
	arm := NewArming()
	loaded := ""
	loader := func(context.Context) (Plan, error) {
		loaded = strings.Join(arm.Armed(), ",")
		return Plan{NICs: []NICBinding{{NICDev: "lvt525400000001", VMName: "web", Guard: &NICGuard{MAC: "52:54:00:00:00:01"}}}}, nil
	}
	r := NewReconciler(loader, NewApplier(f), 0)
	r.SetArming(arm)
	if err := r.Arm(context.Background(), "web"); err == nil {
		t.Fatal("Arm reported success for a pass nft refused")
	}
	if loaded != "web" {
		t.Errorf("the pass did not see the VM armed: %q", loaded)
	}
	if err := r.Arm(context.Background(), "web"); err != nil {
		t.Errorf("Arm after nft recovered: %v", err)
	}
}
