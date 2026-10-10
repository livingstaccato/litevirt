package firewall

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func on(allowed ...string) *corrosion.NICGuardRecord {
	return &corrosion.NICGuardRecord{VMName: "vm", MAC: "52:54:00:aa:bb:cc", Mode: corrosion.NICGuardOn, Allowed: allowed}
}

// TestResolveNICGuard pins which addresses a guarded NIC may send from.
func TestResolveNICGuard(t *testing.T) {
	cases := []struct {
		name           string
		rec            *corrosion.NICGuardRecord
		ip, subnet     string
		wantNil        bool
		wantV4, wantV6 []string
	}{
		{name: "no record is unguarded", rec: nil, ip: "10.0.0.5", wantNil: true},
		{name: "off is unguarded", rec: &corrosion.NICGuardRecord{Mode: corrosion.NICGuardOff}, ip: "10.0.0.5", wantNil: true},
		{name: "assigned address only, prefix length dropped", rec: on(), ip: "10.0.0.5/24", subnet: "10.0.0.0/24",
			wantV4: []string{"10.0.0.5"}},
		{name: "dynamic DHCP falls back to the subnet", rec: on(), subnet: "10.1.0.0/24",
			wantV4: []string{"10.1.0.0/24"}},
		{name: "allowed VIP joins the assigned address", rec: on("10.0.0.250", "2001:db8::/64"), ip: "10.0.0.5",
			wantV4: []string{"10.0.0.5", "10.0.0.250"}, wantV6: []string{"2001:db8::/64"}},
		{name: "nothing known leaves both families open", rec: on()},
		{name: "IPv6 subnet restricts IPv6 only", rec: on(), subnet: "fd00:1::/64",
			wantV6: []string{"fd00:1::/64"}},
		{name: "known static IPv6 beats the subnet", rec: &corrosion.NICGuardRecord{Mode: corrosion.NICGuardOn, Known: []string{"fd00:1::5"}},
			subnet: "fd00:1::/64", wantV6: []string{"fd00:1::5"}},
		{name: "garbage skipped", rec: on("not-an-ip"), ip: "garbage"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := ResolveNICGuard(c.rec, "52:54:00:AA:BB:CC", c.ip, c.subnet)
			if c.wantNil {
				if g != nil {
					t.Fatalf("got %+v, want unguarded", g)
				}
				return
			}
			if g == nil {
				t.Fatal("got unguarded, want a guard")
			}
			if g.MAC != "52:54:00:aa:bb:cc" {
				t.Errorf("MAC = %q", g.MAC)
			}
			if !reflect.DeepEqual(g.V4, c.wantV4) || !reflect.DeepEqual(g.V6, c.wantV6) {
				t.Errorf("V4=%v V6=%v, want V4=%v V6=%v", g.V4, g.V6, c.wantV4, c.wantV6)
			}
		})
	}
}

// TestCorrosionPlanLoader_GuardsRecordedNICsOnly: a NIC with an "on" record is
// rendered guarded with the address its NIC row carries; a NIC with no record
// — every NIC that predates guards — renders exactly as before.
func TestCorrosionPlanLoader_GuardsRecordedNICsOnly(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "new", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "new", NetworkName: "prod", MAC: "52:54:00:00:00:01", IP: "10.0.0.10"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "old", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "old", NetworkName: "prod", MAC: "52:54:00:00:00:02", IP: "10.0.0.11"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, db, corrosion.NICGuardRecord{
		VMName: "new", MAC: "52:54:00:00:00:01", Mode: corrosion.NICGuardOn, Allowed: []string{"10.0.0.250"},
	}, "test"); err != nil {
		t.Fatalf("PutNICGuard: %v", err)
	}
	loader := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"new": {"52:54:00:00:00:01": "vnet1"},
		"old": {"52:54:00:00:00:02": "vnet2"},
	}))
	plan, err := loader(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	byDev := map[string]NICBinding{}
	for _, n := range plan.NICs {
		byDev[n.NICDev] = n
	}
	if g := byDev["vnet2"].Guard; g != nil {
		t.Errorf("a NIC with no record was guarded: %+v", g)
	}
	g := byDev["vnet1"].Guard
	if g == nil {
		t.Fatal("the recorded NIC was not guarded")
	}
	if !reflect.DeepEqual(g.V4, []string{"10.0.0.10", "10.0.0.250"}) {
		t.Errorf("V4 = %v", g.V4)
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(out, "iifname vnet1 jump guard_vnet1") || strings.Contains(out, "guard_vnet2") {
		t.Errorf("guard dispatch wrong:\n%s", out)
	}
}
