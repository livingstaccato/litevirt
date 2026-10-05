package firewall

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCorrosionPlanLoader_TapComesFromLibvirtNotTheRecord pins that a NIC's
// chain is bound to the tap libvirt reports NOW, never to the tap_device
// recorded at create.
//
// The shape is the one the lab showed after `lv stop; lv start`: vm-a was
// created on vnet0 and restarted onto vnet3, and vnet0 now belongs to vm-b,
// which has no groups. A loader that trusted the record would put vm-a's rules
// on vm-b's tap and leave vm-a's real tap unfiltered.
func TestCorrosionPlanLoader_TapComesFromLibvirtNotTheRecord(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: "sg-web", Name: "web"}); err != nil {
		t.Fatalf("InsertSecurityGroup: %v", err)
	}
	if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r1", SGID: "sg-web",
		Direction: "ingress", Proto: "tcp", PortRange: "22", Action: "accept"}); err != nil {
		t.Fatalf("InsertSGRule: %v", err)
	}
	for _, vm := range []struct {
		name, mac, recordedTap string
		sgs                    []string
	}{
		{"vm-a", "52:54:00:00:00:0a", "vnet0", []string{"web"}},
		{"vm-b", "52:54:00:00:00:0b", "vnet1", nil},
		{"vm-stopped", "52:54:00:00:00:0c", "vnet2", []string{"web"}},
	} {
		if err := corrosion.InsertVM(ctx, db,
			corrosion.VMRecord{Name: vm.name, HostName: "host-a", State: "running"},
			[]corrosion.InterfaceRecord{{
				VMName: vm.name, NetworkName: "prod", MAC: vm.mac,
				TapDevice: vm.recordedTap, SecurityGroups: vm.sgs,
			}}, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
	}

	// libvirt now: vm-a restarted onto vnet3, vm-b holds vnet0, vm-stopped is
	// not running and so has no tap at all.
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"vm-a": {"52:54:00:00:00:0a": "vnet3"},
		"vm-b": {"52:54:00:00:00:0b": "vnet0"},
	}))(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	byDev := map[string]NICBinding{}
	for _, n := range plan.NICs {
		byDev[n.NICDev] = n
	}
	if got := byDev["vnet3"]; got.VMName != "vm-a" || !equalStringSlice(got.SecurityGroups, []string{"web"}) {
		t.Errorf("vm-a's groups must bind to the tap libvirt reports (vnet3); got %+v (all: %+v)", got, plan.NICs)
	}
	if got := byDev["vnet0"]; got.VMName != "vm-b" || len(got.SecurityGroups) != 0 {
		t.Errorf("vnet0 is vm-b's now and must carry none of vm-a's groups; got %+v", got)
	}
	if _, ok := byDev["vnet2"]; ok {
		t.Errorf("a VM libvirt reports no tap for must get no chain; its recorded tap was rendered: %+v", plan.NICs)
	}
	if len(plan.NICs) != 2 {
		t.Errorf("want exactly the two running VMs' NICs, got %+v", plan.NICs)
	}

	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	mustContainAll(t, out, "oifname vnet3 tcp dport 22 accept")
	if strings.Contains(out, "oifname vnet0 tcp dport 22") {
		t.Error("vm-a's rule was rendered on vm-b's tap")
	}
}

// TestCorrosionPlanLoader_NoResolverRendersNoVMChains: without a resolver
// there is no trustworthy device name for any VM NIC, so none is rendered —
// the recorded tap is not a fallback.
func TestCorrosionPlanLoader_NoResolverRendersNoVMChains(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm-a", HostName: "host-a", State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "vm-a", NetworkName: "prod", MAC: "52:54:00:00:00:0a", TapDevice: "vnet0"}},
		nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if len(plan.NICs) != 0 {
		t.Errorf("no resolver must mean no VM NIC chains, got %+v", plan.NICs)
	}
}

// TestCorrosionPlanLoader_OneTapIsBoundOnce: if two NIC rows resolve to one
// device (a stale row for a MAC libvirt reused), the tap gets one chain. Two
// would be a duplicate nft chain, and nft refuses the whole ruleset for it —
// every NIC on the host would lose its filtering over one bad row.
func TestCorrosionPlanLoader_OneTapIsBoundOnce(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, vm := range []struct{ name, mac string }{
		{"vm-a", "52:54:00:00:00:0a"},
		{"vm-b", "52:54:00:00:00:0b"},
	} {
		if err := corrosion.InsertVM(ctx, db,
			corrosion.VMRecord{Name: vm.name, HostName: "host-a", State: "running"},
			[]corrosion.InterfaceRecord{{VMName: vm.name, NetworkName: "prod", MAC: vm.mac}},
			nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
	}
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, liveTaps(map[string]map[string]string{
		"vm-a": {"52:54:00:00:00:0a": "vnet7"},
		"vm-b": {"52:54:00:00:00:0b": "vnet7"},
	}))(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	if len(plan.NICs) != 1 {
		t.Fatalf("one device must be bound once, got %+v", plan.NICs)
	}
	if out, err := Render(plan); err != nil || strings.Count(out, "chain nic_vnet7 {") != 1 {
		t.Errorf("want exactly one nic_vnet7 chain (err %v):\n%s", err, out)
	}
}

// TestCorrosionPlanLoader_DuplicateNameFailsClosed: two live groups named
// "web". A VM NIC and a container NIC bound to "web" are held at drop and get
// neither group's rules; a NIC bound only to an unambiguous group is untouched;
// the duplicate is reported with the number of NICs it holds.
func TestCorrosionPlanLoader_DuplicateNameFailsClosed(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, g := range []struct{ id, name, port string }{
		{"web-1", "web", "80"},
		{"web-2", "web", "8080"},
		{"ssh-1", "ssh", "22"},
	} {
		if err := corrosion.InsertSecurityGroup(ctx, db, corrosion.SecurityGroup{ID: g.id, Name: g.name}); err != nil {
			t.Fatalf("InsertSecurityGroup %s: %v", g.id, err)
		}
		if err := corrosion.InsertSGRule(ctx, db, corrosion.SGRule{ID: "r-" + g.id, SGID: g.id,
			Direction: "ingress", Proto: "tcp", PortRange: g.port, Action: "accept"}); err != nil {
			t.Fatalf("InsertSGRule %s: %v", g.id, err)
		}
	}
	for _, vm := range []struct {
		name, mac string
		sgs       []string
	}{
		{"vm-web", "52:54:00:00:00:0a", []string{"ssh", "web"}},
		{"vm-ssh", "52:54:00:00:00:0b", []string{"ssh"}},
	} {
		if err := corrosion.InsertVM(ctx, db,
			corrosion.VMRecord{Name: vm.name, HostName: "host-a", State: "running"},
			[]corrosion.InterfaceRecord{{VMName: vm.name, NetworkName: "prod", MAC: vm.mac, SecurityGroups: vm.sgs}},
			nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
	}
	if err := corrosion.UpsertContainer(ctx, db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct-web", State: "running"}); err != nil {
		t.Fatalf("UpsertContainer: %v", err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, db, corrosion.ContainerInterfaceRecord{
		HostName: "host-a", CtName: "ct-web", NetworkName: "prod", MAC: "52:00:00:00:00:10",
		VethDevice: "lvc0web", SecurityGroups: []string{"web"}}); err != nil {
		t.Fatalf("UpsertContainerInterface: %v", err)
	}

	var reported map[string]int
	opts := liveTaps(map[string]map[string]string{"vm-web": {"52:54:00:00:00:0a": "vnet1"}, "vm-ssh": {"52:54:00:00:00:0b": "vnet2"}})
	opts.OnDuplicateSGs = func(m map[string]int) { reported = m }
	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, opts)(ctx)
	if err != nil {
		t.Fatalf("loader: %v", err)
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	chain := func(dev string) string {
		head := "chain nic_" + dev + " {\n"
		i := strings.Index(out, head)
		if i < 0 {
			t.Fatalf("no chain for %s:\n%s", dev, out)
		}
		body := out[i+len(head):]
		return body[:strings.Index(body, "\n    }")]
	}
	for _, dev := range []string{"vnet1", "lvc0web"} {
		c := chain(dev)
		for _, want := range []string{"oifname " + dev + " drop", "iifname " + dev + " drop"} {
			if !strings.Contains(c, want) {
				t.Errorf("%s is bound to the ambiguous web; want %q in its chain:\n%s", dev, want, c)
			}
		}
		for _, leaked := range []string{"dport 80 ", "dport 8080 ", "dport 22 "} {
			if strings.Contains(c, leaked) {
				t.Errorf("%s failed closed must render no group's rules; found %q:\n%s", dev, leaked, c)
			}
		}
	}
	if c := chain("vnet2"); !strings.Contains(c, "oifname vnet2 tcp dport 22 accept") || strings.Contains(c, " drop") {
		t.Errorf("vnet2 binds only the unambiguous ssh and must be unaffected:\n%s", c)
	}
	if len(reported) != 1 || reported["web"] != 2 {
		t.Errorf("OnDuplicateSGs = %v, want web=2 (one VM NIC, one container NIC)", reported)
	}
}
