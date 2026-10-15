package cloudinit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review R2-I1: a VM created before the spec recorded generated MACs has
// spec [A(n1, ip X), B(n2)]. A is hot-detached (its row goes) and C is
// attached on n1 (it takes ordinal 1, len([B]), and the n1 row). A rebuilt
// seed must not give C A's address: C's row is at another position than A's
// spec entry, so A is unresolved and the seed carries no network-config.
// Before the detach, the same spec resolves by position and gives A X.
//
// Mutation: match a MAC-less NIC to the one row on its network (the removed
// by-network fallback) — C is written with X; drop the position match — the
// control (no detach) loses X (with TestCreateVM_SeedIsRebuiltAlike this
// pins the position branch, R2-m1).
func TestSeedNetworkConfig_HotAttachedNICIsNotTheDetachedOne(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for name, def := range map[string]compose.NetworkDef{
		"n1": {Type: "bridge", Subnet: "10.1.0.0/24", DHCP: true},
		"n2": {Type: "bridge", Subnet: "10.2.0.0/24", DHCP: true},
	} {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	spec := &pb.VMSpec{Name: "old", Network: []*pb.NetworkAttachment{
		{Name: "n1", Ip: "10.1.0.50"}, {Name: "n2"}}}
	insert := func(vm string, rows []corrosion.InterfaceRecord) {
		t.Helper()
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm, HostName: "h", Spec: "{}", State: "running"}, rows, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Control: rows as created — A at ordinal 0 on n1, B at 1 on n2.
	insert("old", []corrosion.InterfaceRecord{
		{VMName: "old", NetworkName: "n1", Ordinal: 0, MAC: "52:54:00:00:0a:0a", IP: "10.1.0.50"},
		{VMName: "old", NetworkName: "n2", Ordinal: 1, MAC: "52:54:00:00:0b:0b"}})
	got, err := SeedNetworkConfig(ctx, db, "old", spec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "10.1.0.50/24") || !strings.Contains(got, "52:54:00:00:0a:0a") {
		t.Fatalf("control: A's spec entry not matched to its row by position:\n%s", got)
	}

	// After detach A, attach C on n1: C's row is (1, n1), B's is (1, n2).
	insert("old2", []corrosion.InterfaceRecord{
		{VMName: "old2", NetworkName: "n2", Ordinal: 1, MAC: "52:54:00:00:0b:0c"},
		{VMName: "old2", NetworkName: "n1", Ordinal: 1, MAC: "52:54:00:00:0c:0c"}})
	spec.Name = "old2"
	got, err = SeedNetworkConfig(ctx, db, "old2", spec)
	if err != nil {
		t.Fatal(err)
	}
	if got != "" {
		t.Errorf("the hot-attached NIC was matched to the detached NIC's entry; want no network-config, got:\n%s", got)
	}
}

// R3-m1: spec [B(n2), A(n1, ip X)], MAC-less; A is last. A is detached and C
// attached on n1, which takes ordinal 1 (len of what is left) and the (vm, n1)
// row: its position is A's. C's row records its own lease Y, or no address, and
// is not A's: the entry names an ip:, so the position match needs the row to
// record X. Without it C is written with A's address.
//
// Mutation: drop the address condition on the position match — the two
// detached cases write C with X; make it always fail — the control and the
// CIDR-form case (rows as created) lose X.
func TestSeedNetworkConfig_PositionMatchNeedsTheSpecIP(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	for name, def := range map[string]compose.NetworkDef{
		"n1": {Type: "bridge", Subnet: "10.1.0.0/24", DHCP: true},
		"n2": {Type: "bridge", Subnet: "10.2.0.0/24", DHCP: true},
	} {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	run := func(vm, specIP, rowIP string) string {
		t.Helper()
		rows := []corrosion.InterfaceRecord{
			{VMName: vm, NetworkName: "n2", Ordinal: 0, MAC: "52:54:00:00:0b:0b"},
			{VMName: vm, NetworkName: "n1", Ordinal: 1, MAC: "52:54:00:00:0c:0c", IP: rowIP}}
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm, HostName: "h", Spec: "{}", State: "running"}, rows, nil); err != nil {
			t.Fatal(err)
		}
		spec := &pb.VMSpec{Name: vm, Network: []*pb.NetworkAttachment{{Name: "n2"}, {Name: "n1", Ip: specIP}}}
		got, err := SeedNetworkConfig(ctx, db, vm, spec)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	// C's row: its own lease, or no address.
	for vm, rowIP := range map[string]string{"c-lease": "10.1.0.77", "c-none": ""} {
		if got := run(vm, "10.1.0.50", rowIP); got != "" {
			t.Errorf("%s: the attached NIC was given the detached NIC's entry; want no network-config, got:\n%s", vm, got)
		}
	}
	// Control: the row records X, as every create wrote it.
	if got := run("a-row", "10.1.0.50", "10.1.0.50"); !strings.Contains(got, "10.1.0.50/24") || !strings.Contains(got, "52:54:00:00:0c:0c") {
		t.Errorf("control: the entry did not resolve to the row that records its address:\n%s", got)
	}
	// A spec ip: written with a prefix is the same address.
	if got := run("a-cidr", "10.1.0.50/24", "10.1.0.50"); !strings.Contains(got, "52:54:00:00:0c:0c") {
		t.Errorf("a spec ip: with a prefix length did not match its row:\n%s", got)
	}
}
