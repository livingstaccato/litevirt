package corrosion

import (
	"context"
	"testing"
)

// TestListHostVMNICs_GroupsPreferVMNICs pins the source of each NIC's groups
// and which NICs appear:
//   - a NIC with a live vm_nics row takes its groups from it, even when the
//     legacy row is newer and group-less (the pre-latch hot-attach order);
//   - a NIC with only a legacy row takes the legacy groups;
//   - a NIC with only a vm_nics row (post-latch hot-attach) is listed;
//   - a tombstoned NIC and another host's VM are not.
func TestListHostVMNICs_GroupsPreferVMNICs(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "vm-a", HostName: "host-a", State: "running"},
		[]InterfaceRecord{{VMName: "vm-a", NetworkName: "legacy-only", Ordinal: 0, MAC: "52:54:00:00:00:01",
			SecurityGroups: []string{"from-legacy"}}}, nil); err != nil {
		t.Fatalf("InsertVM vm-a: %v", err)
	}
	if err := InsertVM(ctx, c, VMRecord{Name: "vm-b", HostName: "host-b", State: "running"},
		[]InterfaceRecord{{VMName: "vm-b", NetworkName: "elsewhere", MAC: "52:54:00:00:00:09",
			SecurityGroups: []string{"x"}}}, nil); err != nil {
		t.Fatalf("InsertVM vm-b: %v", err)
	}

	// Pre-latch hot-attach: vm_nics first with the groups, then a newer
	// group-less legacy row for the same MAC.
	hot := NICRecord{VMName: "vm-a", ID: DeterministicNICID("vm-a", "52:54:00:00:00:02"),
		NetworkName: "hot", MAC: "52:54:00:00:00:02", Ordinal: 1, SecurityGroups: `["from-nics"]`}
	if err := UpsertNIC(ctx, c, hot); err != nil {
		t.Fatalf("UpsertNIC hot: %v", err)
	}
	if err := InsertInterface(ctx, c, InterfaceRecord{VMName: "vm-a", NetworkName: "hot", Ordinal: 1,
		MAC: "52:54:00:00:00:02"}); err != nil {
		t.Fatalf("InsertInterface hot: %v", err)
	}
	// Post-latch hot-attach: vm_nics only.
	if err := UpsertNIC(ctx, c, NICRecord{VMName: "vm-a", ID: DeterministicNICID("vm-a", "52:54:00:00:00:03"),
		NetworkName: "v2", MAC: "52:54:00:00:00:03", Ordinal: 2, SecurityGroups: `["v2-only"]`}); err != nil {
		t.Fatalf("UpsertNIC v2: %v", err)
	}
	// A detached NIC: written, then tombstoned.
	gone := NICRecord{VMName: "vm-a", ID: DeterministicNICID("vm-a", "52:54:00:00:00:04"),
		NetworkName: "gone", MAC: "52:54:00:00:00:04", Ordinal: 3, SecurityGroups: `["gone"]`}
	if err := UpsertNIC(ctx, c, gone); err != nil {
		t.Fatalf("UpsertNIC gone: %v", err)
	}
	if err := TombstoneNIC(ctx, c, "vm-a", gone.ID); err != nil {
		t.Fatalf("TombstoneNIC: %v", err)
	}

	got, err := ListHostVMNICs(ctx, c, "host-a")
	if err != nil {
		t.Fatalf("ListHostVMNICs: %v", err)
	}
	want := map[string]string{
		"52:54:00:00:00:01": "from-legacy",
		"52:54:00:00:00:02": "from-nics",
		"52:54:00:00:00:03": "v2-only",
	}
	if len(got) != len(want) {
		t.Fatalf("want NICs %v, got %+v", want, got)
	}
	for _, n := range got {
		w, ok := want[n.MAC]
		if !ok {
			t.Errorf("unexpected NIC %+v", n)
			continue
		}
		if len(n.SecurityGroups) != 1 || n.SecurityGroups[0] != w {
			t.Errorf("NIC %s: groups %v, want [%s]", n.MAC, n.SecurityGroups, w)
		}
		if n.VMName != "vm-a" || n.VMState != "running" {
			t.Errorf("NIC %s: owner %q state %q, want vm-a running", n.MAC, n.VMName, n.VMState)
		}
	}
}
