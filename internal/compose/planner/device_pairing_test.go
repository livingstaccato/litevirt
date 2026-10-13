package planner

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// pairingState is h2 with three NVIDIA GPUs and one VF; h1 has nothing.
func pairingState() *ClusterState {
	state := makeState(deviceHosts(), nil, nil)
	for _, a := range []string{"0000:41:00.0", "0000:42:00.0", "0000:43:00.0"} {
		state.Devices["h2"] = append(state.Devices["h2"],
			corrosion.PCIDeviceRecord{HostName: "h2", Address: a, Type: "gpu", VendorID: "10de", IOMMUGroup: -1})
	}
	state.Devices["h2"] = append(state.Devices["h2"],
		corrosion.PCIDeviceRecord{HostName: "h2", Address: "0000:81:00.1", Type: "network", VendorID: "8086", IOMMUGroup: -1})
	return state
}

func pinnedSpec(t *testing.T, devs []compose.DeviceDef) (VMAction, []string) {
	t.Helper()
	f := makeFile("pair", map[string]compose.VMDef{"vm": {Image: "ubuntu", CPU: 1, Memory: 512, Devices: devs}})
	plan, err := Resolve(context.Background(), f, pairingState())
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	a := findAction(t, plan, "vm")
	PinAssignedDevices(a.Spec, a.Devices)
	var got []string
	for _, d := range a.Spec.Devices {
		got = append(got, d.Address)
	}
	return a, got
}

// The review's case: a `count: 2` GPU entry, then an address-only VF. Paired
// by position, the VF entry got the second GPU's address and, being an
// address-kind entry, would have been bound to that GPU exactly.
func TestPinAssignedDevices_ACountedEntryDoesNotShiftTheNext(t *testing.T) {
	a, got := pinnedSpec(t, []compose.DeviceDef{{Type: "gpu", Count: 2}, {Address: "0000:81:00.1"}})
	if len(a.Devices) != 3 {
		t.Fatalf("assignments = %+v, want 2 GPUs and the VF", a.Devices)
	}
	if got[1] != "0000:81:00.1" {
		t.Fatalf("addresses after pinning = %v, want the VF entry to keep 0000:81:00.1", got)
	}
	if !strings.HasPrefix(got[0], "0000:4") {
		t.Fatalf("addresses after pinning = %v, want a GPU recorded on the GPU entry", got)
	}
}

// Vendor-only, counted type and address-only entries together: each entry is
// paired with its own assignments, the vendor-only one included (it used to
// get none, which shifted the pairing the other way), and no device is
// assigned twice.
func TestPinAssignedDevices_MixedEntriesPairWithTheirOwnAssignments(t *testing.T) {
	a, got := pinnedSpec(t, []compose.DeviceDef{
		{Vendor: "10de"}, {Type: "gpu", Count: 2}, {Address: "0000:81:00.1"},
	})
	perEntry := map[int][]string{}
	seen := map[string]bool{}
	for _, d := range a.Devices {
		perEntry[d.Index] = append(perEntry[d.Index], d.Address)
		if seen[d.Address] {
			t.Fatalf("%s assigned twice: %+v", d.Address, a.Devices)
		}
		seen[d.Address] = true
	}
	if len(perEntry[0]) != 1 || len(perEntry[1]) != 2 || len(perEntry[2]) != 1 || perEntry[2][0] != "0000:81:00.1" {
		t.Fatalf("assignments per entry = %v, want 1 GPU, 2 GPUs, the VF", perEntry)
	}
	if got[0] != perEntry[0][0] || got[1] != perEntry[1][0] || got[2] != "0000:81:00.1" {
		t.Fatalf("addresses after pinning = %v, want %v / %v / the VF", got, perEntry[0][0], perEntry[1][0])
	}
}

// An address or a mapping entry is never overwritten, whatever the
// assignments say; an SR-IOV entry is left unpinned for its VF allocator.
func TestPinAssignedDevices_LeavesAddressMappingAndSRIOVEntries(t *testing.T) {
	spec := &pb.VMSpec{Devices: []*pb.DeviceSpec{
		{Address: "0000:81:00.1"}, {Mapping: "accel"}, {Type: "network", Sriov: true}, {Type: "gpu"},
	}}
	PinAssignedDevices(spec, []DeviceAssignment{
		{Address: "0000:99:00.0", Index: 0}, {Address: "0000:98:00.0", Index: 1},
		{Address: "0000:97:00.0", Index: 2}, {Address: "0000:41:00.0", Index: 3},
	})
	want := []string{"0000:81:00.1", "", "", "0000:41:00.0"}
	for i, d := range spec.Devices {
		if d.Address != want[i] {
			t.Errorf("device %d address = %q, want %q", i, d.Address, want[i])
		}
	}
}
