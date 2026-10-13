package planner

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// The compose planner built its placement request from a device's Type, Count,
// Vendor, Sriov and Parent only, dropping Address, Mapping and Model. An
// address-only or mapping-only device then reached placement as a request with
// no selector at all, which every host rejects, so such a stack could never be
// placed (lab 1, 2026-10-13: `no eligible host for VM "hwv": node-5: devices`
// with the device free). A Model filter was silently ignored.

func TestBuildPlacementRequest_CarriesEverySelectorField(t *testing.T) {
	tests := []struct {
		name string
		dev  *pb.DeviceSpec
		want placement.DeviceRequest
	}{
		{
			name: "address only",
			dev:  &pb.DeviceSpec{Address: "01:10.2", Count: 1},
			want: placement.DeviceRequest{Address: "0000:01:10.2", Count: 1},
		},
		{
			name: "mapping",
			dev:  &pb.DeviceSpec{Mapping: "accel", Count: 1},
			want: placement.DeviceRequest{Mapping: "accel", Count: 1},
		},
		{
			name: "type with model",
			dev:  &pb.DeviceSpec{Type: "gpu", Vendor: "10de", Model: "H100", Count: 2},
			want: placement.DeviceRequest{Type: "gpu", Vendor: "10de", Model: "H100", Count: 2},
		},
		{
			name: "sriov with model and parent",
			dev:  &pb.DeviceSpec{Type: "network", Sriov: true, Model: "ConnectX", Parent: "0000:01:00.0", Count: 1},
			want: placement.DeviceRequest{Type: "network", Sriov: true, Model: "ConnectX", Parent: "0000:01:00.0", Count: 1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := buildPlacementRequest(&pb.VMSpec{Name: "vm", Devices: []*pb.DeviceSpec{tt.dev}}, corrosion.CapacityPolicy{})
			if len(req.Devices) != 1 || req.Devices[0] != tt.want {
				t.Fatalf("Devices = %+v, want [%+v]", req.Devices, tt.want)
			}
		})
	}
}

func deviceHosts() []corrosion.HostRecord {
	// h1 is the roomier host, so anything that does not pin the VM to h2
	// through its device lands on h1.
	return []corrosion.HostRecord{makeHost("h1", 64, 262144), makeHost("h2", 8, 16384)}
}

func TestResolve_AddressOnlyDeviceIsPlacedWhereTheDeviceIs(t *testing.T) {
	f := makeFile("pclhw", map[string]compose.VMDef{
		"hwv": {Image: "ubuntu", CPU: 1, Memory: 512, Devices: []compose.DeviceDef{{Address: "0000:01:10.2"}}},
	})
	state := makeState(deviceHosts(), nil, nil)
	state.Devices["h1"] = []corrosion.PCIDeviceRecord{{HostName: "h1", Address: "0000:02:00.0", Type: "network", IOMMUGroup: 3}}
	state.Devices["h2"] = []corrosion.PCIDeviceRecord{{HostName: "h2", Address: "0000:01:10.2", Type: "network", IOMMUGroup: 14}}

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	vm := findAction(t, plan, "hwv")
	if vm.TargetHost != "h2" {
		t.Fatalf("hwv placed on %q, want h2 (the only host with 0000:01:10.2)", vm.TargetHost)
	}
	if len(vm.Devices) != 1 || vm.Devices[0].Address != "0000:01:10.2" {
		t.Fatalf("hwv device assignments = %+v, want exactly 0000:01:10.2", vm.Devices)
	}
}

func TestResolve_AddressOnlyDeviceHeldElsewhereIsNotPlaceable(t *testing.T) {
	f := makeFile("pclhw", map[string]compose.VMDef{
		"hwv": {Image: "ubuntu", CPU: 1, Memory: 512, Devices: []compose.DeviceDef{{Address: "0000:01:10.2"}}},
	})
	state := makeState(deviceHosts(), nil, nil)
	_, err := Resolve(context.Background(), f, state)
	if err == nil || !strings.Contains(err.Error(), "no eligible host") {
		t.Fatalf("Resolve err = %v, want no eligible host (no host has the device free)", err)
	}
}

// Two VMs of one batch naming the same address: the first takes it, so the
// second must not be planned onto it as well.
func TestResolve_AddressOnlyDeviceIsReservedWithinTheBatch(t *testing.T) {
	dev := []compose.DeviceDef{{Address: "0000:01:10.2"}}
	f := makeFile("pclhw", map[string]compose.VMDef{
		"a": {Image: "ubuntu", CPU: 1, Memory: 512, Devices: dev},
		"b": {Image: "ubuntu", CPU: 1, Memory: 512, Devices: dev},
	})
	state := makeState(deviceHosts(), nil, nil)
	state.Devices["h2"] = []corrosion.PCIDeviceRecord{{HostName: "h2", Address: "0000:01:10.2", Type: "network", IOMMUGroup: 14}}
	_, err := Resolve(context.Background(), f, state)
	if err == nil || !strings.Contains(err.Error(), "no eligible host") {
		t.Fatalf("Resolve err = %v, want no eligible host for the second claimant", err)
	}
}

func TestResolve_MappingDeviceIsPlacedOnAMappedHost(t *testing.T) {
	f := makeFile("pclhw", map[string]compose.VMDef{
		"hwv": {Image: "ubuntu", CPU: 1, Memory: 512, Devices: []compose.DeviceDef{{Mapping: "accel"}}},
	})
	state := makeState(deviceHosts(), nil, nil)
	state.Devices["h1"] = []corrosion.PCIDeviceRecord{{HostName: "h1", Address: "0000:41:00.0", Type: "gpu", IOMMUGroup: 3}}
	state.Devices["h2"] = []corrosion.PCIDeviceRecord{{HostName: "h2", Address: "0000:42:00.0", Type: "gpu", IOMMUGroup: 4}}
	state.Mappings = map[string]map[string][]string{"accel": {"h2": {"0000:42:00.0"}}}

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	vm := findAction(t, plan, "hwv")
	if vm.TargetHost != "h2" {
		t.Fatalf("hwv placed on %q, want h2 (the only host under mapping accel)", vm.TargetHost)
	}
	if len(vm.Devices) != 1 || vm.Devices[0].Address != "0000:42:00.0" {
		t.Fatalf("hwv device assignments = %+v, want exactly 0000:42:00.0", vm.Devices)
	}
}

func TestResolve_DeviceModelFilterIsApplied(t *testing.T) {
	f := makeFile("gpus", map[string]compose.VMDef{
		"ml": {Image: "ubuntu", CPU: 1, Memory: 512, Devices: []compose.DeviceDef{{Type: "gpu", Model: "H100"}}},
	})
	state := makeState(deviceHosts(), nil, nil)
	state.Devices["h1"] = []corrosion.PCIDeviceRecord{{HostName: "h1", Address: "0000:41:00.0", Type: "gpu", DeviceName: "A100", IOMMUGroup: 3}}
	state.Devices["h2"] = []corrosion.PCIDeviceRecord{{HostName: "h2", Address: "0000:42:00.0", Type: "gpu", DeviceName: "H100", IOMMUGroup: 4}}

	plan, err := Resolve(context.Background(), f, state)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if vm := findAction(t, plan, "ml"); vm.TargetHost != "h2" {
		t.Fatalf("ml placed on %q, want h2 (the only H100)", vm.TargetHost)
	}
}

// LoadClusterState carries every resource mapping, per host in address order,
// so a mapping device is placed where ResolveMappingAddress will resolve it.
func TestLoadClusterState_LoadsResourceMappings(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	if err := corrosion.CreateResourceMapping(ctx, db, "accel", ""); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	for _, d := range []struct{ host, addr string }{
		{"h2", "0000:42:00.1"}, {"h2", "0000:42:00.0"}, {"h1", "0000:41:00.0"},
	} {
		if err := corrosion.AddMappingDevice(ctx, db, "accel", d.host, d.addr, "", ""); err != nil {
			t.Fatalf("AddMappingDevice: %v", err)
		}
	}
	state, err := LoadClusterState(ctx, db, corrosion.CapacityPolicy{})
	if err != nil {
		t.Fatalf("LoadClusterState: %v", err)
	}
	got := state.Mappings["accel"]
	if len(got["h2"]) != 2 || got["h2"][0] != "0000:42:00.0" || got["h2"][1] != "0000:42:00.1" ||
		len(got["h1"]) != 1 || got["h1"][0] != "0000:41:00.0" {
		t.Fatalf("Mappings[accel] = %v, want h1:[0000:41:00.0] h2:[0000:42:00.0 0000:42:00.1]", got)
	}
}

func findAction(t *testing.T, plan *ResolvedPlan, name string) VMAction {
	t.Helper()
	for _, vm := range plan.VMs {
		if vm.VMName == name {
			return vm
		}
	}
	t.Fatalf("no action for %s in plan", name)
	return VMAction{}
}
