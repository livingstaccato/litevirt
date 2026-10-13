package scheduler

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// The rebalancer built a device request from type, count and vendor only, so
// a destination was ranked without the device's mapping, exact address,
// model, SR-IOV flag or parent. It now makes CreateVM's conversion, keeping
// its own default of one device for an unset count.
func TestBuildPlacementRequest_CarriesEveryDeviceSelector(t *testing.T) {
	vm := corrosion.VMRecord{Name: "vm1", HostName: "h1", CPUActual: 1, MemActual: 1024}
	devs := []*pb.DeviceSpec{
		{Type: "gpu", Mapping: "accel", Count: 1},
		{Address: "41:00.0"},
		{Type: "gpu", Vendor: "10de", Model: "H100", Count: 2},
		{Type: "network", Sriov: true, Model: "ConnectX", Parent: "0000:01:00.0", Count: 1},
	}
	req := buildPlacementRequest(vm, &pb.VMSpec{Devices: devs}, vmPolicy{}, corrosion.CapacityPolicy{})
	if len(req.Devices) != len(devs) {
		t.Fatalf("Devices = %+v, want %d", req.Devices, len(devs))
	}
	for i, d := range devs {
		want := placement.DeviceRequestFor(d)
		if want.Count <= 0 {
			want.Count = 1
		}
		if req.Devices[i] != want {
			t.Errorf("Devices[%d] = %+v, want %+v", i, req.Devices[i], want)
		}
	}
}
