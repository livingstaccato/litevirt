package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/placement"
)

// Drain chose a target from a request that kept a device's type, count and
// vendor only. A mapping, an exact address, a model, SR-IOV and its parent
// were dropped, so a drain could pick a host the VM's device is not on (a
// type+mapping GPU VM went to any host with a free GPU) or refuse one it is
// on (a mapping-only or address-only VM had no eligible host at all).

func drainVM(t *testing.T, devs ...*pb.DeviceSpec) corrosion.VMRecord {
	t.Helper()
	b, err := json.Marshal(&pb.VMSpec{Name: "vm1", Devices: devs})
	if err != nil {
		t.Fatal(err)
	}
	return corrosion.VMRecord{Name: "vm1", HostName: "draining-host", CPUActual: 1, MemActual: 512, Spec: string(b)}
}

func TestBuildDrainPlacementRequest_CarriesEveryDeviceSelector(t *testing.T) {
	devs := []*pb.DeviceSpec{
		{Type: "gpu", Mapping: "accel", Count: 1},
		{Address: "41:00.0", Count: 1},
		{Type: "gpu", Vendor: "10de", Model: "H100", Count: 2},
		{Type: "network", Sriov: true, Model: "ConnectX", Parent: "0000:01:00.0", Count: 1},
	}
	req := buildDrainPlacementRequest(drainVM(t, devs...), "draining-host", corrosion.CapacityPolicy{})
	if len(req.Devices) != len(devs) {
		t.Fatalf("Devices = %+v, want %d", req.Devices, len(devs))
	}
	for i, d := range devs {
		if want := placement.DeviceRequestFor(d); req.Devices[i] != want {
			t.Errorf("Devices[%d] = %+v, want %+v", i, req.Devices[i], want)
		}
	}
}

// End to end through placement.Select: a type+mapping GPU VM drains onto the
// host its mapping names, although the other host is roomier and has a free GPU.
func TestDrainTarget_TypeAndMappingDeviceGoesToTheMappedHost(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, h := range []corrosion.HostRecord{
		{Name: "roomy", Address: "10.0.0.1", State: "active", CPUTotal: 128, MemTotal: 524288},
		{Name: "mapped", Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 16384},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost: %v", err)
		}
		if err := corrosion.UpsertPCIDevice(ctx, db, corrosion.PCIDeviceRecord{
			HostName: h.Name, Address: "0000:41:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
		}); err != nil {
			t.Fatalf("UpsertPCIDevice: %v", err)
		}
	}
	if err := corrosion.CreateResourceMapping(ctx, db, "accel", ""); err != nil {
		t.Fatalf("CreateResourceMapping: %v", err)
	}
	if err := corrosion.AddMappingDevice(ctx, db, "accel", "mapped", "0000:41:00.0", "", ""); err != nil {
		t.Fatalf("AddMappingDevice: %v", err)
	}

	req := buildDrainPlacementRequest(drainVM(t, &pb.DeviceSpec{Type: "gpu", Mapping: "accel", Count: 1}),
		"draining-host", corrosion.CapacityPolicy{})
	host, err := placement.Select(ctx, db, req)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if host != "mapped" {
		t.Fatalf("drain target = %q, want mapped (the only host under mapping accel)", host)
	}
}
