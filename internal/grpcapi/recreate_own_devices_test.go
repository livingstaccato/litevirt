package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A re-create of a GPU VM on a host whose only GPU it holds is placed onto
// that GPU: the teardown releases it before the create re-takes it. Counted
// as taken, placeRecreate (an ISO or LUN VM) and the pre-delete device check
// refused every such re-create.
//
// Mutations: placeRecreate without ReuseDevicesOf — the first two legs go
// red; the check on a spec naming a GPU another VM holds — the third.
func TestRecreate_AGPUVMIsPlacedOntoItsOwnGPU(t *testing.T) {
	s, _, _ := isoServer(t)
	ctx := context.Background()
	const gpu = "0000:41:00.0"
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "ml", HostName: s.hostName, State: "running", CPUActual: 1, MemActual: 512,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, d := range []corrosion.PCIDeviceRecord{
		{HostName: s.hostName, Address: gpu, Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: "ml"},
		{HostName: s.hostName, Address: "0000:42:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: "other"},
	} {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, d); err != nil {
			t.Fatal(err)
		}
	}
	cur := vmRecord(t, s, "ml")
	spec := &pb.VMSpec{Name: "ml", Cpu: 1, MemoryMib: 512, Iso: "/srv/x.iso",
		Devices: []*pb.DeviceSpec{{Type: "gpu", Count: 1}}}

	if host, err := s.placeRecreate(ctx, spec, cur); err != nil || host != s.hostName {
		t.Fatalf("placeRecreate of a VM holding the host's only free-able GPU: %q, %v; want %s", host, err, s.hostName)
	}
	spec.Placement = &pb.PlacementSpec{Host: s.hostName}
	if err := s.preflightRecreateDevices(ctx, spec, cur); err != nil {
		t.Fatalf("pre-delete device check, own GPU: %v", err)
	}
	spec.Devices = []*pb.DeviceSpec{{Address: "0000:42:00.0"}}
	if err := s.preflightRecreateDevices(ctx, spec, cur); err == nil || !strings.Contains(err.Error(), "devices") {
		t.Fatalf("pre-delete device check, another VM's GPU: %v, want a devices refusal", err)
	}
}
