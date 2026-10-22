package grpcapi

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

// A type intent is realized again by the device that realizes it on this host
// only while the VM still owns that device. A realized device the VM no
// longer owns (another VM's now) or a realization on another host is not
// reused; the intent then takes a free device.
func TestResolveDeviceIntents_TypeReusesOnlyAnOwnedRealization(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	defer vfio.SetFS(newPCIBindFakeFS())()

	for _, d := range []struct{ addr, owner string }{
		{"0000:81:00.0", "other"}, // realized for vm-t, owned by another VM since
		{"0000:82:00.0", ""},      // free
	} {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: "test-host", Address: d.addr, Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: d.owner,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []corrosion.PCIRealizationRecord{
		{VMName: "vm-t", DeviceID: "dev0", MemberID: "m0", HostName: "test-host", ResolvedAddress: "0000:81:00.0"},
		{VMName: "vm-t", DeviceID: "dev0", MemberID: "m1", HostName: "elsewhere", ResolvedAddress: "0000:82:00.0", Ordinal: 1},
	} {
		if err := corrosion.UpsertPCIRealization(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := protojson.Marshal(&pb.DeviceSpec{Type: "gpu", Vendor: "10de"})
	if err != nil {
		t.Fatal(err)
	}
	intent := corrosion.PCIIntentRecord{VMName: "vm-t", DeviceID: "dev0", HostName: "test-host", SelectorKind: "type", SelectorPayload: string(payload)}

	members, err := s.resolveDeviceIntents(ctx, "vm-t", []corrosion.PCIIntentRecord{intent})
	if err != nil || len(members) != 1 || members[0].Address != "0000:82:00.0" {
		t.Fatalf("members = %+v (%v); want the free 0000:82:00.0, not another VM's 0000:81:00.0", members, err)
	}

	// Owned by vm-t again: the realization is reused and the free device is not taken.
	if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: "0000:81:00.0", Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: "vm-t",
	}); err != nil {
		t.Fatal(err)
	}
	members, err = s.resolveDeviceIntents(ctx, "vm-t", []corrosion.PCIIntentRecord{intent})
	if err != nil || len(members) != 1 || members[0].Address != "0000:81:00.0" {
		t.Fatalf("members = %+v (%v); want its own 0000:81:00.0", members, err)
	}
}
