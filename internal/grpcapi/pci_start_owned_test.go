package grpcapi

import (
	"strings"
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

// A VM's concrete addresses recorded on another host (a failover) find no
// free device of their kind here: the refusal says what holds each device of
// the kind here, another VM or another of the VM's own devices, rather than
// that there is none.
func TestResolveDeviceIntents_MovedAddressRefusalNamesWhatHoldsTheDevice(t *testing.T) {
	ctx := adminCtx()
	defer vfio.SetFS(newPCIBindFakeFS())()
	put := func(t *testing.T, s *Server, host, addr, device, typ, owner string, group int) {
		t.Helper()
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{HostName: host, Address: addr,
			VendorID: "10de", DeviceID: device, Type: typ, IOMMUGroup: group, VMName: owner}); err != nil {
			t.Fatal(err)
		}
	}
	intent := func(addr string) corrosion.PCIIntentRecord {
		key := addr
		return corrosion.PCIIntentRecord{VMName: "vm-m", DeviceID: "dev-" + addr, HostName: "origin",
			SelectorKind: "address", ExclusiveKey: &key}
	}

	t.Run("another VM", func(t *testing.T) {
		s := testServerR2(t)
		put(t, s, "origin", "0000:41:00.0", "2330", "gpu", "vm-m", 40)
		put(t, s, "origin", "0000:41:00.1", "22a3", "audio", "vm-m", 40)
		put(t, s, "test-host", "0000:81:00.0", "2330", "gpu", "", 60)
		put(t, s, "test-host", "0000:81:00.1", "22a3", "audio", "other", 61)
		_, err := s.resolveDeviceIntents(ctx, "vm-m", []corrosion.PCIIntentRecord{intent("0000:41:00.0"), intent("0000:41:00.1")})
		if err == nil || !strings.Contains(err.Error(), "0000:81:00.1 is owned by VM other") {
			t.Fatalf("err = %v; want it to name 0000:81:00.1 as owned by VM other", err)
		}
	})
	t.Run("its own other device", func(t *testing.T) {
		s := testServerR2(t)
		put(t, s, "origin", "0000:41:00.1", "22a3", "audio", "vm-m", 40)
		put(t, s, "origin", "0000:42:00.1", "22a3", "audio", "vm-m", 41)
		put(t, s, "test-host", "0000:81:00.1", "22a3", "audio", "", 60)
		_, err := s.resolveDeviceIntents(ctx, "vm-m", []corrosion.PCIIntentRecord{intent("0000:41:00.1"), intent("0000:42:00.1")})
		if err == nil || !strings.Contains(err.Error(), "0000:81:00.1 is taken by another of vm-m's devices") {
			t.Fatalf("err = %v; want it to name 0000:81:00.1 as taken by another of vm-m's devices", err)
		}
	})
}

// A create naming a GPU and its audio function by address, one IOMMU group,
// passes each through once, each claimed by the VM.
func TestAllocateDevices_GroupFunctionsEachNamedTakenOnce(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	defer vfio.SetFS(newPCIBindFakeFS())()
	for _, a := range []string{"0000:41:00.0", "0000:41:00.1"} {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: "test-host", Address: a, Type: "gpu", VendorID: "10de", IOMMUGroup: 20}); err != nil {
			t.Fatal(err)
		}
	}
	addrs, finish, err := s.allocateDevices(ctx, "vm-pair", []*pb.DeviceSpec{{Address: "0000:41:00.0"}, {Address: "0000:41:00.1"}}, deviceLeaseStageBound)
	if err != nil {
		t.Fatalf("allocateDevices: %v", err)
	}
	defer finish()
	if len(addrs) != 2 || addrs[0] != "0000:41:00.0" || addrs[1] != "0000:41:00.1" {
		t.Fatalf("addresses = %v; want [0000:41:00.0 0000:41:00.1], each once", addrs)
	}
}
