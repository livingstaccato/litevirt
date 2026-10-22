package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

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

// A realization row recorded on another host is not this host's device. Here
// intent X's row is on another host at 0000:82:00.0, the device intent Y
// realizes and the VM owns here; X resolves first. X takes the free
// 0000:81:00.0, Y keeps 0000:82:00.0.
func TestResolveDeviceIntents_TypeReuseIgnoresAnotherHostsRow(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	defer vfio.SetFS(newPCIBindFakeFS())()
	for _, d := range []struct{ addr, owner string }{{"0000:81:00.0", ""}, {"0000:82:00.0", "vm-t"}} {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: "test-host", Address: d.addr, Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: d.owner}); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range []corrosion.PCIRealizationRecord{
		{VMName: "vm-t", DeviceID: "dev-x", MemberID: "m0", HostName: "elsewhere", ResolvedAddress: "0000:82:00.0"},
		{VMName: "vm-t", DeviceID: "dev-y", MemberID: "m0", HostName: "test-host", ResolvedAddress: "0000:82:00.0"},
	} {
		if err := corrosion.UpsertPCIRealization(ctx, s.db, r); err != nil {
			t.Fatal(err)
		}
	}
	payload, err := protojson.Marshal(&pb.DeviceSpec{Type: "gpu", Vendor: "10de"})
	if err != nil {
		t.Fatal(err)
	}
	var intents []corrosion.PCIIntentRecord
	for _, id := range []string{"dev-x", "dev-y"} {
		intents = append(intents, corrosion.PCIIntentRecord{VMName: "vm-t", DeviceID: id, HostName: "test-host", SelectorKind: "type", SelectorPayload: string(payload)})
	}
	members, err := s.resolveDeviceIntents(ctx, "vm-t", intents)
	got := map[string]string{}
	for _, m := range members {
		got[m.DeviceID] = m.Address
	}
	if err != nil || len(members) != 2 || got["dev-x"] != "0000:81:00.0" || got["dev-y"] != "0000:82:00.0" {
		t.Fatalf("members = %+v (%v); want dev-x on the free 0000:81:00.0 and dev-y keeping 0000:82:00.0", members, err)
	}
}

// The operator pinned by address the device a type intent had realized. The
// type intent does not reuse it as well: it takes a free one, and each device
// is resolved once.
func TestResolveDeviceIntents_TypeReuseSkipsADeviceNamedByAddress(t *testing.T) {
	s := testServerR2(t)
	ctx := adminCtx()
	defer vfio.SetFS(newPCIBindFakeFS())()
	for _, d := range []struct{ addr, owner string }{{"0000:81:00.0", "vm-t"}, {"0000:82:00.0", ""}} {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: "test-host", Address: d.addr, Type: "gpu", VendorID: "10de", IOMMUGroup: -1, VMName: d.owner}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.UpsertPCIRealization(ctx, s.db, corrosion.PCIRealizationRecord{VMName: "vm-t", DeviceID: "dev-t", MemberID: "m0",
		HostName: "test-host", ResolvedAddress: "0000:81:00.0"}); err != nil {
		t.Fatal(err)
	}
	payload, err := protojson.Marshal(&pb.DeviceSpec{Type: "gpu", Vendor: "10de"})
	if err != nil {
		t.Fatal(err)
	}
	key := "0000:81:00.0"
	members, err := s.resolveDeviceIntents(ctx, "vm-t", []corrosion.PCIIntentRecord{
		{VMName: "vm-t", DeviceID: "dev-t", HostName: "test-host", SelectorKind: "type", SelectorPayload: string(payload)},
		{VMName: "vm-t", DeviceID: "dev-a", HostName: "test-host", SelectorKind: "address", ExclusiveKey: &key},
	})
	got := map[string]string{}
	for _, m := range members {
		got[m.DeviceID] = m.Address
	}
	if err != nil || len(members) != 2 || got["dev-a"] != "0000:81:00.0" || got["dev-t"] != "0000:82:00.0" {
		t.Fatalf("members = %+v (%v); want dev-a on 0000:81:00.0 and dev-t on the free 0000:82:00.0", members, err)
	}
}

// Mixed selectors over one IOMMU group {GPU 81:00.0, audio 81:00.1}: an
// address, a type or a mapping for each, in each intent order. Each device
// is resolved exactly once, with no refusal, whatever the order.
func TestResolveDeviceIntents_MixedSelectorsOneGroupEachOrder(t *testing.T) {
	ctx := adminCtx()
	defer vfio.SetFS(newPCIBindFakeFS())()
	mk := func(t *testing.T, id string, spec *pb.DeviceSpec) corrosion.PCIIntentRecord {
		kind, key := corrosion.ClassifyPCISelector(spec)
		p, err := protojson.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		return corrosion.PCIIntentRecord{VMName: "vm-x", DeviceID: id, HostName: "test-host", SelectorKind: kind, SelectorPayload: string(p), ExclusiveKey: key}
	}
	gpuAddr := &pb.DeviceSpec{Address: "0000:81:00.0"}
	audAddr := &pb.DeviceSpec{Address: "0000:81:00.1"}
	gpuType := &pb.DeviceSpec{Type: "gpu"}
	audMap := &pb.DeviceSpec{Mapping: "aud"}
	for _, tc := range []struct {
		name string
		a, b *pb.DeviceSpec
	}{
		{"addr gpu, addr audio", gpuAddr, audAddr},
		{"addr audio, addr gpu", audAddr, gpuAddr},
		{"type gpu, addr audio", gpuType, audAddr},
		{"addr audio, type gpu", audAddr, gpuType},
		{"addr gpu, map audio", gpuAddr, audMap},
		{"map audio, addr gpu", audMap, gpuAddr},
		{"type gpu, map audio", gpuType, audMap},
		{"map audio, type gpu", audMap, gpuType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerR2(t)
			for _, d := range []struct{ addr, typ string }{{"0000:81:00.0", "gpu"}, {"0000:81:00.1", "audio"}} {
				if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{HostName: "test-host", Address: d.addr, Type: d.typ, VendorID: "10de", IOMMUGroup: 20}); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.CreateResourceMapping(ctx, s.db, "aud", ""); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.AddMappingDevice(ctx, s.db, "aud", "test-host", "0000:81:00.1", "10de", "22a3"); err != nil {
				t.Fatal(err)
			}
			members, err := s.resolveDeviceIntents(ctx, "vm-x", []corrosion.PCIIntentRecord{mk(t, "d1", tc.a), mk(t, "d2", tc.b)})
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			seen := map[string]int{}
			for _, m := range members {
				seen[m.Address]++
			}
			if len(seen) != 2 || seen["0000:81:00.0"] != 1 || seen["0000:81:00.1"] != 1 {
				t.Errorf("members %+v; want each of the pair once", members)
			}
		})
	}
}

// The create path (allocateDevices) over the same group and orderings: each
// device of the pair is claimed exactly once, with no refusal.
func TestAllocateDevices_MixedSelectorsOneGroupEachOrder(t *testing.T) {
	ctx := adminCtx()
	defer vfio.SetFS(newPCIBindFakeFS())()
	gpuAddr := &pb.DeviceSpec{Address: "0000:81:00.0"}
	audAddr := &pb.DeviceSpec{Address: "0000:81:00.1"}
	gpuType := &pb.DeviceSpec{Type: "gpu"}
	audMap := &pb.DeviceSpec{Mapping: "aud"}
	for _, tc := range []struct {
		name string
		a, b *pb.DeviceSpec
	}{
		{"addr gpu, addr audio", gpuAddr, audAddr},
		{"addr audio, addr gpu", audAddr, gpuAddr},
		{"type gpu, addr audio", gpuType, audAddr},
		{"addr audio, type gpu", audAddr, gpuType},
		{"addr gpu, map audio", gpuAddr, audMap},
		{"map audio, addr gpu", audMap, gpuAddr},
		{"type gpu, map audio", gpuType, audMap},
		{"map audio, type gpu", audMap, gpuType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerR2(t)
			for _, d := range []struct{ addr, typ string }{{"0000:81:00.0", "gpu"}, {"0000:81:00.1", "audio"}} {
				if err := corrosion.UpsertPCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{HostName: "test-host", Address: d.addr, Type: d.typ, VendorID: "10de", IOMMUGroup: 20}); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.CreateResourceMapping(ctx, s.db, "aud", ""); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.AddMappingDevice(ctx, s.db, "aud", "test-host", "0000:81:00.1", "10de", "22a3"); err != nil {
				t.Fatal(err)
			}
			specs := []*pb.DeviceSpec{proto.Clone(tc.a).(*pb.DeviceSpec), proto.Clone(tc.b).(*pb.DeviceSpec)}
			addrs, finish, err := s.allocateDevices(ctx, "vm-x", specs, deviceLeaseStageBound)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			defer finish()
			seen := map[string]int{}
			for _, a := range addrs {
				seen[a]++
			}
			if len(seen) != 2 || seen["0000:81:00.0"] != 1 || seen["0000:81:00.1"] != 1 {
				t.Errorf("addresses %v; want each of the pair once", addrs)
			}
		})
	}
}
