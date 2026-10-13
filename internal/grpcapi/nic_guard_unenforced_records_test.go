package grpcapi

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// openGuardRecords makes guard records writable on s, and gives it an SR-IOV
// network "vf" with no PF named: its bridge name is the network's own, with no
// direct: prefix, so only the network's type says a guard cannot hold there.
func openGuardRecords(t *testing.T, s *Server) {
	t.Helper()
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(&relGate{t: t, open: true})
	s.netProvisioner = &bridgeRemovalProv{}
	s.bridgeEnsure = func(string) error { return nil }
	if err := corrosion.UpsertNetwork(adminCtx(), s.db, corrosion.NetworkRecord{Name: "vf", Type: "sriov",
		Config: `{"type":"sriov"}`}); err != nil {
		t.Fatal(err)
	}
}

// guardRecordsOf is the MACs vm has a live guard record for.
func guardRecordsOf(t *testing.T, s *Server, vm string) map[string]bool {
	t.Helper()
	recs, err := corrosion.ListNICGuards(adminCtx(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, r := range recs {
		if r.VMName == vm {
			out[r.MAC] = true
		}
	}
	return out
}

// Round 4, R3: lv attach-nic gives an SR-IOV NIC no guard record — the record
// would claim a protection the NIC lacks — while a bridge NIC gets its default.
func TestAttachNIC_AnSRIOVNICGetsNoGuardRecord(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	openGuardRecords(t, s)
	seedNICVM(t, s, "vm1", "stopped")
	const lanMAC, vfMAC = "52:54:00:ab:00:01", "52:54:00:ab:00:02"
	for _, n := range []*pb.NetworkAttachment{{Name: "lan", Mac: lanMAC}, {Name: "vf", Mac: vfMAC}} {
		if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "vm1", Nic: n}); err != nil {
			t.Fatalf("attach %s: %v", n.Name, err)
		}
	}
	got := guardRecordsOf(t, s, "vm1")
	if !got[lanMAC] {
		t.Errorf("the bridge NIC got no default guard record (records %v): the check below would prove nothing", got)
	}
	if got[vfMAC] {
		t.Errorf("the SR-IOV NIC got a guard record: %v", got)
	}
}

// Round 4, R3: a clone's SR-IOV NIC gets no guard record either.
func TestCloneVM_AnSRIOVNICGetsNoGuardRecord(t *testing.T) {
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	openGuardRecords(t, s)
	ctx := adminCtx()
	srcDisk := s.images.DiskPath("tpl", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatal(err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 512,
		Network: []*pb.NetworkAttachment{{Name: "lan"}, {Name: "vf"}}})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "tpl", HostName: "test-host", State: "stopped", IsTemplate: true, Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: "tpl", DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "tpl", Target: "c1", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	spec := clonedSpec(t, s, "c1")
	if len(spec.GetNetwork()) != 2 {
		t.Fatalf("clone NICs %v", spec.GetNetwork())
	}
	got := guardRecordsOf(t, s, "c1")
	lanMAC, vfMAC := spec.Network[0].GetMac(), spec.Network[1].GetMac()
	if !got[lanMAC] {
		t.Errorf("the clone's bridge NIC got no default guard record (records %v)", got)
	}
	if got[vfMAC] {
		t.Errorf("the clone's SR-IOV NIC got a guard record: %v", got)
	}
}

// copyNICGuards (a renamed restore or promotion) leaves out a NIC whose
// network cannot enforce a guard.
func TestCopyNICGuards_LeavesOutAnUnenforcedNetwork(t *testing.T) {
	recs := copyNICGuards("v", "u", []corrosion.InterfaceRecord{{NetworkName: "lan", MAC: "52:54:00:00:00:01"},
		{NetworkName: "vf", MAC: "52:54:00:00:00:02", Ordinal: 1}}, func(n string) string {
		if n == "vf" {
			return "sriov"
		}
		return ""
	})
	if len(recs) != 1 || recs[0].Network != "lan" {
		t.Errorf("records %+v, want only lan's", recs)
	}
}
