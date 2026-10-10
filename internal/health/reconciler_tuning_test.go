package health

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A VM started by the reconciler on this host (a failover, or a clean-reboot
// autostart) is defined from its stored spec, so its disks' discard and
// throttle and its NIC's queues come out in the new definition. A start that
// dropped them would quietly un-throttle a noisy VM the moment its host failed.
//
// Mutations: drop compose.ApplyDiskTuning from domainXMLFor — the throttle and
// discard checks go red; drop compose.ApplyNICTuning — the queues check does.
func TestStartPendingVM_RendersDiskAndNICTuningFromTheSpec(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	diskPath := filepath.Join(t.TempDir(), "vm1-root.img")
	if err := os.WriteFile(diskPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{
		Name: "vm1", Cpu: 2, MemoryMib: 512,
		Disks:   []*pb.DiskSpec{{Name: "root", Bus: "virtio", Discard: "unmap", Io: &pb.DiskIOLimits{ReadIopsSec: 300}}},
		Network: []*pb.NetworkAttachment{{Name: "br0", Mac: "52:54:00:aa:bb:cc", Queues: 4}},
	})
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: string(spec), State: "running", CPUActual: 2, MemActual: 512},
		[]corrosion.InterfaceRecord{{VMName: "vm1", NetworkName: "br0", MAC: "52:54:00:aa:bb:cc"}},
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "node-a", Path: diskPath, StorageType: "local", SizeBytes: 1 << 30}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}

	r, fake, _ := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "vm1")
	r.startPendingVM(ctx, *fresh)

	x := fake.DefinedXML("vm1")
	if x == "" {
		t.Fatal("the VM was not defined")
	}
	if got, _ := lv.DiskIOTuneFromXML(x, "vda"); got.ReadIopsSec != 300 {
		t.Errorf("the started domain's throttle = %+v, want read_iops_sec 300:\n%s", got, x)
	}
	if !strings.Contains(x, `discard="unmap"`) {
		t.Errorf("the started domain lost discard:\n%s", x)
	}
	if !strings.Contains(x, `queues="4"`) {
		t.Errorf("the started domain lost its NIC queues:\n%s", x)
	}
}

// A NIC hot-plugged after the create has a vm_interfaces row and no spec entry,
// and a compose NIC with no `mac:` recorded none in the spec. The started domain
// still gives the tuned NIC its queues: it is matched by ordinal, not by the
// length of the list.
//
// Mutation: drop SpecOrdinal from the reconciler's NetworkConfig — the queues go
// to no NIC and the check goes red.
func TestStartPendingVM_TunedNICKeepsItsQueuesAfterAHotPlug(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	diskPath := filepath.Join(t.TempDir(), "vm2-root.img")
	if err := os.WriteFile(diskPath, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm2", Cpu: 2, MemoryMib: 512,
		Disks:   []*pb.DiskSpec{{Name: "root", Bus: "virtio"}},
		Network: []*pb.NetworkAttachment{{Name: "br0", Queues: 4}}}) // one entry, no MAC
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "vm2", HostName: "node-a", Spec: string(spec), State: "running", CPUActual: 2, MemActual: 512},
		[]corrosion.InterfaceRecord{
			{VMName: "vm2", NetworkName: "br0", Ordinal: 0, MAC: "52:54:00:aa:bb:01"},
			{VMName: "vm2", NetworkName: "br1", Ordinal: 1, MAC: "52:54:00:aa:bb:02"}, // hot-plugged
		},
		[]corrosion.DiskRecord{{VMName: "vm2", DiskName: "root", HostName: "node-a", Path: diskPath, StorageType: "local", SizeBytes: 1 << 30}},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	r, fake, _ := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "vm2")
	r.startPendingVM(ctx, *fresh)

	x := fake.DefinedXML("vm2")
	first, second, q := strings.Index(x, "aa:bb:01"), strings.Index(x, "aa:bb:02"), strings.Index(x, "queues=")
	if first < 0 || second < 0 || q < first || q > second || strings.Count(x, "queues=") != 1 {
		t.Errorf("the tuned NIC (aa:bb:01) must carry the only queues attribute:\n%s", x)
	}
}
