package fleet

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// lv snapshot create --memory entered on a node that does not own the VM:
// the owner captures it in the guest's running QEMU process (no new process,
// a pause shorter than one RAM write), and a later revert restores the
// memory the image holds, in a new process.
//
// Mutation "capture by save+restore" (the fake's capture model restarting
// QEMU) or "revert ignores the image" (MemoryGeneration not restored): red.
func TestFleet_MemorySnapshotIsCapturedInProcessAndReverts(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	seedRunningVM(t, c, owner, "mem", "", 1, 1024)
	if err := owner.Virt.DefineDomain("<domain type='kvm'><name>mem</name><memory unit='KiB'>1048576</memory><devices></devices></domain>"); err != nil {
		t.Fatal(err)
	}
	owner.Virt.SetState("mem", libvirtfake.StateRunning)
	owner.Virt.SetMemoryModel("mem", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 16 << 20, ReportBps: 16 << 20})

	starts := owner.Virt.QEMUStarts("mem")
	if _, err := c.SelfClient(entry).CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "mem", Name: "s1", WithMemory: true}); err != nil {
		t.Fatalf("memory snapshot s1 through %s: %v", entry.Name, err)
	}
	atS1 := owner.Virt.MemoryGeneration("mem")
	if _, err := c.SelfClient(entry).CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "mem", Name: "s2", WithMemory: true}); err != nil {
		t.Fatalf("memory snapshot s2: %v", err)
	}
	if got := owner.Virt.QEMUStarts("mem"); got != starts {
		t.Fatalf("two captures started QEMU %d time(s); a capture keeps the guest's process", got-starts)
	}
	for _, w := range owner.Virt.PauseWindows("mem") {
		if w.Len() >= 1e9 { // one RAM write: 1 GiB at 1 GiB/s
			t.Fatalf("a capture paused the guest %v, no less than one RAM write", w.Len())
		}
	}
	for _, cc := range owner.Virt.Captures("mem") {
		if !cc.Live() {
			t.Fatalf("capture %+v was not live", cc)
		}
	}
	if owner.Virt.MemoryGeneration("mem") == atS1 {
		t.Fatal("the second capture did not move the guest's memory on")
	}

	if _, err := c.SelfClient(entry).RestoreSnapshot(ctx, &pb.RestoreSnapshotRequest{VmName: "mem", SnapshotName: "s1"}); err != nil {
		t.Fatalf("revert to s1: %v", err)
	}
	if got := owner.Virt.MemoryGeneration("mem"); got != atS1 {
		t.Fatalf("after the revert the guest holds memory generation %d, want s1's %d", got, atS1)
	}
	if got := owner.Virt.QEMUStarts("mem"); got != starts+1 {
		t.Fatalf("the revert started QEMU %d time(s), want once (the restore)", got-starts)
	}
}
