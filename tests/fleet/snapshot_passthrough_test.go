package fleet

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// lv snapshot create --memory of a VM holding a PCI passthrough device,
// entered on a node that does not own it: the owner refuses it before the
// guest is frozen or its disks cut over, the refusal reaches the caller as
// FailedPrecondition, and no snapshot row exists anywhere. Without the
// preflight libvirt refused the RAM save only after the overlay cutover, which
// left the VM on an untracked extra overlay and an "error" snapshot row on
// every attempt.
//
// Mutation: drop the passthrough preflight from the libvirt fake's
// CreateLiveSnapshot (it mirrors libvirt.Client's): red.
func TestFleet_MemorySnapshotOfAPassthroughVMIsRefusedBeforeTheFreeze(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	seedRunningVM(t, c, owner, "gpu", "", 1, 512)
	const root = "/var/lib/litevirt/disks/gpu-root.qcow2"
	owner.Virt.SetInactiveXML("gpu", `<domain type='kvm'><name>gpu</name><uuid>0b0e8f7e-3f4c-4d55-8a3a-3c2f1e0d9b7a</uuid>
<memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>
<disk type='file' device='disk'><source file='`+root+`'/><target dev='vda' bus='virtio'/></disk>
<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/></source></hostdev>
</devices></domain>`)
	owner.Virt.SetDiskSource("gpu", "vda", root)

	_, err := c.SelfClient(entry).CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "gpu", Name: "m1", WithMemory: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(status.Convert(err).Message(), "0000:41:00.0") {
		t.Fatalf("memory snapshot through %s = %v, want FailedPrecondition naming 0000:41:00.0", entry.Name, err)
	}
	for _, e := range owner.Virt.EventLog() {
		if e.Op == "snapshot-live" {
			t.Errorf("the refused snapshot reached the owner's freeze and overlay cutover: %+v", e)
		}
	}
	if srcs, _ := owner.Virt.DomainDiskSources("gpu"); srcs["vda"] != root {
		t.Errorf("vda is on %q after the refusal, want %q", srcs["vda"], root)
	}
	if st, _ := owner.Virt.RawState("gpu"); st != libvirtfake.StateRunning {
		t.Errorf("gpu is %s after the refusal, want running", st)
	}
	for _, n := range c.Nodes {
		if snaps, _ := corrosion.ListSnapshots(ctx, n.DB, "gpu"); len(snaps) != 0 {
			t.Errorf("%s holds snapshot rows after the refusal: %+v", n.Name, snaps)
		}
	}

	// The disk-only snapshot stays available.
	if _, err := c.SelfClient(entry).CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "gpu", Name: "d1"}); err != nil {
		t.Fatalf("disk-only snapshot of the passthrough VM: %v", err)
	}
}
