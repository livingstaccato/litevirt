package grpcapi

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

const gpuDomainXML = `<domain type='kvm'><name>gvm</name><uuid>6f1c1a52-6a0c-4b8e-9a8e-1d2c3b4a5f60</uuid>
<memory unit='MiB'>1024</memory><vcpu>1</vcpu><devices>
<disk type='file' device='disk'><source file='/var/lib/litevirt/disks/gvm-root.qcow2'/><target dev='vda' bus='virtio'/></disk>
<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/></source><alias name='ua-d1-m0'/></hostdev>
</devices></domain>`

// A memory snapshot saves the guest's RAM and device state, and a PCI
// passthrough device's state cannot be saved: libvirt refuses the save. That
// refusal came after the guest had been suspended and its disks cut over to
// a new overlay, so the VM was left on an extra overlay with an errored
// snapshot row, and each retry added another. It is refused before anything
// is touched, with the way out; a disk-only snapshot is still taken.
//
// Mutation: drop the passthrough preflight from the libvirt fake's
// CreateLiveSnapshot (it mirrors libvirt.Client's) — the overlay cuts over and
// an error row is written: red. Drop the PassthroughSnapshotError mapping in
// CreateSnapshot — Internal, not FailedPrecondition: red.
func TestCreateSnapshot_MemorySnapshotOfAPassthroughVMIsRefusedBeforeTheFreeze(t *testing.T) {
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: "gvm", HostName: s.hostName, Spec: `{"name":"gvm"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fake.SetInactiveXML("gvm", gpuDomainXML)
	fake.SetState("gvm", libvirtfake.StateRunning)
	const root = "/var/lib/litevirt/disks/gvm-root.qcow2"
	fake.SetDiskSource("gvm", "vda", root)

	_, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "gvm", Name: "m1", WithMemory: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("memory snapshot of a passthrough VM = %v, want FailedPrecondition", err)
	}
	msg := status.Convert(err).Message()
	for _, want := range []string{"0000:41:00.0", "disk-only"} {
		if !strings.Contains(msg, want) {
			t.Errorf("refusal %q does not name %q", msg, want)
		}
	}
	for _, e := range fake.EventLog() {
		if e.Op == "snapshot-live" {
			t.Errorf("the refused snapshot reached libvirt's freeze and overlay cutover: %+v", e)
		}
	}
	if srcs, _ := fake.DomainDiskSources("gvm"); srcs["vda"] != root {
		t.Errorf("vda is on %q after the refusal, want it still on %q", srcs["vda"], root)
	}
	if snaps, _ := corrosion.ListSnapshots(context.Background(), s.db, "gvm"); len(snaps) != 0 {
		t.Errorf("snapshot rows after the refusal = %+v, want none", snaps)
	}
	if st, _ := fake.RawState("gvm"); st != libvirtfake.StateRunning {
		t.Errorf("gvm is %s after the refusal, want running", st)
	}

	// A disk-only snapshot of the same running VM is still taken.
	snap, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "gvm", Name: "d1"})
	if err != nil {
		t.Fatalf("disk-only snapshot of a passthrough VM: %v", err)
	}
	if snap.Type != "disk" || snap.State != "ok" {
		t.Errorf("disk-only snapshot = %s/%s, want disk/ok", snap.Type, snap.State)
	}
}
