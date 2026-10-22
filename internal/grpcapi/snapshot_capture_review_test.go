package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Reviewer repro: the partition pauser records and suspends the VM while a
// memory snapshot is in flight (here, once libvirt switched the disks). After
// CreateSnapshot the VM must still be paused.
func TestMsrev_PartitionPauseDuringLiveCaptureIsUndone(t *testing.T) {
	s, fake := plainMemoryVM(t, libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	fake.FailCreateLiveSnapshot = func(dom, _ string) error {
		if err := writePauseRecordForTest(s.dataDir, dom, s.hostName); err != nil {
			t.Fatal(err)
		}
		fake.SetPaused(dom) // the pauser's suspend
		return nil
	}
	if _, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "pm", Name: "s1", WithMemory: true}); err != nil {
		t.Fatal(err)
	}
	if st, _ := fake.RawState("pm"); st != libvirtfake.StatePaused {
		t.Fatalf("partition-paused pm is %s after the live capture, want paused", st)
	}
}

func TestMsrev_PartitionPauseDuringPausedCaptureIsUndone(t *testing.T) {
	f := newFRFixture(t, "running", libvirtfake.StateRunning)
	f.fake.SetActiveXML("os1", "<domain type='kvm'><name>os1</name><devices></devices></domain>")
	f.fake.SetMemoryModel("os1", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30})
	f.fake.FailCreateLiveSnapshot = func(dom, _ string) error {
		// The domain reads paused here (the capture paused it), so the real
		// pauser would skip it; an operator's `virsh suspend` lands the same.
		if err := writePauseRecordForTest(f.s.dataDir, dom, f.s.hostName); err != nil {
			t.Fatal(err)
		}
		return nil
	}
	if _, err := f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "os1", Name: "s1", WithMemory: true}); err != nil {
		t.Fatal(err)
	}
	if st, _ := f.fake.RawState("os1"); st != libvirtfake.StatePaused {
		t.Fatalf("os1 with a pause record is %s after the paused capture, want paused", st)
	}
}
