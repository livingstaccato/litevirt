package grpcapi

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// plainMemoryVM is a running VM pm (no firmware state) on this host, on a
// fake whose QEMU has 1 GiB of RAM written at 1 GiB/s.
func plainMemoryVM(t *testing.T, mm libvirtfake.MemoryModel) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := testServer(t)
	fake := libvirtfake.New()
	s.virt = fake
	s.dataDir = t.TempDir()
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{
		Name: "pm", HostName: s.hostName, Spec: `{"name":"pm","cpu":1,"memory_mib":1024}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake.SetState("pm", libvirtfake.StateRunning)
	fake.SetMemoryModel("pm", mm)
	return s, fake
}

func totalPause(ws []libvirtfake.PauseWindow) time.Duration {
	var t time.Duration
	for _, w := range ws {
		t += w.Len()
	}
	return t
}

// A memory snapshot of a VM without firmware state is captured live, in
// the QEMU process it runs in, and pauses the guest for less than one write
// of its RAM (the old save+restore paused it for a write and a read).
//
// Mutation: make CreateSnapshot set Firmware for every VM — red (paused).
func TestCreateSnapshot_MemoryCaptureIsLiveInProcess(t *testing.T) {
	s, fake := plainMemoryVM(t, libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	starts := fake.QEMUStarts("pm")
	if _, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "pm", Name: "s1", WithMemory: true}); err != nil {
		t.Fatal(err)
	}
	caps := fake.Captures("pm")
	if len(caps) != 1 || !caps[0].Live() || caps[0].PausedBefore {
		t.Fatalf("captures = %+v, want one live capture of the running guest", caps)
	}
	if got := fake.QEMUStarts("pm"); got != starts {
		t.Fatalf("QEMU started %d -> %d times across the capture", starts, got)
	}
	if p := totalPause(fake.PauseWindows("pm")); p >= time.Second {
		t.Fatalf("the guest paused %v, no less than one RAM write (1s)", p)
	}
	rec, _ := corrosion.GetSnapshot(adminCtx(), s.db, "pm", "s1")
	if rec == nil || rec.State != "ok" || rec.Type != "memory" || rec.VMStateBytes == 0 {
		t.Fatalf("snapshot record = %+v", rec)
	}
	if _, err := os.Stat(rec.VMStatePath); err != nil {
		t.Fatalf("no vmstate image: %v", err)
	}
}

// A Secure Boot / vTPM VM is captured with its vCPUs stopped: the firmware
// bundle is taken at the snapshot instant. Its domain definition here names
// no NVRAM or TPM, so only the VM's spec can choose the paused variant.
//
// Mutation: drop Firmware and the capture hook from CreateSnapshot's
// options — red (captured live, no firmware bundle).
func TestCreateSnapshot_FirmwareVMCapturedPaused(t *testing.T) {
	f := newFRFixture(t, "running", libvirtfake.StateRunning)
	f.fake.SetActiveXML("os1", "<domain type='kvm'><name>os1</name><devices></devices></domain>")
	f.fake.SetMemoryModel("os1", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30})
	starts := f.fake.QEMUStarts("os1")
	if _, err := f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "os1", Name: "s1", WithMemory: true}); err != nil {
		t.Fatal(err)
	}
	caps := f.fake.Captures("os1")
	if len(caps) != 1 || caps[0].Live() || !caps[0].PausedBefore {
		t.Fatalf("captures = %+v, want one capture with the vCPUs stopped first", caps)
	}
	if got := f.fake.QEMUStarts("os1"); got != starts {
		t.Fatalf("QEMU started %d -> %d times across the capture", starts, got)
	}
	ws := f.fake.PauseWindows("os1")
	if len(ws) != 1 || ws[0].Len() > time.Second+time.Millisecond {
		t.Fatalf("pause windows %+v, want one of at most one RAM write (1s)", ws)
	}
	bundle, err := lv.SafeSnapshotFirmwareBundlePath(f.s.dataDir, "os1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(bundle); err != nil || fi.Size() == 0 {
		t.Fatalf("no firmware bundle captured: %v", err)
	}
	if st, _ := f.fake.RawState("os1"); st != libvirtfake.StateRunning {
		t.Fatalf("after the capture os1 is %v", st)
	}
}

// memory_snapshot.live_deadline reaches the capture: a guest that dirties
// faster than its image is written (after measuring idle) is suspended at
// the configured deadline, and the capture completes with it running.
//
// Mutation: do not pass the tuning's deadline — red (the 2m default; the
// fake gives up after 30s).
func TestCreateSnapshot_LiveDeadlineFromConfig(t *testing.T) {
	s, fake := plainMemoryVM(t, libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0})
	s.SetMemorySnapshotTuning(MemorySnapshotTuning{LiveDeadline: 50 * time.Millisecond})
	start := time.Now()
	if _, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "pm", Name: "s1", WithMemory: true}); err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Fatalf("the capture took %v", took)
	}
	caps := fake.Captures("pm")
	if len(caps) != 1 || !caps[0].Live() || !caps[0].SuspendedDuring {
		t.Fatalf("captures = %+v, want a live capture the deadline suspended", caps)
	}
	if st, _ := fake.RawState("pm"); st != libvirtfake.StateRunning {
		t.Fatalf("after the capture pm is %v", st)
	}
}

// memory_snapshot.pause_budget reaches the variant choice: a guest whose
// predicted final pause (2s: a 1 GiB guest dirtying faster than the
// write) fits a 5s budget is still captured live.
//
// Mutation: do not pass the tuning's budget — red (the 1s default takes
// the paused variant).
func TestCreateSnapshot_PauseBudgetFromConfig(t *testing.T) {
	s, fake := plainMemoryVM(t, libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 1 << 30, ReportBps: 2 << 30})
	s.SetMemorySnapshotTuning(MemorySnapshotTuning{PauseBudget: 5 * time.Second, LiveDeadline: 50 * time.Millisecond})
	if _, err := s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "pm", Name: "s1", WithMemory: true}); err != nil {
		t.Fatal(err)
	}
	caps := fake.Captures("pm")
	if len(caps) != 1 || !caps[0].Live() {
		t.Fatalf("captures = %+v, want live within a 5s budget", caps)
	}
}

// Rolling upgrade: a memory snapshot row an older node wrote (its RAM saved
// by DomainSaveFlags next to a disk-only libvirt snapshot) still reverts on
// this build; a row whose image is gone is refused before anything is torn
// down.
func TestRestoreSnapshot_AnOldFormatMemorySnapshotReverts(t *testing.T) {
	s, fake := plainMemoryVM(t, libvirtfake.MemoryModel{})
	path, err := lv.SafeVMStatePath(s.dataDir, "pm", "old")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("LibvirtQemudSave\x02older node"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fake.CreateSnapshot("pm", "old"); err != nil { // the older node's disk-only snapshot
		t.Fatal(err)
	}
	fake.SetSavedImageXML(path, "<domain type='kvm'><name>pm</name><devices></devices></domain>")
	if err := corrosion.InsertSnapshot(adminCtx(), s.db, corrosion.SnapshotRecord{
		VMName: "pm", HostName: s.hostName, Name: "old", State: "ok", Type: "memory", VMStatePath: path, VMStateBytes: 26,
	}); err != nil {
		t.Fatal(err)
	}
	starts := fake.QEMUStarts("pm")
	if _, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "pm", SnapshotName: "old"}); err != nil {
		t.Fatalf("revert to an older node's memory snapshot: %v", err)
	}
	if got := fake.QEMUStarts("pm"); got != starts+1 {
		t.Fatalf("QEMU started %d -> %d times; a revert restores the image in a new process", starts, got)
	}

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := len(fake.EventLog())
	_, err = s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "pm", SnapshotName: "old"})
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("revert with the image gone: %v, want refused as missing", err)
	}
	for _, e := range fake.EventLog()[before:] {
		if e.Op == "revert-live" {
			t.Fatal("the revert went ahead with the image gone")
		}
	}
}
