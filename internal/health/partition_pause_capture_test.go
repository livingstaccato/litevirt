package health

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// captureOpts are the options grpcapi.CreateSnapshot gives a capture of vm on
// this fixture's host: its registry, and its pause record as Held.
func (f *pauseFixture) captureOpts(reg *lv.CaptureRegistry, vm string) lv.CaptureOptions {
	return lv.CaptureOptions{Registry: reg, Deadline: 20 * time.Second, Held: func() bool {
		_, held, err := ReadPauseRecord(f.dataDir, PauseKindVM, vm)
		return err != nil || held
	}}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 5000; i++ {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// The partition pause wins over a live memory snapshot: the pauser aborts the
// capture's job, waits out libvirt's cleanup resume, then records and
// suspends the VM, and the capture leaves it paused.
//
// Mutation: drop the registry Hold from pauseVMs — the abort never comes, the
// capture's job never ends, and the VM is resumed or never recorded; red.
func TestPartitionPause_WinsOverALiveCapture(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0})
	errc := make(chan error, 1)
	go func() {
		_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
		errc <- err
	}()
	waitFor(t, "the live capture's memory write", func() bool { return f.virt.LiveJobRunning("vm-ha") })

	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the aborted capture reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the capture did not end after the pause")
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after the pause, want paused", st)
	}
	if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); !held {
		t.Fatal("vm-ha has no pause record")
	}
	if reg.InFlight("vm-ha") {
		t.Fatal("the capture is still registered")
	}
}

// The partition pause wins over a paused (firmware) memory snapshot: the VM
// reads paused while it is captured, yet the pauser records it as its own,
// and the capture does not resume it.
//
// Mutation: skip a paused domain even with a capture in flight — no record,
// the capture resumes the VM; red.
func TestPartitionPause_WinsOverAPausedCapture(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	inWindow, release := make(chan struct{}), make(chan struct{})
	o := f.captureOpts(reg, "vm-ha")
	o.Firmware = true
	o.CaptureSuspended = func() error {
		close(inWindow)
		<-release
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), o)
		errc <- err
	}()
	<-inWindow
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s inside the paused capture", st)
	}
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); !held {
		t.Fatal("the pauser did not record the VM a capture held paused")
	}
	close(release)
	if err := <-errc; err != nil {
		t.Fatalf("the capture: %v", err)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after the capture, want paused (the pauser's)", st)
	}
}

// A memory snapshot whose libvirt job outlives the pauser's wait (QEMU does
// not act on the abort): the pauser suspends and records anyway, and counts
// the pause as failed, because libvirt resumes the guest at the job's end
// (§3.3, §3.4: self-fence when armed).
//
// Mutation: discard Hold's settled — no failure is raised; red.
func TestPartitionPause_ACaptureOutlivingTheWaitIsAFailedPause(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0, IgnoreAbort: true})
	errc := make(chan error, 1)
	go func() {
		_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
		errc <- err
	}()
	waitFor(t, "the live capture's memory write", func() bool { return f.virt.LiveJobRunning("vm-ha") })

	var whys []string
	f.p.SetSelfFence(func() bool { return true }, func() {
		f.p.mu.Lock()
		whys = append(whys, f.p.failed[PauseKindVM+"/vm-ha"])
		f.p.mu.Unlock()
	})
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if len(whys) == 0 || !strings.Contains(whys[0], "memory snapshot") {
		t.Fatalf("self-fences with pause failures %q, want one for vm-ha's capture job", whys)
	}
	select {
	case <-errc:
	case <-time.After(10 * time.Second):
		t.Fatal("the capture did not end")
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s, want paused (the capture re-suspends it)", st)
	}
}

// A captured VM that shut off is nothing to pause: the pauser takes a VM a
// capture holds only while it reads paused (any paused reason), and skips
// one that is not executing at all.
//
// Mutation: take every non-running VM with a capture in flight — the suspend
// of the shut-off VM fails and counts as a failed pause; red.
func TestPartitionPause_ACapturedVMThatShutOffIsSkipped(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	inWindow, release := make(chan struct{}), make(chan struct{})
	o := f.captureOpts(reg, "vm-ha")
	o.Firmware = true
	o.CaptureSuspended = func() error {
		close(inWindow)
		<-release
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), o)
		errc <- err
	}()
	<-inWindow
	f.virt.SetState("vm-ha", libvirtfake.StateShutdown) // the guest went down mid-capture
	fenced := 0
	f.p.SetSelfFence(func() bool { return true }, func() { fenced++ })
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	close(release)
	<-errc
	if fenced != 0 {
		t.Fatalf("a shut-off captured VM made the pause fail (%d self-fences)", fenced)
	}
	if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); held {
		t.Fatal("a shut-off VM was recorded as paused")
	}
}

// domainPaused is "paused, any reason", and nothing else: a guest QEMU
// paused on an I/O error during a capture, or one the capture or libvirt
// paused (user, snapshot), is the pauser's as much as one with no reason.
//
// Mutation: narrow it by PausedReason (exclude io-error, or accept only
// user/snapshot) — red.
func TestDomainPaused_AnyPausedReason(t *testing.T) {
	for _, st := range []lv.DomainStatus{
		{State: "stopped", Reason: "paused"},
		{State: "stopped", Reason: "paused", PausedReason: lv.PausedReasonIOError},
		{State: "stopped", Reason: "paused", PausedReason: "user"},
		{State: "stopped", Reason: "paused", PausedReason: "snapshot"},
		{State: "stopped", Reason: "paused", PausedReason: "unknown"},
	} {
		if !domainPaused(st) {
			t.Errorf("%+v is not paused", st)
		}
	}
	for _, r := range []string{"running", "pmsuspended", "shutting-down", "crashed", "destroyed", "guest-shutdown", "unknown"} {
		if domainPaused(lv.DomainStatus{State: "stopped", Reason: r}) {
			t.Errorf("reason %q counted as paused", r)
		}
	}
}
