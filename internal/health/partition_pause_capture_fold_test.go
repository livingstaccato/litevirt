package health

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// endCaptureOnRead is the fake with one DomainStateReason of vm that reads
// the domain (paused, by a capture), then lets the capture finish (its
// settle resumes the guest, no hold being taken yet) and returns only once
// the capture has left the registry: the capture ends between the pass's
// state read and its in-flight check.
type endCaptureOnRead struct {
	*libvirtfake.Fake
	vm      string
	reg     *lv.CaptureRegistry
	release chan struct{}
	fired   atomic.Bool
}

func (b *endCaptureOnRead) DomainStateReason(name string) (lv.DomainStatus, error) {
	st, err := b.Fake.DomainStateReason(name)
	if name == b.vm && err == nil && st.Reason == "paused" && b.reg.InFlight(name) && b.fired.CompareAndSwap(false, true) {
		close(b.release)
		for i := 0; i < 5000 && b.reg.InFlight(name); i++ {
			time.Sleep(time.Millisecond)
		}
	}
	return st, err
}

// A paused-variant capture holds vm-ha paused when the pass reads its state,
// and ends (resuming it) before the pass asks whether a capture is in flight.
// The pass still takes vm-ha as its own: in its first pass, vm-ha is paused
// and recorded, or the pause counts as failed — never left running with no
// record and no failure.
//
// Mutation: check only InFlight at the moment of the check (drop the set of
// captures seen at the pass's start) — vm-ha runs unrecorded with 0
// failures; red.
func TestPartitionPause_ACaptureEndingAfterTheStateReadIsStillPaused(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	b := &endCaptureOnRead{Fake: f.virt, vm: "vm-ha", reg: reg, release: make(chan struct{})}
	f.p.SetVMBackend(b)
	inWindow := make(chan struct{})
	o := f.captureOpts(reg, "vm-ha")
	o.Firmware = true
	o.CaptureSuspended = func() error {
		close(inWindow)
		<-b.release
		return nil
	}
	errc := make(chan error, 1)
	go func() {
		_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), o)
		errc <- err
	}()
	<-inWindow
	f.set(QuorumNo)
	for elapsed := time.Duration(0); elapsed <= PartitionPauseAfter+time.Second && !b.fired.Load(); elapsed += time.Second {
		f.tick()
		f.advance(time.Second)
	}
	if !b.fired.Load() {
		t.Fatal("no pause pass read vm-ha while it was captured")
	}
	_, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha")
	f.p.mu.Lock()
	why, failed := f.p.failed[PauseKindVM+"/vm-ha"]
	f.p.mu.Unlock()
	if st := f.raw("vm-ha"); !(failed || (held && st == libvirtfake.StatePaused)) {
		t.Fatalf("after the pass that read vm-ha: %s, recorded %v, failure %q; want paused and recorded, or a failed pause", st, held, why)
	}
	select {
	case <-errc:
	case <-time.After(10 * time.Second):
		t.Fatal("the capture did not end")
	}
}

// A capture on a VM the pass does not pause (policy none) is not preempted:
// it completes across a pause pass.
//
// Mutation: preemptCaptures ignores the row filter — vm-none's capture is
// aborted; red.
func TestPartitionPause_ACaptureOfAVMThePassSkipsIsNotPreempted(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-none", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0})
	o := f.captureOpts(reg, "vm-none")
	o.Deadline = 3 * time.Second // the guest is suspended to finish it, after the pass
	errc := make(chan error, 1)
	go func() {
		_, _, err := f.virt.CreateLiveSnapshot("vm-none", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), o)
		errc <- err
	}()
	waitFor(t, "the live capture's memory write", func() bool { return f.virt.LiveJobRunning("vm-none") })
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); !held {
		t.Fatal("the pass did not run: vm-ha is not recorded")
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatalf("the capture of a VM the pass does not pause failed: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the capture did not end")
	}
	if st := f.raw("vm-none"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-none is %s after its capture, want running", st)
	}
}

// No capture starts while this host lacks the voter majority.
//
// Mutation: Evaluate never refuses captures — the capture is admitted; red.
func TestPartitionPause_NoCaptureStartsWithoutTheMajority(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	f.set(QuorumNo)
	f.tick() // the loss is seen; nothing is paused yet
	if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); held {
		t.Fatal("vm-ha was paused on the first loss reading")
	}
	_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
	var nt *lv.CaptureNotTakenError
	if !errors.As(err, &nt) {
		t.Fatalf("a capture on a host without the majority: err = %v, want refused (nothing taken)", err)
	}
	if n := len(f.virt.Captures("vm-ha")); n != 0 {
		t.Fatalf("%d capture(s) taken", n)
	}
	// The majority back: captures start again.
	f.set(QuorumYes)
	f.tick()
	if _, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s2", filepath.Join(t.TempDir(), "s2.vmstate"), f.captureOpts(reg, "vm-ha")); err != nil {
		t.Fatalf("a capture with the majority back: %v", err)
	}
}

// A capture asked for while a pause pass runs (here the voter set is
// unreadable, which pauses but is not a reported loss) is refused: it could
// meet the pass after the pass's start-of-pass preemption, and fail a pause
// a plain suspend would have made.
//
// Mutation: drop PausePass from pauseAll — the capture starts mid-pass; red.
func TestPartitionPause_NoCaptureStartsDuringAPausePass(t *testing.T) {
	f := newPauseFixture(t)
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: "vm-b", HostName: "node-a",
		Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	f.virt.SetState("vm-b", libvirtfake.StateRunning)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 32 << 20, ReportBps: 32 << 20})
	var once sync.Once
	var midErr error
	var tried atomic.Bool
	f.virt.FailDomainStateReason = func(name string) error {
		if name == "vm-b" {
			once.Do(func() {
				_, _, midErr = f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
				tried.Store(true)
			})
		}
		return nil
	}
	var fences atomic.Int32
	f.p.SetSelfFence(func() bool { return true }, func() { fences.Add(1) })
	f.set(QuorumUnknown)
	for elapsed := time.Duration(0); elapsed <= PartitionPauseAfter+time.Second && !tried.Load(); elapsed += time.Second {
		f.tick()
		f.advance(time.Second)
	}
	if !tried.Load() {
		t.Fatal("no pause pass ran")
	}
	var nt *lv.CaptureNotTakenError
	if !errors.As(midErr, &nt) {
		t.Fatalf("a capture asked for mid-pass: err = %v, want refused (nothing taken)", midErr)
	}
	if n := fences.Load(); n != 0 {
		t.Fatalf("the host self-fenced %d time(s)", n)
	}
	if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-ha"); !held {
		t.Fatal("vm-ha was not paused")
	}
}
