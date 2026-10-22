package health

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// msr2: libvirt does not answer the pauser's abort of a live capture (job
// lock held, libvirtd wedged). The pause pass must still end, count the
// pause as failed and self-fence when armed, as it does for a suspend that
// does not return.
func TestMsr2_AnUnansweredAbortStillSelfFences(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	hang := make(chan struct{})
	defer close(hang)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0, AbortBlock: hang})
	go func() {
		_, _, _ = f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
	}()
	waitFor(t, "the live capture's memory write", func() bool { return f.virt.LiveJobRunning("vm-ha") })

	fenced := make(chan struct{}, 1)
	f.p.SetSelfFence(func() bool { return true }, func() {
		select {
		case fenced <- struct{}{}:
		default:
		}
	})
	lost := make(chan struct{})
	go func() { defer close(lost); f.loseFor(QuorumNo, PartitionPauseAfter+time.Second) }()
	select {
	case <-fenced:
	case <-time.After(30 * time.Second):
		t.Fatalf("no self-fence 30s into the loss; vm-ha is %s (the pass is stuck in Hold's abort)", f.raw("vm-ha"))
	}
	<-lost
}

// Many VMs, one of them under a capture whose abort libvirt does not answer:
// every pass still ends within its budget, the other VMs are paused, and the
// stuck one counts as a failed pause.
//
// Mutation: Hold calls the abort synchronously — the pass waits on it and
// never ends; red.
func TestMsr2_ManyVMsOneStuckCaptureThePassStaysBounded(t *testing.T) {
	f := newPauseFixture(t)
	ctx := context.Background()
	for _, vm := range []string{"vm-b", "vm-c", "vm-d"} {
		if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: vm, HostName: "node-a",
			Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		f.virt.SetState(vm, libvirtfake.StateRunning)
	}
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	hang := make(chan struct{})
	defer close(hang)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0, AbortBlock: hang})
	go func() {
		_, _, _ = f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
	}()
	waitFor(t, "the live capture's memory write", func() bool { return f.virt.LiveJobRunning("vm-ha") })
	var fences int
	var mu sync.Mutex
	f.p.SetSelfFence(func() bool { return true }, func() { mu.Lock(); fences++; mu.Unlock() })

	f.set(QuorumNo)
	var longest time.Duration
	done := make(chan struct{})
	go func() {
		defer close(done)
		for elapsed := time.Duration(0); elapsed <= PartitionPauseAfter+time.Second; elapsed += time.Second {
			start := time.Now()
			f.tick()
			if d := time.Since(start); d > longest {
				longest = d
			}
			f.advance(time.Second)
		}
	}()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the pause passes did not end: a capture's unanswered abort holds the pass")
	}
	if longest > PartitionPauseExecBudget+time.Second {
		t.Fatalf("the longest pass took %v, past the budget %v", longest, PartitionPauseExecBudget)
	}
	for _, vm := range []string{"vm-b", "vm-c", "vm-d", "vm-ha"} {
		if st := f.raw(vm); st != libvirtfake.StatePaused {
			t.Errorf("%s is %s, want paused", vm, st)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if fences == 0 {
		t.Fatal("the stuck capture's pause was not counted as failed (no self-fence)")
	}
}

// Hold's wait is taken from the pass's budget, not added to it: with reads
// that used most of the budget and a capture whose job ignores the abort, the
// pause still lands within E of the pass's start (counted failed, since the
// hold could not settle in what was left).
//
// Mutation: Hold waits the full captureWait whatever the pass has used — the
// pass runs past E; red.
func TestPartitionPause_AHoldStaysInsideThePassBudget(t *testing.T) {
	f := newPauseFixture(t)
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0, IgnoreAbort: true})
	go func() {
		_, _, _ = f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
	}()
	waitFor(t, "the live capture's memory write", func() bool { return f.virt.LiveJobRunning("vm-ha") })
	slow := true
	f.virt.FailDomainStateReason = func(name string) error {
		if slow && name == "vm-ha" {
			time.Sleep(1900 * time.Millisecond) // a slow read: most of the reads' budget
		}
		return nil
	}
	f.virt.FailSuspendDomain = func(name string) error {
		if name == "vm-ha" {
			time.Sleep(1500 * time.Millisecond) // a slow suspend that succeeds
		}
		return nil
	}
	f.set(QuorumNo)
	var took time.Duration // the longest pass: the one that pauses
	for elapsed := time.Duration(0); elapsed <= PartitionPauseAfter+time.Second; elapsed += time.Second {
		start := time.Now()
		f.tick()
		took = max(took, time.Since(start))
		f.advance(time.Second)
		if st := f.raw("vm-ha"); st == libvirtfake.StatePaused {
			break
		}
	}
	slow = false
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after the loss", st)
	}
	if took > PartitionPauseExecBudget+300*time.Millisecond {
		t.Fatalf("the pausing pass took %v, past E = %v", took, PartitionPauseExecBudget)
	}
}
