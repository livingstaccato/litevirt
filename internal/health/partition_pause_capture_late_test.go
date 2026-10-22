package health

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A capture on the VM listed LAST in a slow pause pass: the reads of the VMs
// before it use most of the pass's read budget, so by the time the pass
// reaches it its Hold has almost no wait left. libvirt answers the abort in
// 600 ms, and a plain suspend would hold, so the capture alone must not make
// the pause count as failed and self-fence the host: the pass aborts every
// capture it is about to pause at its START, and the late Hold finds the job
// long ended.
//
// Mutation: drop the pass-start preemption — the late Hold's wait runs out
// before libvirt's answer, the pause counts as failed, and the armed host
// self-fences; red.
func TestPartitionPause_ALateListedCaptureDoesNotSelfFence(t *testing.T) {
	f := newPauseFixture(t)
	ctx := context.Background()
	early := []string{"vm-b", "vm-c", "vm-d"} // sorted before vm-ha
	for _, vm := range early {
		if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: vm, HostName: "node-a",
			Spec: `{"on_host_failure":"restart-any"}`, State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		f.virt.SetState(vm, libvirtfake.StateRunning)
	}
	reg := lv.NewCaptureRegistry()
	f.p.SetCaptureRegistry(reg)
	f.virt.SetMemoryModel("vm-ha", libvirtfake.MemoryModel{RAMBytes: 1 << 30, WriteBps: 1 << 30, DirtyBps: 2 << 30, ReportBps: 0,
		AbortDelay: 600 * time.Millisecond})
	errc := make(chan error, 1)
	go func() {
		_, _, err := f.virt.CreateLiveSnapshot("vm-ha", "s1", filepath.Join(t.TempDir(), "s1.vmstate"), f.captureOpts(reg, "vm-ha"))
		errc <- err
	}()
	waitFor(t, "the live capture's memory write", func() bool { return f.virt.LiveJobRunning("vm-ha") })

	// Each early VM's state read takes 950 ms: vm-ha's is read ~2.85 s into
	// the pass, with ~0.15 s of the reads' 3 s left for its Hold.
	var slow atomic.Bool
	slow.Store(true)
	f.virt.FailDomainStateReason = func(name string) error {
		if slow.Load() && name != "vm-ha" && name != "vm-none" {
			time.Sleep(950 * time.Millisecond)
		}
		return nil
	}
	var fences atomic.Int32
	f.p.SetSelfFence(func() bool { return true }, func() { fences.Add(1) })
	f.set(QuorumNo)
	for elapsed := time.Duration(0); elapsed <= PartitionPauseAfter+time.Second; elapsed += time.Second {
		f.tick()
		f.advance(time.Second)
		if f.raw("vm-ha") == libvirtfake.StatePaused && f.raw("vm-d") == libvirtfake.StatePaused {
			break
		}
	}
	slow.Store(false)
	if n := fences.Load(); n != 0 {
		f.p.mu.Lock()
		why := f.p.failed[PauseKindVM+"/vm-ha"]
		f.p.mu.Unlock()
		t.Fatalf("the host self-fenced %d time(s) over a capture on its last-listed VM (vm-ha: %q); a plain suspend would have held", n, why)
	}
	for _, vm := range append(early, "vm-ha") {
		if st := f.raw(vm); st != libvirtfake.StatePaused {
			t.Errorf("%s is %s, want paused", vm, st)
		}
		if _, held, _ := ReadPauseRecord(f.dataDir, PauseKindVM, vm); !held {
			t.Errorf("%s has no pause record", vm)
		}
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("the preempted capture reported success")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the capture did not end")
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after the capture ended, want paused", st)
	}
}
