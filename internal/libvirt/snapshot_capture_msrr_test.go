package libvirt

import (
	"sync/atomic"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Re-review repro (msrr): the pauser's Hold lands while a live capture is
// still measuring the dirty rate, before its libvirt job exists. The abort
// finds no job, the capture then starts its LIVE job anyway, the Hold's wait
// runs out, and the pauser suspends during the precopy and records the pause.
// libvirt's cleanup then resumes the guest it found running when the job
// began: a partition-paused guest runs again until settle re-suspends it.
func TestMsrr_HoldDuringDirtyRateProbeIsResumedByLibvirt(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0          // measured: converges on paper (live chosen)
	m.qemu.dirtyBps = 2 * m.bps() // but never converges: the job waits
	reg := NewCaptureRegistry()
	var pauserSuspended atomic.Bool
	pauserDone := make(chan struct{})
	started := false
	captureSleep = func(time.Duration) {
		if started {
			return
		}
		started = true
		go func() { // the partition pauser, as pauseVMs runs it
			defer close(pauserDone)
			reg.Hold("vm", 300*time.Millisecond) // captureWait, scaled
			if err := m.DomainSuspend(golibvirt.Domain{Name: "vm"}); err == nil {
				pauserSuspended.Store(true) // pauseOne: recorded, reported paused
			}
		}()
		time.Sleep(50 * time.Millisecond) // the probe's remaining second
	}
	var ranAfterPause atomic.Bool
	m.qemu.postJob = func() { // libvirt's create returned, its cleanup resume included
		if pauserSuspended.Load() && m.state() == golibvirt.DomainRunning {
			ranAfterPause.Store(true)
		}
	}
	_, _ = m.capture("s1", CaptureOptions{Deadline: 5 * time.Second, Registry: reg})
	<-pauserDone
	if !pauserSuspended.Load() {
		t.Fatal("the pauser's suspend failed")
	}
	if ranAfterPause.Load() {
		t.Fatal("libvirt resumed a guest the partition pauser had suspended and recorded (Hold landed before the capture's job)")
	}
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("final state %v, want paused", st)
	}
}
