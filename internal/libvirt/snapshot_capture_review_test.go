package libvirt

import (
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Review repro (memsnap-p1-review.md B1): a guest the partition pauser
// pauses while a capture is in flight must still be paused afterwards. The
// pauser pauses through the host's capture registry (Hold, then suspend), as
// health.PartitionPauser does; a bare suspend with no hold and no record
// cannot be told from QEMU's own switch-over stop, which libvirt also reports
// as PAUSED_SNAPSHOT.

// Live variant: the pauser pauses during the precopy (the domain reads
// "running").
func TestMsrev_LiveCaptureUndoesAnExternalPause(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0
	m.qemu.dirtyBps = 2 * m.bps() // never converges: the job waits
	reg := NewCaptureRegistry()
	go func() {
		for i := 0; i < 500; i++ {
			m.mu.Lock()
			job := m.qemu.liveJob
			m.mu.Unlock()
			if job {
				reg.Hold("vm", 2*time.Second)
				_ = m.DomainSuspend(golibvirt.Domain{Name: "vm"})
				return
			}
			time.Sleep(time.Millisecond)
		}
	}()
	_, _ = m.capture("s1", CaptureOptions{Deadline: 5 * time.Second, Registry: reg})
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("a guest the pauser suspended during the live capture is %v afterwards, want paused", st)
	}
}

// Paused variant: the pauser pauses while litevirt holds the guest paused
// (the domain reads paused; the registry tells the pauser it is its to
// pause).
func TestMsrev_PausedCaptureUndoesAnExternalPause(t *testing.T) {
	m := newLibvirt10(t)
	reg := NewCaptureRegistry()
	o := CaptureOptions{Firmware: true, Registry: reg, CaptureSuspended: func() error {
		reg.Hold("vm", time.Second)
		return m.DomainSuspend(golibvirt.Domain{Name: "vm"})
	}}
	m.mustCapture("s1", o)
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("a guest suspended during the paused capture is %v afterwards, want paused", st)
	}
}
