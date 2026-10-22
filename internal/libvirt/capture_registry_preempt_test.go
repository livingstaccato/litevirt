package libvirt

import (
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// Once libvirt answers, the capture's abort repeats until its create call
// returns: a capture that started its job after the first abort found none
// is still aborted.
func TestCaptureRegistry_TheAbortRepeatsUntilTheJobEnds(t *testing.T) {
	reg := NewCaptureRegistry()
	var calls atomic.Int32
	var e *captureEntry
	e, err := reg.begin("vm", func() error {
		if calls.Add(1) == 3 {
			e.jobDone() // the third abort reaches the job
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reg.end("vm", e)
	if _, settled := reg.Hold("vm", time.Second); !settled {
		t.Fatalf("the hold did not settle; %d aborts issued", calls.Load())
	}
}

// The pass-start Preempt and the later Holds share the capture's one
// outstanding abort.
func TestCaptureRegistry_PreemptAndHoldShareOneAbort(t *testing.T) {
	reg := NewCaptureRegistry()
	release := make(chan struct{})
	var outstanding, most atomic.Int32
	e, err := reg.begin("vm", func() error {
		n := outstanding.Add(1)
		for m := most.Load(); n > m && !most.CompareAndSwap(m, n); m = most.Load() {
		}
		<-release
		outstanding.Add(-1)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); reg.end("vm", e) }()
	for i := 0; i < 3; i++ {
		reg.Preempt("vm")
		_, _ = reg.Hold("vm", 20*time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if m := most.Load(); m != 1 {
		t.Fatalf("%d aborts outstanding at once; want 1", m)
	}
}

// Preempt marks the capture so it never starts its libvirt job, and aborts a
// job already running; it sets no hold, so a VM the pass then does not pause
// is not left held.
func TestCaptureRegistry_PreemptSetsNoHold(t *testing.T) {
	reg := NewCaptureRegistry()
	e, err := reg.begin("vm", func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer reg.end("vm", e)
	if reg.Preempt("vm"); reg.Holding("vm") {
		t.Fatal("Preempt set a hold")
	}
	if !e.preempted() {
		t.Fatal("the capture is not marked preempted")
	}
	if reg.Preempt("other"); reg.Holding("other") {
		t.Fatal("Preempt of a VM with no capture set a hold")
	}
}

// A job that has already ended settles a Hold even with no wait left: the
// pass preempted the capture at its start, and its Hold, however late in the
// pass, must not lose a coin toss between the ended job and a spent
// deadline.
//
// Mutation: drop Hold's ended-job check before its wait — about half of the
// holds come back unsettled; red.
func TestCaptureRegistry_AnEndedJobSettlesAHoldWithNoWaitLeft(t *testing.T) {
	reg := NewCaptureRegistry()
	e, err := reg.begin("vm", func() error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer reg.end("vm", e)
	e.jobDone() // the create call returned; the capture is still settling
	for i := 0; i < 64; i++ {
		if captured, settled := reg.Hold("vm", 0); !captured || !settled {
			t.Fatalf("hold %d: captured %v, settled %v; want a settled hold of the ended capture", i, captured, settled)
		}
	}
}

// preemptOnProbe is the libvirt10 model with the pauser's pass starting while
// the capture measures the guest's dirty rate, before its job.
type preemptOnProbe struct {
	*libvirt10
	reg *CaptureRegistry
}

func (p preemptOnProbe) DomainStartDirtyRateCalc(dom golibvirt.Domain, s int32, f uint32) error {
	p.reg.Preempt(dom.Name)
	return p.libvirt10.DomainStartDirtyRateCalc(dom, s, f)
}

// A capture preempted before its job never starts it, and its error says
// nothing was taken.
//
// Mutation: preJob ignores the preemption — the job is started (and then
// aborted); red.
func TestCapture_APreemptedCaptureNeverStartsItsJob(t *testing.T) {
	m := newLibvirt10(t)
	reg := NewCaptureRegistry()
	_, _, err := CaptureMemorySnapshot(preemptOnProbe{m, reg}, "vm", "s1", filepath.Join(m.dir, "vm-s1.vmstate"),
		CaptureOptions{Deadline: 5 * time.Second, Registry: reg})
	var nt *CaptureNotTakenError
	if !errors.As(err, &nt) {
		t.Fatalf("err = %v, want a capture that took nothing", err)
	}
	if n := len(m.qemu.creates); n != 0 {
		t.Fatalf("the preempted capture started %d libvirt job(s)", n)
	}
	if st := m.state(); st != golibvirt.DomainRunning {
		t.Fatalf("the guest is %v after the refused capture, want running (nothing held it)", st)
	}
}

// lostConnection is the libvirt10 model whose connection breaks during the
// snapshot create: the create call fails (libvirtd may still finish the job
// and switch the disks), and every domain XML read after it fails too.
type lostConnection struct {
	*libvirt10
	broken *atomic.Bool
}

func (l lostConnection) DomainSnapshotCreateXML(dom golibvirt.Domain, x string, flags uint32) (golibvirt.DomainSnapshot, error) {
	l.broken.Store(true)
	return golibvirt.DomainSnapshot{}, errors.New("libvirt: connection reset by peer")
}

func (l lostConnection) DomainGetXMLDesc(dom golibvirt.Domain, f golibvirt.DomainXMLFlags) (string, error) {
	if l.broken.Load() {
		return "", errors.New("libvirt: not connected")
	}
	return l.libvirt10.DomainGetXMLDesc(dom, f)
}

// A create that failed when nothing can show the disks unmoved (the after
// XML unreadable) is not "nothing taken": the caller must account for a
// snapshot that may exist (an error row, the disk paths reconciled).
//
// Mutation: switched() drops its unreadable-after-XML guard — the failure is
// reported as nothing taken; red.
func TestCapture_AFailedCreateWithAnUnreadableDomainMayHaveSwitched(t *testing.T) {
	for _, v := range captureVariants {
		t.Run(v.name, func(t *testing.T) {
			m := newLibvirt10(t)
			o := v.opts
			o.Registry = NewCaptureRegistry()
			_, _, err := CaptureMemorySnapshot(lostConnection{m, new(atomic.Bool)}, "vm", "s1", filepath.Join(m.dir, "vm-s1.vmstate"), o)
			if err == nil {
				t.Fatal("the failed create succeeded")
			}
			var nt *CaptureNotTakenError
			if errors.As(err, &nt) {
				t.Fatalf("a create that failed with the domain unreadable after it is reported as nothing taken: %v", err)
			}
		})
	}
}
