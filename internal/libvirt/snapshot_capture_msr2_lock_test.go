package libvirt

import (
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// hangResume is the libvirt10 model with a DomainResume that libvirt does
// not answer (its job lock held by a stuck call, or the connection wedged).
type hangResume struct {
	*libvirt10
	entered chan struct{}
	release chan struct{}
}

func (h hangResume) DomainResume(dom golibvirt.Domain) error {
	close(h.entered)
	<-h.release
	return h.libvirt10.DomainResume(dom)
}

// msr2: a capture's settle makes its libvirt calls under the registry's one
// lock. When one of them does not return, the pauser's Hold of ANY VM on the
// host, and its InFlight read, wait on that lock: the pause pass cannot end,
// so it neither pauses nor counts a failure nor self-fences.
func TestMsr2_AStuckSettleDoesNotBlockThePauserOfAnotherVM(t *testing.T) {
	m := newLibvirt10(t)
	reg := NewCaptureRegistry()
	h := hangResume{libvirt10: m, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(h.release)
	go func() {
		_, _, _ = CaptureMemorySnapshot(h, "vm", "s1", m.dir+"/s1.vmstate",
			CaptureOptions{Firmware: true, CaptureSuspended: func() error { return nil }, Registry: reg})
	}()
	<-h.entered // settle is in DomainResume, under the registry lock
	ret := make(chan bool, 1)
	go func() {
		_, settled := reg.Hold("other-vm", 50*time.Millisecond)
		ret <- settled
	}()
	select {
	case settled := <-ret:
		// The settle lock is per VM: another VM's stuck settle is not this
		// one's, so its hold settles at once (mutation: one lock for every
		// VM — the hold times out unsettled; red).
		if !settled {
			t.Fatal("the hold of another VM did not settle: it waited on this VM's settle lock")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the pauser's InFlight/Hold (another VM) is blocked behind a capture's settle stuck in a libvirt call")
	}
}

// The same VM's settle stuck in a libvirt call: the pauser's Hold of that VM
// gives up on the settle lock at its deadline and reports the hold
// unsettled, so the pause is counted as failed (and self-fences when armed)
// instead of waiting on libvirt.
//
// Mutation: Hold waits for the settle lock without its deadline — red.
func TestMsr2_AStuckSettleOfTheSameVMIsAnUnsettledHold(t *testing.T) {
	m := newLibvirt10(t)
	reg := NewCaptureRegistry()
	h := hangResume{libvirt10: m, entered: make(chan struct{}), release: make(chan struct{})}
	defer close(h.release)
	go func() {
		_, _, _ = CaptureMemorySnapshot(h, "vm", "s1", m.dir+"/s1.vmstate",
			CaptureOptions{Firmware: true, CaptureSuspended: func() error { return nil }, Registry: reg})
	}()
	<-h.entered // settle is in DomainResume, holding vm's settle lock
	type res struct{ captured, settled bool }
	ret := make(chan res, 1)
	go func() {
		c, s := reg.Hold("vm", 50*time.Millisecond)
		ret <- res{c, s}
	}()
	select {
	case r := <-ret:
		if r.settled {
			t.Fatal("Hold reported settled while the capture's settle was still deciding a resume")
		}
		if !reg.Holding("vm") {
			t.Fatal("the hold was not set")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hold(wait=50ms) is blocked behind the same VM's stuck settle")
	}
}
