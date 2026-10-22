package libvirt

import (
	"math/rand"
	"sync"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// msr2 adversarial interleavings: the pauser (Hold, then suspend) lands at a
// random instant across a capture's whole life (probe, pre-job gap, job,
// deadline suspend, cleanup, settle, tail). Once the pauser's suspend has
// succeeded with a settled hold, nothing may run the vCPUs again.
func TestMsr2_PauserAtAnyInstantIsNeverResumed(t *testing.T) {
	type scen struct {
		name      string
		opts      CaptureOptions
		dirty     float64 // x bps
		deadline  time.Duration
		failFirst bool
	}
	scens := []scen{
		{"live-nonconverging-deadline", CaptureOptions{}, 2, 20 * time.Millisecond, false},
		{"live-nonconverging-long", CaptureOptions{}, 2, time.Second, false},
		{"live-converging", CaptureOptions{}, 0, 5 * time.Second, false},
		{"paused-firmware", CaptureOptions{Firmware: true, CaptureSuspended: func() error { time.Sleep(time.Millisecond); return nil }}, 0, 5 * time.Second, false},
		{"live-createfails", CaptureOptions{}, 0, 5 * time.Second, true},
	}
	rng := rand.New(rand.NewSource(42))
	for _, sc := range scens {
		t.Run(sc.name, func(t *testing.T) {
			viol, unsettled, iters := 0, 0, 60
			for i := 0; i < iters; i++ {
				m := newLibvirt10(t)
				m.qemu.reportBps = 0
				m.qemu.dirtyBps = sc.dirty * m.bps()
				if sc.failFirst {
					m.qemu.failCreate = errTestCreate
				}
				captureSleep = func(time.Duration) { time.Sleep(2 * time.Millisecond) }
				reg := NewCaptureRegistry()
				delay := time.Duration(rng.Intn(40000)) * time.Microsecond
				var mu sync.Mutex
				suspendedAt := -1
				settledOK := true
				done := make(chan struct{})
				go func() {
					defer close(done)
					time.Sleep(delay)
					// The hold's wait: well under the 1s-deadline scenario's job,
					// which only an abort ends; elsewhere nothing but
					// scheduling stands between the hold and the job's end,
					// so a loaded -race host gets a full second.
					wait := time.Second
					if sc.deadline == time.Second {
						wait = 500 * time.Millisecond
					}
					_, settled := reg.Hold("vm", wait)
					err := m.DomainSuspend(golibvirt.Domain{Name: "vm"})
					m.mu.Lock()
					n := len(m.qemu.pauses)
					m.mu.Unlock()
					mu.Lock()
					settledOK = settled
					if err == nil {
						suspendedAt = n
					}
					mu.Unlock()
				}()
				_, _ = m.capture("s1", CaptureOptions{Firmware: sc.opts.Firmware, CaptureSuspended: sc.opts.CaptureSuspended, Deadline: sc.deadline, Registry: reg})
				<-done
				mu.Lock()
				if !settledOK {
					unsettled++ // the model honours every abort: a hold must settle
					t.Errorf("iter %d delay %v: the hold did not settle although libvirt honours the abort", i, delay)
				} else if suspendedAt >= 0 {
					m.mu.Lock()
					n := len(m.qemu.pauses)
					st := m.dom.state
					m.mu.Unlock()
					if n != suspendedAt || st != golibvirt.DomainPaused {
						viol++
						t.Errorf("iter %d delay %v: resumed after the pauser's suspend (pauses %d -> %d, state %v)", i, delay, suspendedAt, n, st)
					}
				}
				mu.Unlock()
			}
			t.Logf("%s: %d iterations, %d violations, %d unsettled holds", sc.name, iters, viol, unsettled)
		})
	}
}

var errTestCreate = &testCreateErr{}

type testCreateErr struct{}

func (*testCreateErr) Error() string { return "model: create failed" }

// Hold must be bounded by its wait even when libvirt does not answer the
// abort (a job lock held by another call, a wedged libvirtd): the pauser's
// pass waits for every Hold, and only a pass that ends can count a failed
// pause and self-fence.
func TestMsr2_HoldIsBoundedWhenTheAbortHangs(t *testing.T) {
	reg := NewCaptureRegistry()
	block := make(chan struct{})
	defer close(block)
	e, err := reg.begin("vm", func() error { <-block; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer reg.end("vm", e)
	ret := make(chan bool, 1)
	go func() { _, settled := reg.Hold("vm", 50*time.Millisecond); ret <- settled }()
	select {
	case s := <-ret:
		if s {
			t.Fatal("settled with the job still running")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Hold(wait=50ms) has not returned after 2s: an abort that libvirt does not answer blocks it, and with it the pause pass")
	}
}
