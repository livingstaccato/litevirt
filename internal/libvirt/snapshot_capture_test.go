package libvirt

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// capture takes a memory snapshot of the model's domain the way
// CreateLiveSnapshot does, writing the image next to the disks.
func (m *libvirt10) capture(name string, o CaptureOptions) (string, error) {
	m.t.Helper()
	path := filepath.Join(m.dir, "vm-"+name+".vmstate")
	_, _, err := CaptureMemorySnapshot(m, "vm", name, path, o)
	return path, err
}

func (m *libvirt10) mustCapture(name string, o CaptureOptions) string {
	m.t.Helper()
	p, err := m.capture(name, o)
	if err != nil {
		m.t.Fatalf("capture %s: %v", name, err)
	}
	return p
}

func (m *libvirt10) lastCreate() createCall {
	m.t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.qemu.creates) == 0 {
		m.t.Fatal("no snapshot was created")
	}
	return m.qemu.creates[len(m.qemu.creates)-1]
}

func isLive(c createCall) bool {
	return c.flags&uint32(golibvirt.DomainSnapshotCreateLive) != 0
}

// The variants a capture can take, as their options select them.
var captureVariants = []struct {
	name string
	opts CaptureOptions
}{
	{"live", CaptureOptions{}},
	{"firmware", CaptureOptions{Firmware: true, CaptureSuspended: func() error { return nil }}},
}

// The capture keeps the guest in the QEMU process it runs in: no save
// (which ends QEMU) and no restore (which starts a new one). A new process
// would re-take the disk locks and, with a <genid/>, hand the guest a new
// generation ID on every capture (DESIGN §4.1, §7.4).
//
// Mutation: capture through DomainSaveFlags + restoreWithRetry again — red.
func TestCapture_DoesNotRestartQEMU(t *testing.T) {
	for _, v := range captureVariants {
		t.Run(v.name, func(t *testing.T) {
			m := newLibvirt10(t)
			pid, restarts := m.qemu.pid, m.qemu.restarts
			m.mustCapture("s1", v.opts)
			if m.qemu.pid != pid || m.qemu.restarts != restarts {
				t.Fatalf("QEMU restarted: pid %d -> %d, starts %d -> %d", pid, m.qemu.pid, restarts, m.qemu.restarts)
			}
			if m.state() != golibvirt.DomainRunning {
				t.Fatalf("after the capture the domain is %v, want running", m.state())
			}
		})
	}
}

// The guest pauses for less than the old capture, which wrote all of RAM
// and read it all back with the vCPUs stopped (2 × RAM ÷ bandwidth): the
// paused variant writes it once, the live one pauses only for the final
// dirty set.
//
// Mutation: drop LIVE from the live variant — its pause equals a full RAM
// write and the live bound goes red.
func TestCapture_PausesLessThanSaveAndRestore(t *testing.T) {
	for _, v := range captureVariants {
		t.Run(v.name, func(t *testing.T) {
			m := newLibvirt10(t)
			m.qemu.dirtyBps = 64 << 20 // a guest dirtying 64 MiB/s
			full := m.ramTime(m.ramBytes())
			old := 2 * full
			m.mustCapture("s1", v.opts)
			got := m.totalPause()
			if got >= old {
				t.Fatalf("the guest paused %v, no less than the save+restore capture's %v", got, old)
			}
			if got > full {
				t.Fatalf("the guest paused %v, more than one RAM write (%v)", got, full)
			}
			if v.name == "live" && got > qemuDowntime {
				t.Fatalf("a converging live capture paused the guest %v, more than QEMU's downtime limit %v", got, qemuDowntime)
			}
		})
	}
}

// A VM with firmware state takes the paused variant: litevirt stops the
// vCPUs, libvirt writes RAM and switches the disks without LIVE, the
// firmware is captured at that same stopped instant, then the guest
// resumes. Selected by the flag, by the capture hook, and by the domain's
// own <nvram> when the caller said neither.
//
// Mutation: choose the variant without Firmware (or without the hook, or
// without the XML check) — the matching subtest goes red.
func TestCapture_FirmwareVMTakesThePausedVariant(t *testing.T) {
	cases := []struct {
		name  string
		xml   bool
		flag  bool
		hooks bool
	}{
		{"flag", false, true, false},
		{"hook", false, false, true},
		{"nvram in the XML", true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newLibvirt10(t)
			m.qemu.firmware = tc.xml
			var path string
			hookRan := false
			o := CaptureOptions{Firmware: tc.flag}
			if tc.hooks {
				o.CaptureSuspended = func() error {
					hookRan = true
					if st := m.state(); st != golibvirt.DomainPaused {
						t.Errorf("firmware captured while the domain is %v, want paused", st)
					}
					if _, err := os.Stat(path); err != nil {
						t.Errorf("firmware captured before the RAM image was written: %v", err)
					}
					if len(m.qemu.creates) == 0 {
						t.Error("firmware captured before the snapshot was taken")
					}
					return nil
				}
			}
			path = filepath.Join(m.dir, "vm-s1.vmstate")
			if _, _, err := CaptureMemorySnapshot(m, "vm", "s1", path, o); err != nil {
				t.Fatal(err)
			}
			c := m.lastCreate()
			if c.memory != path {
				t.Fatalf("the snapshot's memory went to %q, want %q (an in-process external memory snapshot)", c.memory, path)
			}
			if isLive(c) || !c.pausedBefore {
				t.Fatalf("firmware VM captured live=%v pausedBefore=%v, want the paused variant", isLive(c), c.pausedBefore)
			}
			if tc.hooks && !hookRan {
				t.Fatal("the firmware hook never ran")
			}
			if m.state() != golibvirt.DomainRunning {
				t.Fatalf("after the capture the domain is %v, want running", m.state())
			}
		})
	}
}

// A VM without firmware state whose dirty rate lets the precopy converge
// is captured live: the vCPUs keep running while RAM is written.
//
// Mutation: always choose the paused variant — red.
func TestCapture_ConvergingGuestIsCapturedLive(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.dirtyBps, m.qemu.reportBps = 64<<20, 64<<20
	m.mustCapture("s1", CaptureOptions{})
	c := m.lastCreate()
	if !isLive(c) || c.pausedBefore {
		t.Fatalf("captured live=%v pausedBefore=%v, want a live capture of a running guest", isLive(c), c.pausedBefore)
	}
	if m.qemu.dirtyCalcs != 1 {
		t.Fatalf("dirty rate measured %d times, want once before choosing", m.qemu.dirtyCalcs)
	}
}

// A guest dirtying memory faster than the image can be written would
// never converge: the dirty-rate check predicts it and takes the paused
// variant up front.
//
// Mutation: ignore the measured rate — red (the capture goes live).
func TestCapture_HighDirtyRateTakesThePausedVariant(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.dirtyBps = 2 * m.bps()
	m.qemu.reportBps = m.qemu.dirtyBps
	m.mustCapture("s1", CaptureOptions{})
	c := m.lastCreate()
	if isLive(c) || !c.pausedBefore {
		t.Fatalf("captured live=%v pausedBefore=%v, want paused for a guest that cannot converge", isLive(c), c.pausedBefore)
	}
	if m.state() != golibvirt.DomainRunning {
		t.Fatalf("after the capture the domain is %v, want running", m.state())
	}
}

// A live capture that does not converge (the guest got busier after it
// was measured) is suspended at its deadline, which turns the remainder
// into a stopped copy; the capture completes and the guest runs again.
//
// Mutation: drop the deadline suspend — the model's capture never ends
// and fails; red.
func TestCapture_NonConvergingLiveCaptureIsSuspendedAtTheDeadline(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0          // measured idle
	m.qemu.dirtyBps = 2 * m.bps() // then dirties faster than the write
	start := time.Now()
	m.mustCapture("s1", CaptureOptions{Deadline: 50 * time.Millisecond})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the capture took %v; the deadline did not cut it", took)
	}
	c := m.lastCreate()
	if !isLive(c) {
		t.Fatal("the capture was not live")
	}
	if !m.qemu.suspendInJb {
		t.Fatal("the guest was not suspended during the live capture")
	}
	if m.state() != golibvirt.DomainRunning {
		t.Fatalf("after the capture the domain is %v, want running", m.state())
	}
	if m.qemu.restarts != 1 {
		t.Fatalf("QEMU started %d times, want 1", m.qemu.restarts)
	}
}

// A memory snapshot taken in process reverts like the old ones: its image
// names the disks as they were before the switch (libvirt writes memory
// first), and the revert puts the restored domain on the snapshot's
// overlay, reset over the frozen base.
func TestRevert_AnInProcessMemorySnapshotReverts(t *testing.T) {
	for _, v := range captureVariants {
		t.Run(v.name, func(t *testing.T) {
			m := newLibvirt10(t)
			base := m.active()
			m.write(markA, 1)
			save := m.mustCapture("m1", v.opts)
			ov := m.active()
			if ov == base {
				t.Fatal("the capture did not switch the disk to an overlay")
			}
			m.write(markB, 2)
			m.revertLive("m1", save)
			if !m.has(markA, 1) || m.has(markB, 2) {
				t.Fatalf("after the revert A=%v B=%v, want A only (qemu opens %s)", m.has(markA, 1), m.has(markB, 2), m.qemuSpec("vda"))
			}
			if got := m.active(); got != ov {
				t.Fatalf("the reverted domain runs on %s, want the snapshot's overlay %s", got, ov)
			}
			if m.state() != golibvirt.DomainRunning {
				t.Fatalf("after the revert the domain is %v", m.state())
			}
			m.rm("m1")
		})
	}
}

// Rolling upgrade: a memory snapshot an older node took (disk-only
// snapshot, then a save image naming the new overlays) still reverts
// after this node captures in process, in either order.
//
// Mutation: make the revert require the in-process layout (refuse an
// image whose disks already name the overlay) — red.
func TestRevert_AnOldFormatMemorySnapshotStillReverts(t *testing.T) {
	m := newLibvirt10(t)
	m.write(markA, 1)
	old := m.memorySnapshot("old") // the save+restore layout
	m.write(markB, 2)
	// While it is the newest: its image already names the overlay.
	m.revertLive("old", old)
	if !m.has(markA, 1) || m.has(markB, 2) {
		t.Fatalf("revert to the newest old-format snapshot: A=%v B=%v, want A only", m.has(markA, 1), m.has(markB, 2))
	}
	m.write(markB, 2)
	cur := m.mustCapture("new", CaptureOptions{})
	m.write(markC, 3)

	m.revertLive("old", old)
	if !m.has(markA, 1) || m.has(markB, 2) || m.has(markC, 3) {
		t.Fatalf("revert to the old-format snapshot: A=%v B=%v C=%v, want A only", m.has(markA, 1), m.has(markB, 2), m.has(markC, 3))
	}
	m.revertLive("new", cur)
	if !m.has(markA, 1) || !m.has(markB, 2) || m.has(markC, 3) {
		t.Fatalf("revert to the in-process snapshot: A=%v B=%v C=%v, want A and B", m.has(markA, 1), m.has(markB, 2), m.has(markC, 3))
	}
	m.revertLive("old", old)
	if !m.has(markA, 1) || m.has(markB, 2) {
		t.Fatalf("second revert to the old-format snapshot: A=%v B=%v, want A only", m.has(markA, 1), m.has(markB, 2))
	}
	if err := m.stopAndStart(); err != nil {
		t.Fatal(err)
	}
	if !m.has(markA, 1) || m.has(markB, 2) {
		t.Fatal("after a stop and start the reverted state is gone")
	}
}

// The variant choice, against a 1 GiB guest written at 512 MiB/s (2s per
// full pass) with a 1s budget and a 2m deadline.
//
// Mutation: compare the final pause with QEMU's downtime limit only (drop
// the budget) — the "fits the budget" row goes red; treat an unknown rate
// as paused — the unknown row goes red.
func TestChooseCaptureVariant(t *testing.T) {
	const gib, mib = 1 << 30, 1 << 20
	cases := []struct {
		name  string
		ram   uint64
		dirty float64
		live  bool
	}{
		{"idle guest converges", gib, 0, true},
		{"slow dirtier converges in a few passes", gib, 64 * mib, true},
		{"dirtying as fast as the write never converges", gib, 512 * mib, false},
		{"dirtying faster than the write", gib, 2 * gib, false},
		{"small guest: the stuck final set fits the budget", 256 * mib, 2 * gib, true},
		{"unknown dirty rate: the deadline bounds it", gib, -1, true},
		{"unknown RAM size", 0, 64 * mib, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			live, why := chooseCaptureVariant(tc.ram, tc.dirty, 512*mib, time.Second, 2*time.Minute)
			if live != tc.live {
				t.Fatalf("live = %v (%s), want %v", live, why, tc.live)
			}
		})
	}
	// A deadline shorter than the passes converging: the final set when it
	// fires decides.
	if live, why := chooseCaptureVariant(gib, 400*mib, 512*mib, time.Second, 3*time.Second); live {
		t.Fatalf("converging too slowly for a 3s deadline was chosen live (%s)", why)
	}
}

func TestHasFirmwareStateAndRAM(t *testing.T) {
	for x, want := range map[string]bool{
		"<domain><os><nvram>/v.fd</nvram></os></domain>":                      true,
		"<domain><os><nvram template='/t.fd'/></os></domain>":                 true,
		"<domain><devices><tpm model='tpm-crb'><backend/></tpm></devices>":    true,
		"<domain><os><loader>/c.fd</loader></os><devices></devices></domain>": false,
	} {
		if got := hasFirmwareState(x); got != want {
			t.Errorf("hasFirmwareState(%s) = %v", x, got)
		}
	}
	for x, want := range map[string]uint64{
		"<memory unit='KiB'>1048576</memory>":         1 << 30,
		"<memory>2048</memory>":                       2 << 20,
		`<memory unit="GiB">4</memory>`:               4 << 30,
		"<memory unit='bytes'>4096</memory>":          4096,
		"<currentMemory unit='KiB'>1</currentMemory>": 0,
	} {
		if got := domainRAMBytes("<domain>" + x + "</domain>"); got != want {
			t.Errorf("domainRAMBytes(%s) = %d, want %d", x, got, want)
		}
	}
}

// ── The partition pause wins over a capture (review B1) ──────────────────

// A pauser on the model: takes its hold on the registry (aborting a capture
// in flight and waiting for libvirt's cleanup), then suspends.
func (m *libvirt10) pauseAsPauser(reg *CaptureRegistry, wait time.Duration) (captured, settled bool) {
	captured, settled = reg.Hold("vm", wait)
	if err := m.DomainSuspend(golibvirt.Domain{Name: "vm"}); err != nil {
		m.t.Errorf("pauser suspend: %v", err)
	}
	return captured, settled
}

func (m *libvirt10) liveJobRunning() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.qemu.liveJob
}

// Live variant: the pauser pauses the guest while the precopy runs (the
// domain reads running). The capture's job is aborted, libvirt's cleanup
// resume is over before the pauser suspends, and the guest stays paused.
//
// Mutation: Hold does not abort, or the capture's settle resumes regardless
// of the hold — red.
func TestCapture_PauserDuringALiveCaptureWins(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0
	m.qemu.dirtyBps = 2 * m.bps() // never converges: the job runs until stopped
	reg := NewCaptureRegistry()
	type res struct{ captured, settled bool }
	got := make(chan res, 1)
	go func() {
		for i := 0; i < 5000 && !m.liveJobRunning(); i++ {
			time.Sleep(time.Millisecond)
		}
		c, s := m.pauseAsPauser(reg, 2*time.Second)
		got <- res{c, s}
	}()
	_, err := m.capture("s1", CaptureOptions{Deadline: 5 * time.Second, Registry: reg})
	if err == nil {
		t.Fatal("an aborted capture reported success")
	}
	r := <-got
	if !r.captured || !r.settled || !m.qemu.aborted {
		t.Fatalf("pauser hold: captured=%v settled=%v aborted=%v, want the job aborted and over", r.captured, r.settled, m.qemu.aborted)
	}
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("a guest the pauser paused during a live capture is %v, want paused", st)
	}
	if reg.InFlight("vm") {
		t.Fatal("the capture is still registered")
	}
}

// The job ignores the abort past the pauser's wait: the pauser suspends
// anyway (during the job), libvirt resumes at the end of the job, and the
// capture re-suspends the guest it finds held.
//
// Mutation: drop the re-suspend in the capture's settle — red.
func TestCapture_APauserPastItsWaitIsReSuspended(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0
	m.qemu.dirtyBps = 2 * m.bps()
	m.qemu.abortIgnored = true
	reg := NewCaptureRegistry()
	done := make(chan bool, 1)
	go func() {
		for i := 0; i < 5000 && !m.liveJobRunning(); i++ {
			time.Sleep(time.Millisecond)
		}
		_, settled := m.pauseAsPauser(reg, 20*time.Millisecond)
		done <- settled
	}()
	m.mustCapture("s1", CaptureOptions{Deadline: 5 * time.Second, Registry: reg})
	if settled := <-done; settled {
		t.Fatal("the pauser's wait reported the job over; the scenario needs it past the wait")
	}
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("a held guest is %v after the capture, want paused", st)
	}
}

// Paused variant: the guest reads paused for the whole capture, the pauser
// takes its hold in that window, and the capture's final resume is skipped.
//
// Mutation: resume in the paused variant without consulting the hold — red.
func TestCapture_PauserDuringAPausedCaptureWins(t *testing.T) {
	m := newLibvirt10(t)
	reg := NewCaptureRegistry()
	o := CaptureOptions{Firmware: true, Registry: reg, CaptureSuspended: func() error {
		if !reg.InFlight("vm") {
			t.Error("the capture is not registered while it runs")
		}
		m.pauseAsPauser(reg, time.Second)
		return nil
	}}
	m.mustCapture("s1", o)
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("a guest the pauser paused during the paused capture is %v, want paused", st)
	}
}

// A pause record (the pauser's durable claim) stops every resume too, with
// no hold in this registry: the record was written by a pauser of another
// registry, or before a daemon restart.
//
// Mutation: settle ignores Held — red.
func TestCapture_APauseRecordStopsTheResume(t *testing.T) {
	for _, v := range captureVariants {
		t.Run(v.name, func(t *testing.T) {
			m := newLibvirt10(t)
			o := v.opts
			held := false
			o.Held = func() bool { return held }
			m.qemu.postJob = func() {
				held = true
				_ = m.DomainSuspend(golibvirt.Domain{Name: "vm"})
			}
			m.mustCapture("s1", o)
			if st := m.state(); st != golibvirt.DomainPaused {
				t.Fatalf("a guest with a pause record is %v after the capture, want paused", st)
			}
		})
	}
}

// ── Resume sites (review S3) ─────────────────────────────────────────────

// A guest someone else suspended after libvirt's own resume (no record, no
// hold: an operator) is not the capture's to resume.
//
// Mutation: resume after every live capture (`if suspended` → `if true`) — red.
func TestCapture_LiveDoesNotResumeAGuestItDidNotSuspend(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.postJob = func() { _ = m.DomainSuspend(golibvirt.Domain{Name: "vm"}) }
	m.mustCapture("s1", CaptureOptions{})
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("an operator's pause after the capture is %v, want paused", st)
	}
}

// The deadline's suspend blocks on the job lock until the job (and libvirt's
// resume) is over, then lands: the capture suspended the guest, so it
// resumes it.
//
// Mutation: drop the post-deadline resume — red.
func TestCapture_ADeadlineSuspendThatLandsLateIsResumed(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.slowJob = 200 * time.Millisecond
	m.mustCapture("s1", CaptureOptions{Deadline: 20 * time.Millisecond})
	if st := m.state(); st != golibvirt.DomainRunning {
		t.Fatalf("after a capture whose deadline suspend landed late the guest is %v, want running", st)
	}
}

// A paused capture that fails (the memory write, or the firmware capture)
// resumes the guest it suspended.
//
// Mutation: drop the failure resume of the paused variant — red.
func TestCapture_AFailedPausedCaptureResumesTheGuest(t *testing.T) {
	t.Run("memory write", func(t *testing.T) {
		m := newLibvirt10(t)
		m.qemu.failCreate = fmt.Errorf("operation failed: migration job: unexpectedly failed")
		if _, err := m.capture("s1", CaptureOptions{Firmware: true}); err == nil {
			t.Fatal("a failed memory write reported success")
		}
		if st := m.state(); st != golibvirt.DomainRunning {
			t.Fatalf("after a failed capture the guest is %v, want running", st)
		}
	})
	t.Run("firmware", func(t *testing.T) {
		m := newLibvirt10(t)
		o := CaptureOptions{Firmware: true, CaptureSuspended: func() error { return fmt.Errorf("swtpm state unreadable") }}
		if _, err := m.capture("s1", o); err == nil {
			t.Fatal("a failed firmware capture reported success")
		}
		if st := m.state(); st != golibvirt.DomainRunning {
			t.Fatalf("after a failed capture the guest is %v, want running", st)
		}
	})
}

// A failed deadline suspend aborts the job instead of waiting on it forever
// (review S1).
//
// Mutation: wait on the job after a failed suspend — the model gives up
// after 10s and the capture is slow; red.
func TestCapture_AFailedDeadlineSuspendAbortsTheJob(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0
	m.qemu.dirtyBps = 2 * m.bps()
	start := time.Now()
	_, _, err := CaptureMemorySnapshot(failingSuspend{m}, "vm", "s1", filepath.Join(m.dir, "vm-s1.vmstate"), CaptureOptions{Deadline: 20 * time.Millisecond})
	if err == nil {
		t.Fatal("a capture whose job was aborted reported success")
	}
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the capture took %v", took)
	}
	if st := m.state(); st != golibvirt.DomainRunning {
		t.Fatalf("after the aborted capture the guest is %v, want running", st)
	}
}

type failingSuspend struct{ *libvirt10 }

func (failingSuspend) DomainSuspend(golibvirt.Domain) error {
	return fmt.Errorf("Timed out during operation: cannot acquire state change lock")
}

// ── The image names the overlays (review B2) ────────────────────────────

// libvirt writes the image before the disks switch, so its definition names
// the old disks; the capture rewrites it onto the overlays, the layout every
// build's revert expects (a revert before 0fef47979 restores the image's
// disks as written).
//
// Mutation: skip the rewrite — red.
func TestCapture_TheImageNamesTheOverlays(t *testing.T) {
	m := newLibvirt10Disks(t, 2)
	save := m.mustCapture("s1", CaptureOptions{})
	x, err := m.DomainSaveImageGetXMLDesc(save, 0)
	if err != nil {
		t.Fatal(err)
	}
	disks := parseDomainDiskSources(x)
	for _, dev := range []string{"vda", "vdb"} {
		if disks[dev] != m.activeOf(dev) {
			t.Fatalf("the image's %s is %s, want the overlay %s", dev, disks[dev], m.activeOf(dev))
		}
	}
	if !strings.Contains(x, "litevirt-managed") {
		t.Fatal("the rewrite lost the image's metadata")
	}
}

// ── An unknown dirty rate (review S2) ────────────────────────────────────

// When the dirty rate cannot be measured, the live capture's deadline is
// capped at twice the predicted RAM write (at least a second).
//
// Mutation: keep the configured deadline — the capture waits the model's
// 10s; red.
func TestCapture_AnUnknownDirtyRateCapsTheDeadline(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.ram = 64 << 20
	m.qemu.writeBps = 64 << 20 // a slow disk: the 64 MiB guest never fits the downtime limit
	m.qemu.reportBps = -1
	m.qemu.dirtyBps = 2 * m.bps()
	start := time.Now()
	m.mustCapture("s1", CaptureOptions{Deadline: time.Minute})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the capture took %v; an unknown rate should cap the 1m deadline", took)
	}
	if !m.qemu.suspendInJb {
		t.Fatal("the capture was not suspended at the capped deadline")
	}
}

// A hold taken after the capture's last check, before its libvirt job
// exists: the first abort finds no job, and Hold keeps aborting until the
// job (which admits an abort for its whole length) ends. The pauser's
// suspend then lands after libvirt's cleanup, and libvirt never resumes the
// guest over it.
//
// Mutation: Hold aborts once — its wait runs out, the pauser suspends during
// the job and libvirt resumes the guest at its end; red.
func TestCapture_AHoldBeforeTheJobExistsStillAbortsIt(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0
	m.qemu.dirtyBps = 2 * m.bps()
	reg := NewCaptureRegistry()
	var pauserSuspended, ranAfterPause bool
	var mu sync.Mutex
	pauserDone := make(chan bool, 1)
	m.qemu.preCreate = func() {
		go func() {
			_, settled := reg.Hold("vm", 2*time.Second)
			err := m.DomainSuspend(golibvirt.Domain{Name: "vm"})
			mu.Lock()
			pauserSuspended = err == nil
			mu.Unlock()
			pauserDone <- settled
		}()
		time.Sleep(30 * time.Millisecond) // the first abort finds no job
	}
	m.qemu.postJob = func() {
		mu.Lock()
		defer mu.Unlock()
		if pauserSuspended && m.state() == golibvirt.DomainRunning {
			ranAfterPause = true
		}
	}
	_, _ = m.capture("s1", CaptureOptions{Deadline: 5 * time.Second, Registry: reg})
	settled := <-pauserDone
	if !settled || !m.qemu.aborted {
		t.Fatalf("the hold: settled=%v, job aborted=%v; want the job aborted and over within the wait", settled, m.qemu.aborted)
	}
	if ranAfterPause {
		t.Fatal("libvirt resumed the guest after the pauser's suspend")
	}
	if st := m.state(); st != golibvirt.DomainPaused {
		t.Fatalf("final state %v, want paused", st)
	}
}

// A VM the pauser already holds is not captured at all.
//
// Mutation: drop the refusal at begin — the capture suspends and snapshots
// the held guest; red.
func TestCapture_AHeldVMIsNotCaptured(t *testing.T) {
	for _, v := range captureVariants {
		t.Run(v.name, func(t *testing.T) {
			m := newLibvirt10(t)
			reg := NewCaptureRegistry()
			reg.Hold("vm", time.Second)
			o := v.opts
			o.Registry = reg
			if _, err := m.capture("s1", o); err == nil {
				t.Fatal("a held VM was captured")
			}
			if len(m.qemu.creates) != 0 || m.qemu.dirtyCalcs != 0 || len(m.qemu.pauses) != 0 {
				t.Fatalf("the refused capture acted: creates=%d dirty-rate calcs=%d pauses=%d",
					len(m.qemu.creates), m.qemu.dirtyCalcs, len(m.qemu.pauses))
			}
		})
	}
}

// A hold taken while the capture measures the dirty rate: the capture
// re-checks under the registry's lock before its job and starts none.
//
// Mutation: drop the pre-job check — a LIVE job is started for a held
// guest; red.
func TestCapture_AHoldDuringTheProbeStartsNoJob(t *testing.T) {
	m := newLibvirt10(t)
	m.qemu.reportBps = 0
	reg := NewCaptureRegistry()
	held := false
	captureSleep = func(time.Duration) {
		if !held {
			held = true
			reg.Hold("vm", time.Millisecond) // no job to abort yet
		}
	}
	if _, err := m.capture("s1", CaptureOptions{Registry: reg}); err == nil {
		t.Fatal("a capture held during its probe reported success")
	}
	if n := len(m.qemu.creates); n != 0 {
		t.Fatalf("%d snapshot job(s) started for a held guest", n)
	}
}
