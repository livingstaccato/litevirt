package libvirt

import (
	"os"
	"path/filepath"
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
