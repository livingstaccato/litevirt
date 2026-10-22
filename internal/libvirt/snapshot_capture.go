package libvirt

import (
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// A memory snapshot is captured inside the running QEMU process, with
// libvirt's external memory+disk snapshot (virDomainSnapshotCreateXML with
// <memory snapshot='external' file=...>), never by saving the domain and
// restoring it: a save ends QEMU and the restore starts a new one, which
// paused the guest for a RAM write AND a RAM read, re-took the disk locks,
// and would hand a guest with a <genid/> a new generation ID on every
// capture (docs/design: memory snapshots §4.1, §4.2).
//
// libvirt v10.0.0 (src/qemu/qemu_snapshot.c, qemuSnapshotCreateActiveExternal)
// writes the memory through a migration to the file FIRST, then switches the
// disks to their overlays, then resumes a domain that was running when the
// call began; a domain that was paused is left paused. The image is a save
// image whose definition names the disks as they were before the switch,
// which revertToLiveSnapshot already repoints onto the overlays it restores
// on, as it does for the images older litevirt wrote after the switch.
//
// Two variants:
//
//   - paused: litevirt suspends the guest, libvirt writes RAM and switches
//     the disks without LIVE, the firmware (UEFI NVRAM, swtpm) is captured
//     at that same stopped instant, and litevirt resumes. Pause = one RAM
//     write + disk switch + firmware tar. Every VM with firmware state takes
//     it: NVRAM is a pflash file outside the migration stream.
//   - live: VIR_DOMAIN_SNAPSHOT_CREATE_LIVE. QEMU precopies RAM to the file
//     while the guest runs and stops the vCPUs only for the final dirty set
//     and device state. Chosen from the guest's measured dirty rate; one
//     that does not converge is suspended at its deadline, which turns the
//     remainder into a stopped copy (libvirt admits a suspend during the
//     snapshot job's memory write, qemu_snapshot.c:1377-1380 at the v10.0.0
//     tag, and its cleanup still resumes the guest at the end, 1445).

// Capture defaults. All three are design targets until the P1 lab
// measurements replace them [measure].
var (
	// DefaultCapturePauseBudget is the longest predicted guest pause a live
	// capture is chosen for (memory_snapshot.pause_budget).
	DefaultCapturePauseBudget = time.Second
	// DefaultCaptureDeadline is how long a live capture runs before the
	// guest is suspended to finish it (memory_snapshot.live_deadline).
	DefaultCaptureDeadline = 2 * time.Minute
	// captureWriteBps is the bandwidth the prediction assumes for writing
	// the image, bytes/s.
	captureWriteBps float64 = 512 << 20
)

// The dirty-rate measurement: how long QEMU samples, and the wait between
// polls of the result. Variables so the tests run without the real waits.
var (
	dirtyRateCalcSeconds int32 = 1
	captureSleep               = time.Sleep
)

// CaptureOptions shapes one memory snapshot capture (CreateLiveSnapshot).
type CaptureOptions struct {
	// Firmware: the VM has UEFI NVRAM or vTPM state, which lives outside
	// QEMU's migration stream and must be captured while the vCPUs are
	// stopped. Such a VM always takes the paused variant.
	Firmware bool
	// CaptureSuspended, when set, runs while the guest is stopped at the
	// snapshot instant (after RAM and disks are captured, before the
	// resume) to capture firmware state. Setting it selects the paused
	// variant: a live capture has no such instant.
	CaptureSuspended func() error
	// PauseBudget is the longest predicted guest pause a live capture is
	// chosen for; 0 is DefaultCapturePauseBudget.
	PauseBudget time.Duration
	// Deadline bounds a live capture: past it the guest is suspended so the
	// remainder is written with vCPUs stopped. 0 is DefaultCaptureDeadline.
	Deadline time.Duration
	// Registry is this host's capture registry, shared with the partition
	// pauser; nil is a registry of this capture alone.
	Registry *CaptureRegistry
	// Held reports whether the guest has a pause record (the partition
	// pauser paused it): such a guest is never resumed by the capture.
	Held func() bool
}

// LiveCaptureAPI is the part of libvirt a memory snapshot capture uses. It
// is *golibvirt.Libvirt in production; libvirtfake and the tests' libvirt
// 10.0 model implement it to run the same capture.
type LiveCaptureAPI interface {
	DomainLookupByName(name string) (golibvirt.Domain, error)
	DomainGetState(dom golibvirt.Domain, flags uint32) (int32, int32, error)
	DomainGetXMLDesc(dom golibvirt.Domain, flags golibvirt.DomainXMLFlags) (string, error)
	DomainListAllSnapshots(dom golibvirt.Domain, needResults int32, flags uint32) ([]golibvirt.DomainSnapshot, int32, error)
	DomainSnapshotCreateXML(dom golibvirt.Domain, xml string, flags uint32) (golibvirt.DomainSnapshot, error)
	DomainSuspend(dom golibvirt.Domain) error
	DomainResume(dom golibvirt.Domain) error
	DomainGetBlockInfo(dom golibvirt.Domain, path string, flags uint32) (uint64, uint64, uint64, error)
	DomainStartDirtyRateCalc(dom golibvirt.Domain, seconds int32, flags uint32) error
	ConnectGetAllDomainStats(doms []golibvirt.Domain, stats uint32, flags uint32) ([]golibvirt.DomainStatsRecord, error)
	DomainAbortJob(dom golibvirt.Domain) error
	DomainSaveImageGetXMLDesc(file string, flags uint32) (string, error)
	DomainSaveImageDefineXML(file string, dxml string, flags uint32) error
}

var _ LiveCaptureAPI = (*golibvirt.Libvirt)(nil)

// CaptureMemorySnapshot takes a memory snapshot of the running domain
// domainName: RAM to vmstatePath, each disk switched to a new overlay, in the
// QEMU process it runs in. It returns the root disk's allocation and the
// image's size. A paused or stopped domain is refused: the capture ends by
// resuming the guest, and a paused domain is paused by someone (an operator,
// or this host's partition pause, docs/design/partition-pause.md §3.3).
//
// The partition pause wins over the capture (CaptureRegistry). The capture
// is registered while it runs; it never resumes a guest that the pauser
// holds or that has a pause record (o.Held), and re-suspends one it finds
// running then. Otherwise it resumes only a guest it suspended itself.
//
// An error that comes before libvirt switched any disk is a
// *CaptureNotTakenError: nothing was taken, and there is nothing to record or
// clean up.
func CaptureMemorySnapshot(v LiveCaptureAPI, domainName, snapshotName, vmstatePath string, o CaptureOptions) (diskBytes, vmstateBytes int64, err error) {
	// Running, not paused, and no device whose state cannot be saved: a
	// passthrough device is refused here, before the registry, the probe
	// or any suspend (*PassthroughSnapshotError).
	dom, err := liveSnapshotPreflight(v, domainName)
	if err != nil {
		return 0, 0, notTaken(err)
	}
	reg := o.Registry
	if reg == nil {
		reg = NewCaptureRegistry()
	}
	e, err := reg.begin(domainName, func() error { return v.DomainAbortJob(dom) })
	if err != nil {
		return 0, 0, notTaken(err)
	}
	defer reg.end(domainName, e)
	held := false
	reg.settle(domainName, o.Held, func(h bool) { held = h })
	if held {
		return 0, 0, notTaken(fmt.Errorf("domain %q is held paused by this host's partition pause — no memory snapshot", domainName))
	}

	budget, deadline := o.PauseBudget, o.Deadline
	if budget <= 0 {
		budget = DefaultCapturePauseBudget
	}
	if deadline <= 0 {
		deadline = DefaultCaptureDeadline
	}
	before, _ := v.DomainGetXMLDesc(dom, 0)

	live, why := false, "firmware state is captured with the vCPUs stopped"
	if !o.Firmware && o.CaptureSuspended == nil && !hasFirmwareState(before) {
		ram := domainRAMBytes(before)
		rate, rerr := measureDirtyRate(v, dom)
		if rerr != nil {
			// The live capture is then bounded only by its deadline: cap it
			// at twice the predicted RAM write, so a guest that will not
			// converge is not precopied for the whole configured deadline.
			if c := unknownRateDeadline(ram); c < deadline {
				deadline = c
			}
			slog.Warn("memory snapshot: the guest's dirty rate could not be measured; capturing live with a capped deadline",
				"vm", domainName, "deadline", deadline, "error", rerr)
		}
		live, why = chooseCaptureVariant(ram, rate, captureWriteBps, budget, deadline)
	}
	snapXML, err := snapshotCreateXMLMemory(v, dom, snapshotName, vmstatePath)
	if err != nil {
		return 0, 0, notTaken(err)
	}
	start := time.Now()
	c := &capture{v: v, dom: dom, reg: reg, e: e, held: o.Held}
	if live {
		err = c.live(snapXML, deadline)
	} else {
		err = c.paused(snapXML, o.CaptureSuspended)
	}
	if serr := c.settle(); serr != nil && err == nil {
		err = serr
	}
	if err != nil {
		if !c.switched(before) {
			return 0, 0, notTaken(err)
		}
		return 0, 0, err
	}
	after, aerr := v.DomainGetXMLDesc(dom, 0)
	if aerr == nil {
		narrowNew(newDiskSources(before, after)...)
		if rerr := rewriteImageOntoOverlays(v, vmstatePath, before, after); rerr != nil {
			slog.Warn("memory snapshot: the image still names the disks as they were before the snapshot; "+
				"a revert by a build without the overlay repoint (0fef47979) would restore onto them",
				"vm", domainName, "snapshot", snapshotName, "error", rerr)
		}
	}
	narrowNew(vmstatePath) // the guest's RAM
	allocation, _, _, _ := v.DomainGetBlockInfo(dom, "vda", 0)
	if fi, statErr := os.Stat(vmstatePath); statErr == nil {
		vmstateBytes = fi.Size()
	}
	slog.Info("memory snapshot captured in process", "vm", domainName, "snapshot", snapshotName,
		"variant", map[bool]string{true: "live", false: "paused"}[live], "why", why,
		"deadline_suspended", c.suspended, "took", time.Since(start).Round(time.Millisecond))
	return int64(allocation), vmstateBytes, nil
}

// unknownRateDeadline caps a live capture whose guest's dirty rate is
// unknown: twice the predicted write of its RAM, at least a second; the
// configured deadline when its RAM is unknown too.
func unknownRateDeadline(ram uint64) time.Duration {
	if ram == 0 {
		return DefaultCaptureDeadline
	}
	d := time.Duration(2 * float64(ram) / captureWriteBps * float64(time.Second))
	if d < time.Second {
		d = time.Second
	}
	return d
}

// capture is one capture's resume bookkeeping.
type capture struct {
	v    LiveCaptureAPI
	dom  golibvirt.Domain
	reg  *CaptureRegistry
	e    *captureEntry
	held func() bool
	// suspended: this capture suspended the guest (the paused variant, or a
	// live capture's deadline), so it may resume it — unless it is held.
	suspended bool
	// jobIssued: the libvirt create call was made; jobOK: it returned
	// success, so the disks are on their overlays.
	jobIssued, jobOK bool
}

// switched reports whether a failed capture may have left the disks on new
// overlays: the create call succeeded, or it failed and the domain's disk
// sources (or the lack of a readable before/after) do not show every disk
// where it was. Only a capture whose job was never issued, or whose job
// failed with every disk provably unmoved, took nothing.
func (c *capture) switched(beforeXML string) bool {
	if c.jobOK {
		return true
	}
	if !c.jobIssued {
		return false
	}
	if len(parseDomainDiskSources(beforeXML)) == 0 {
		return true // cannot tell: treat as taken
	}
	after, err := c.v.DomainGetXMLDesc(c.dom, 0)
	if err != nil || len(parseDomainDiskSources(after)) == 0 {
		return true
	}
	return len(newDiskSources(beforeXML, after)) > 0
}

// CaptureNotTakenError is a memory snapshot that failed before libvirt
// switched any disk: refused (a pause hold, a passthrough device, a firmware
// move), or failed in libvirt's own pre-switch steps (the memory write). No
// overlay, libvirt snapshot or image was left, so there is no snapshot to
// record; the guest is left as the capture found it (or as the partition
// pause holds it).
type CaptureNotTakenError struct{ Err error }

func (e *CaptureNotTakenError) Error() string { return e.Err.Error() }
func (e *CaptureNotTakenError) Unwrap() error { return e.Err }

// NotTakenCapture wraps err as a capture that took nothing
// (*CaptureNotTakenError); nil stays nil.
func NotTakenCapture(err error) error { return notTaken(err) }

func notTaken(err error) error {
	if err == nil {
		return nil
	}
	return &CaptureNotTakenError{Err: err}
}

// settle is every capture's end, success or failure, under the registry's
// lock: a held guest (the pauser's hold, or a pause record) is never resumed
// and is re-suspended if it runs (libvirt's own cleanup resumes a guest that
// was running when the snapshot began); otherwise a guest this capture
// suspended and finds paused is resumed.
func (c *capture) settle() error {
	var err error
	c.reg.settle(c.dom.Name, c.held, func(held bool) {
		st, _, serr := c.v.DomainGetState(c.dom, 0)
		if serr != nil {
			err = fmt.Errorf("read domain %q state after the memory snapshot: %w", c.dom.Name, serr)
			return
		}
		if held {
			if st == int32(golibvirt.DomainRunning) {
				if serr := c.v.DomainSuspend(c.dom); serr != nil {
					err = fmt.Errorf("re-suspend partition-paused domain %q after the memory snapshot: %w", c.dom.Name, serr)
				}
			}
			slog.Warn("memory snapshot: the guest is held by this host's partition pause; the capture leaves it paused",
				"vm", c.dom.Name)
			return
		}
		if c.suspended && st == int32(golibvirt.DomainPaused) {
			if rerr := c.v.DomainResume(c.dom); rerr != nil {
				err = fmt.Errorf("resume domain %q after the memory snapshot: %w", c.dom.Name, rerr)
			}
		}
	})
	return err
}

// preJob refuses to start the libvirt job once the pauser holds the guest,
// or has preempted the capture at the start of its pass: a hold taken while
// the capture measured the dirty rate found no job to abort, and a LIVE job
// started after it would be resumed by libvirt's cleanup over the pauser's
// suspend. A hold or preemption after this check aborts the job (the abort
// repeats until the create call returns).
func (c *capture) preJob() error {
	var err error
	c.reg.settle(c.dom.Name, c.held, func(held bool) {
		switch {
		case held:
			err = fmt.Errorf("domain %q is held by this host's partition pause — memory snapshot abandoned", c.dom.Name)
		case c.e.preempted():
			err = fmt.Errorf("domain %q is about to be paused by this host's partition pause — memory snapshot abandoned", c.dom.Name)
		}
	})
	return err
}

// paused is the paused variant: suspend, snapshot without LIVE (libvirt
// leaves a domain it found paused paused), firmware at the same instant;
// settle resumes.
func (c *capture) paused(snapXML string, captureSuspended func() error) error {
	if err := c.v.DomainSuspend(c.dom); err != nil {
		return fmt.Errorf("suspend domain %q: %w", c.dom.Name, err)
	}
	c.suspended = true
	if err := c.preJob(); err != nil {
		return err
	}
	c.jobIssued = true
	_, err := c.v.DomainSnapshotCreateXML(c.dom, snapXML, uint32(golibvirt.DomainSnapshotCreateAtomic))
	c.jobOK = err == nil
	c.e.jobDone()
	if err != nil {
		return fmt.Errorf("memory snapshot: %w", err)
	}
	if captureSuspended != nil {
		if err := captureSuspended(); err != nil {
			return fmt.Errorf("capture firmware state: %w", err)
		}
	}
	return nil
}

// live is the live variant. Past the deadline the guest is suspended, so
// QEMU writes the remainder with the vCPUs stopped; libvirt resumes the
// domain when the snapshot ends, because it was running when the snapshot
// began, and a suspend that lands after that resume is undone by settle. A
// suspend that fails aborts the job instead (libvirt's cleanup resumes the
// guest), rather than waiting on a job that will not end.
func (c *capture) live(snapXML string, deadline time.Duration) error {
	if err := c.preJob(); err != nil {
		c.e.jobDone()
		return err
	}
	c.jobIssued = true
	done := make(chan error, 1)
	go func() {
		_, err := c.v.DomainSnapshotCreateXML(c.dom, snapXML,
			uint32(golibvirt.DomainSnapshotCreateLive|golibvirt.DomainSnapshotCreateAtomic))
		c.e.jobDone()
		done <- err
	}()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	var err error
	select {
	case err = <-done:
	case <-timer.C:
		if serr := c.v.DomainSuspend(c.dom); serr != nil {
			slog.Warn("memory snapshot: the live capture passed its deadline and the guest could not be suspended; aborting it",
				"vm", c.dom.Name, "deadline", deadline, "error", serr)
			if aerr := c.v.DomainAbortJob(c.dom); aerr != nil {
				slog.Warn("memory snapshot: abort of the live capture failed", "vm", c.dom.Name, "error", aerr)
			}
		} else {
			c.suspended = true
			slog.Info("memory snapshot: the live capture passed its deadline; finishing it with the guest suspended",
				"vm", c.dom.Name, "deadline", deadline)
		}
		err = <-done
	}
	c.jobOK = err == nil
	if err != nil {
		return fmt.Errorf("memory snapshot: %w", err)
	}
	return nil
}

// rewriteImageOntoOverlays makes the image's definition name each disk's
// overlay instead of the disk the snapshot was taken of: libvirt writes the
// image before it switches the disks. Every build's revert then restores
// onto the overlay, including one without repointRevertedDisk, which
// restores the image's disks as written and would write into the snapshot's
// base. Only disk sources change, which libvirt's ABI check accepts.
func rewriteImageOntoOverlays(v LiveCaptureAPI, path, beforeXML, afterXML string) error {
	before, after := parseDomainDiskSources(beforeXML), parseDomainDiskSources(afterXML)
	x, err := v.DomainSaveImageGetXMLDesc(path, uint32(golibvirt.DomainSaveImageXMLSecure))
	if err != nil {
		return err
	}
	saved := parseDomainDiskSources(x)
	out := x
	for _, dev := range sortedDevs(after) {
		if after[dev] == before[dev] || saved[dev] == after[dev] {
			continue
		}
		if out, err = repointRevertedDisk(out, dev, after[dev]); err != nil {
			return err
		}
	}
	if out == x {
		return nil
	}
	return v.DomainSaveImageDefineXML(path, out, 0)
}

// chooseCaptureVariant predicts a live capture of a guest with ram bytes
// dirtying dirtyBps (< 0: unknown) against an image written at writeBps, and
// returns whether to capture live, and why.
//
// The precopy writes all of RAM, then each pass writes what the guest
// dirtied during the one before, until the remainder fits QEMU's downtime
// limit and QEMU stops the vCPUs for it (live wins). If the passes stop
// shrinking, or the deadline arrives first, the final set is what remains
// then; live is still chosen when writing it fits the pause budget, and
// the paused variant (one stopped RAM write, no wasted precopy) otherwise.
func chooseCaptureVariant(ram uint64, dirtyBps, writeBps float64, budget, deadline time.Duration) (bool, string) {
	if dirtyBps < 0 {
		return true, "dirty rate unknown; the deadline bounds the pause"
	}
	if ram == 0 || writeBps <= 0 {
		return true, "RAM size unknown; the deadline bounds the pause"
	}
	set := float64(ram)
	elapsed := 0.0
	for pass := 1; pass <= 64; pass++ {
		t := set / writeBps
		elapsed += t
		next := dirtyBps * t
		if next > float64(ram) {
			next = float64(ram)
		}
		final := time.Duration(next / writeBps * float64(time.Second))
		if final <= qemuDowntimeLimit {
			return true, fmt.Sprintf("predicted to converge after %d pass(es), %.1fs", pass, elapsed)
		}
		if next >= set || elapsed >= deadline.Seconds() {
			if final <= budget {
				return true, fmt.Sprintf("predicted final pause %v is within the budget %v", final.Round(time.Millisecond), budget)
			}
			return false, fmt.Sprintf("predicted final pause %v exceeds the budget %v (guest dirties %.0f MiB/s)",
				final.Round(time.Millisecond), budget, dirtyBps/(1<<20))
		}
		set = next
	}
	return false, "predicted not to converge"
}

// qemuDowntimeLimit is QEMU's default downtime-limit: a precopy switches
// over once the remainder fits it. litevirt does not change it for a
// snapshot (a migration parameter outlives the job).
const qemuDowntimeLimit = 300 * time.Millisecond

// measureDirtyRate asks QEMU for the guest's dirty rate (libvirt 7.2:
// virDomainStartDirtyRateCalc, then the "dirtyrate" stats group), in
// bytes/s; -1 and why when it cannot be measured.
func measureDirtyRate(v LiveCaptureAPI, dom golibvirt.Domain) (float64, error) {
	if err := v.DomainStartDirtyRateCalc(dom, dirtyRateCalcSeconds, 0); err != nil {
		return -1, fmt.Errorf("start dirty rate calculation: %w", err)
	}
	sleep := captureSleep
	if cs, ok := v.(interface{ CaptureSleep(time.Duration) }); ok {
		sleep = cs.CaptureSleep // a model's own clock
	}
	wait := time.Duration(dirtyRateCalcSeconds)*time.Second + 100*time.Millisecond
	for i := 0; i < 4; i++ {
		sleep(wait)
		recs, err := v.ConnectGetAllDomainStats([]golibvirt.Domain{dom}, uint32(golibvirt.DomainStatsDirtyrate), 0)
		if err != nil {
			return -1, fmt.Errorf("read the dirty rate: %w", err)
		}
		if len(recs) == 0 {
			return -1, fmt.Errorf("read the dirty rate: no stats for the domain")
		}
		status, rate := int64(-1), int64(-1)
		for _, p := range recs[0].Params {
			switch p.Field {
			case golibvirt.DomainStatsDirtyrateCalcStatus:
				status = typedInt(p.Value.I)
			case golibvirt.DomainStatsDirtyrateMegabytesPerSecond:
				rate = typedInt(p.Value.I)
			}
		}
		if status == 2 && rate >= 0 { // VIR_DOMAIN_DIRTYRATE_MEASURED
			return float64(rate) * (1 << 20), nil
		}
		wait = 250 * time.Millisecond
	}
	return -1, fmt.Errorf("the dirty rate calculation did not finish")
}

func typedInt(i interface{}) int64 {
	switch n := i.(type) {
	case int32:
		return int64(n)
	case uint32:
		return int64(n)
	case int64:
		return n
	case uint64:
		return int64(n)
	}
	return -1
}

var (
	nvramRe  = regexp.MustCompile(`<nvram[\s/>]`)
	tpmRe    = regexp.MustCompile(`<tpm[\s/>]`)
	memoryRe = regexp.MustCompile(`<memory(?:\s+unit=['"]([A-Za-z]+)['"])?\s*>\s*(\d+)\s*</memory>`)
)

// hasFirmwareState reports whether a domain definition carries state outside
// QEMU's migration stream that a memory snapshot must capture with the vCPUs
// stopped: UEFI NVRAM or a TPM.
func hasFirmwareState(domXML string) bool {
	return nvramRe.MatchString(domXML) || tpmRe.MatchString(domXML)
}

// domainRAMBytes is the domain's <memory> in bytes, 0 when unknown.
func domainRAMBytes(domXML string) uint64 {
	m := memoryRe.FindStringSubmatch(domXML)
	if m == nil {
		return 0
	}
	n, err := strconv.ParseUint(m[2], 10, 64)
	if err != nil {
		return 0
	}
	switch strings.ToLower(m[1]) {
	case "b", "bytes":
		return n
	case "", "k", "kib":
		return n << 10
	case "kb":
		return n * 1000
	case "m", "mib":
		return n << 20
	case "mb":
		return n * 1000 * 1000
	case "g", "gib":
		return n << 30
	case "gb":
		return n * 1000 * 1000 * 1000
	case "t", "tib":
		return n << 40
	}
	return 0
}
