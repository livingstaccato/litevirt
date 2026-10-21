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
//     snapshot job, qemu_snapshot.c:1389-1392, and still resumes at the end).

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
}

var _ LiveCaptureAPI = (*golibvirt.Libvirt)(nil)

// CaptureMemorySnapshot takes a memory snapshot of the running domain
// domainName: RAM to vmstatePath, each disk switched to a new overlay, in the
// QEMU process it runs in. It returns the root disk's allocation and the
// image's size. A paused or stopped domain is refused: the capture ends by
// resuming the guest, and a paused domain is paused by someone (an operator,
// or this host's partition pause, docs/design/partition-pause.md §3.3).
func CaptureMemorySnapshot(v LiveCaptureAPI, domainName, snapshotName, vmstatePath string, o CaptureOptions) (diskBytes, vmstateBytes int64, err error) {
	dom, err := v.DomainLookupByName(domainName)
	if err != nil {
		return 0, 0, fmt.Errorf("lookup domain %q: %w", domainName, err)
	}
	state, _, _ := v.DomainGetState(dom, 0)
	if state == int32(golibvirt.DomainPaused) {
		return 0, 0, fmt.Errorf("domain %q is paused — a memory snapshot would resume it; resume it first", domainName)
	}
	if state != int32(golibvirt.DomainRunning) {
		return 0, 0, fmt.Errorf("domain %q is not running — memory snapshot requires a running VM", domainName)
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
		rate := measureDirtyRate(v, dom)
		live, why = chooseCaptureVariant(domainRAMBytes(before), rate, captureWriteBps, budget, deadline)
	}
	snapXML, err := snapshotCreateXMLMemory(v, dom, snapshotName, vmstatePath)
	if err != nil {
		return 0, 0, err
	}
	start := time.Now()
	var suspended bool
	if live {
		suspended, err = captureLive(v, dom, snapXML, deadline)
	} else {
		err = capturePaused(v, dom, snapXML, o.CaptureSuspended)
	}
	if err != nil {
		return 0, 0, err
	}
	if after, aerr := v.DomainGetXMLDesc(dom, 0); aerr == nil {
		narrowNew(newDiskSources(before, after)...)
	}
	narrowNew(vmstatePath) // the guest's RAM
	allocation, _, _, _ := v.DomainGetBlockInfo(dom, "vda", 0)
	if fi, statErr := os.Stat(vmstatePath); statErr == nil {
		vmstateBytes = fi.Size()
	}
	slog.Info("memory snapshot captured in process", "vm", domainName, "snapshot", snapshotName,
		"variant", map[bool]string{true: "live", false: "paused"}[live], "why", why,
		"deadline_suspended", suspended, "took", time.Since(start).Round(time.Millisecond))
	return int64(allocation), vmstateBytes, nil
}

// capturePaused is the paused variant: suspend, snapshot without LIVE (libvirt
// leaves a domain it found paused paused), firmware at the same instant,
// resume. Any failure resumes the guest before it returns.
func capturePaused(v LiveCaptureAPI, dom golibvirt.Domain, snapXML string, captureSuspended func() error) error {
	if err := v.DomainSuspend(dom); err != nil {
		return fmt.Errorf("suspend domain %q: %w", dom.Name, err)
	}
	resumed := false
	defer func() {
		if !resumed {
			_ = v.DomainResume(dom)
		}
	}()
	if _, err := v.DomainSnapshotCreateXML(dom, snapXML, uint32(golibvirt.DomainSnapshotCreateAtomic)); err != nil {
		return fmt.Errorf("memory snapshot: %w", err)
	}
	if captureSuspended != nil {
		if err := captureSuspended(); err != nil {
			return fmt.Errorf("capture firmware state: %w", err)
		}
	}
	resumed = true
	if err := v.DomainResume(dom); err != nil {
		return fmt.Errorf("resume domain %q after the memory snapshot: %w", dom.Name, err)
	}
	return nil
}

// captureLive is the live variant. Past the deadline the guest is
// suspended, so QEMU writes the remainder with the vCPUs stopped; libvirt
// resumes the domain when the snapshot ends, because it was running when the
// snapshot began. A guest still paused afterwards (the suspend landed after
// libvirt's resume, or libvirt's resume failed) is resumed here, since this
// capture paused it. Reports whether the deadline suspended the guest.
func captureLive(v LiveCaptureAPI, dom golibvirt.Domain, snapXML string, deadline time.Duration) (bool, error) {
	done := make(chan error, 1)
	go func() {
		_, err := v.DomainSnapshotCreateXML(dom, snapXML,
			uint32(golibvirt.DomainSnapshotCreateLive|golibvirt.DomainSnapshotCreateAtomic))
		done <- err
	}()
	timer := time.NewTimer(deadline)
	defer timer.Stop()
	var err error
	suspended := false
	select {
	case err = <-done:
	case <-timer.C:
		if serr := v.DomainSuspend(dom); serr != nil {
			slog.Warn("memory snapshot: the live capture passed its deadline and the guest could not be suspended",
				"vm", dom.Name, "deadline", deadline, "error", serr)
		} else {
			suspended = true
			slog.Info("memory snapshot: the live capture passed its deadline; finishing it with the guest suspended",
				"vm", dom.Name, "deadline", deadline)
		}
		err = <-done
	}
	if suspended {
		if st, _, serr := v.DomainGetState(dom, 0); serr == nil && st == int32(golibvirt.DomainPaused) {
			if rerr := v.DomainResume(dom); rerr != nil && err == nil {
				err = fmt.Errorf("resume domain %q after the memory snapshot: %w", dom.Name, rerr)
			}
		}
	}
	if err != nil {
		return suspended, fmt.Errorf("memory snapshot: %w", err)
	}
	return suspended, nil
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
// bytes/s; -1 when it cannot be measured.
func measureDirtyRate(v LiveCaptureAPI, dom golibvirt.Domain) float64 {
	if err := v.DomainStartDirtyRateCalc(dom, dirtyRateCalcSeconds, 0); err != nil {
		slog.Debug("memory snapshot: dirty rate unavailable", "vm", dom.Name, "error", err)
		return -1
	}
	sleep := captureSleep
	if cs, ok := v.(interface{ CaptureSleep(time.Duration) }); ok {
		sleep = cs.CaptureSleep // a model's own clock
	}
	wait := time.Duration(dirtyRateCalcSeconds)*time.Second + 100*time.Millisecond
	for i := 0; i < 4; i++ {
		sleep(wait)
		recs, err := v.ConnectGetAllDomainStats([]golibvirt.Domain{dom}, uint32(golibvirt.DomainStatsDirtyrate), 0)
		if err != nil || len(recs) == 0 {
			return -1
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
			return float64(rate) * (1 << 20)
		}
		wait = 250 * time.Millisecond
	}
	return -1
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
