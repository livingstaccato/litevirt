package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"slices"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// nvramFlushEvaluator raises the conditions about this host's UEFI vars
// flusher (libvirt.NvramFlusher).
const nvramFlushEvaluator = libvirt.NvramFlushEvaluator

// CondNvramFlushFailed is raised by a node about itself while an fsync of a
// UEFI vars file on it has failed. A file stops counting only once it is
// removed or replaced, or an admin acknowledges that its store may be stale
// (`lv health resolve nvram_flush_failed host/<host> --accept-stale-uefi-vars`),
// which covers the failure episodes the condition named when resolved:
// the kernel reports a writeback error once and marks the lost pages clean,
// and qemu writes back only the sectors a later guest write changes, so no
// later fsync puts the lost pages back.
const CondNvramFlushFailed = libvirt.CondNvramFlushFailed

// CondNvramFlushBlocked is raised by a node about itself while a UEFI vars
// file on it has not been openable for its fsync for longer than a minute,
// and resolved once every such file is flushed again (or gone).
const CondNvramFlushBlocked = "nvram_flush_blocked"

// CondNvramFlushUnrecorded is raised by a node about itself while a failed
// vars fsync is not yet in its state file
// (<data_dir>/nvram-flush-failures.json), which it cannot write.
const CondNvramFlushUnrecorded = "nvram_flush_unrecorded"

// nvramFlushConditionEvery is how often the condition follows the flusher.
const nvramFlushConditionEvery = 10 * time.Second

const nvramFlushRemedy = "the listed vars files may be missing UEFI variable writes their guests made. " +
	"Check the disk (dmesg, smartctl). Writing the variables again in the guest does not clear this, " +
	"and stopping the VM does not write its store out again. Ways out: " +
	"for a Secure Boot or vTPM VM, lv snapshot restore <vm> <name> from a snapshot taken before the failure, " +
	"which replaces its vars file; for any VM, lv rm <vm> without --keep-disks, which removes it; " +
	"or, for a VM kept as it is, an admin's acknowledgement that its vars store may be stale: " +
	"lv health resolve nvram_flush_failed host/<host> --accept-stale-uefi-vars --reason <why>"

const nvramFlushUnrecordedRemedy = "the listed failed vars flushes are not in <data_dir>/nvram-flush-failures.json, " +
	"which this host could not write; they are kept here, and named in nvram_flush_failed, until it can. " +
	"Fix the data directory's filesystem (dmesg, df); the condition clears once the file is written"

const nvramFlushBlockedRemedy = "the listed vars files or directories could not be opened, read or fsynced, " +
	"or an fsync has not returned, so the guests' UEFI variable writes are not being made durable; " +
	"the error says why. Fix that cause (permissions, open-file limits, the entry's type, the disk); " +
	"the condition clears once each is flushed again"

type nvramFlushEvidence struct {
	Files  []libvirt.NvramFlushFailure `json:"files"`
	Remedy string                      `json:"remedy"`
}

// nvramDirs are where this host's UEFI vars files live: libvirt's default
// (UEFI VMs) and litevirt's own (libvirt.NvramPath, Secure Boot and vTPM VMs).
func nvramDirs(dataDir string) []string {
	dirs := []string{health.LibvirtNvramDir}
	if dataDir != "" {
		dirs = append(dirs, filepath.Dir(libvirt.NvramPath(dataDir, "x")))
	}
	return dirs
}

// nvramFinalSweepWait bounds how long a stopping daemon waits for the
// flusher's last sweep.
const nvramFinalSweepWait = 5 * time.Second

// startNvramFlusher starts flushing this host's UEFI vars files, after
// carrying over the failures this host recorded in its data directory. It
// needs nothing but the data directory, so it runs from the start of Run.
// stop ends it with one last sweep and waits for that, bounded.
func (d *Daemon) startNvramFlusher(ctx context.Context) (f *libvirt.NvramFlusher, stop func()) {
	f = libvirt.NewNvramFlusher(nvramDirs(d.cfg.DataDir)...)
	if d.cfg.DataDir != "" {
		f.LoadState(filepath.Join(d.cfg.DataDir, libvirt.NvramFlushStateFile))
	}
	fctx, cancel := context.WithCancel(ctx)
	go f.Run(fctx, libvirt.NvramFlushInterval)
	return f, func() { stopAndWait(cancel, f.Done(), nvramFinalSweepWait) }
}

// readNvramFlushCondition reads this host's condition (a variable so tests
// can fail it).
var readNvramFlushCondition = corrosion.GetHealthCondition

// nvramConditionState is what runNvramFlushCondition carries between ticks.
type nvramConditionState struct {
	seeded bool // the open condition's failures were handed to the flusher
	// holdResolve: the open condition's evidence could not be parsed, so its
	// failures are unknown; it is never resolved, only rewritten by a new
	// failure.
	holdResolve             bool
	lastFailed, lastBlocked string // what each condition was last written as
	lastUnrecorded          string
	// openFiles: the failures nvram_flush_failed was last written open with.
	// If it is found resolved while they are, an admin acknowledged them.
	openFiles []libvirt.NvramFlushFailure
}

// runNvramFlushCondition keeps nvram_flush_failed and nvram_flush_blocked in
// step with the flusher, after carrying over the failures an earlier run
// recorded.
func (d *Daemon) runNvramFlushCondition(ctx context.Context, f *libvirt.NvramFlusher) {
	var st nvramConditionState
	t := time.NewTicker(nvramFlushConditionEvery)
	defer t.Stop()
	for {
		d.nvramFlushTick(ctx, f, &st)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// nvramFlushTick is one pass: the seed until it has been read, then both
// conditions. Nothing is resolved before the seed is read.
func (d *Daemon) nvramFlushTick(ctx context.Context, f *libvirt.NvramFlusher, st *nvramConditionState) {
	if !st.seeded {
		if err := d.seedNvramFlushFailures(ctx, f, st); err != nil {
			slog.Warn("could not read the nvram_flush_failed condition; retried before the condition is touched", "error", err)
			return
		}
		st.seeded = true
	}
	if len(st.openFiles) > 0 {
		row, found, err := readNvramFlushCondition(ctx, d.db, nvramFlushEvaluator, CondNvramFlushFailed, "host", d.cfg.HostName)
		if err == nil && found && row.Lifecycle == corrosion.ConditionResolved {
			// An admin resolved it: drop only the failure episodes the
			// resolved row named (and the audit recorded), matched on path,
			// inode and episode. The rest is raised again below; so is
			// everything if the row cannot be read.
			var ev nvramFlushEvidence
			if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
				slog.Error("nvram_flush_failed was resolved but its evidence cannot be read; nothing is acknowledged and it is raised again", "error", err)
			} else {
				f.Acknowledge(acknowledgedFiles(st.openFiles, ev.Files))
			}
			st.openFiles, st.lastFailed = nil, ""
		}
	}
	failed := f.Failures()
	if len(failed) > 0 {
		st.holdResolve = false
	}
	// A failure the state file lacks is named in nvram_flush_failed, which a
	// resolve overwrites, only once nvram_flush_unrecorded (which no resolve
	// touches) holds it; a restart carries it over from there.
	unrec := f.Unrecorded()
	d.syncNvramCondition(ctx, CondNvramFlushUnrecorded, corrosion.SeverityCritical, unrec, nvramFlushUnrecordedRemedy, &st.lastUnrecorded)
	if b, _ := json.Marshal(unrec); string(b) != st.lastUnrecorded {
		failed = withoutFailures(failed, unrec)
	}
	if !st.holdResolve {
		d.syncNvramCondition(ctx, CondNvramFlushFailed, corrosion.SeverityCritical, failed, nvramFlushRemedy, &st.lastFailed)
		if b, _ := json.Marshal(failed); string(b) == st.lastFailed {
			st.openFiles = failed
		}
	}
	d.syncNvramCondition(ctx, CondNvramFlushBlocked, corrosion.SeverityWarning, f.Blocked(), nvramFlushBlockedRemedy, &st.lastBlocked)
}

// seedNvramFlushFailures hands the flusher the failures the open condition
// names, so a restart does not forget a write that never reached disk. The
// flusher already holds those this host recorded itself (LoadState); a
// resolved condition acknowledges, of those, only the episodes it names, so a
// resolve written over newer evidence (a stale read, a lagging replica)
// drops nothing it did not name, across a restart too. A read error is
// returned, to be retried.
func (d *Daemon) seedNvramFlushFailures(ctx context.Context, f *libvirt.NvramFlusher, st *nvramConditionState) error {
	// Failures the state file never recorded: no resolve touches this row.
	urow, ufound, err := readNvramFlushCondition(ctx, d.db, nvramFlushEvaluator, CondNvramFlushUnrecorded, "host", d.cfg.HostName)
	if err != nil {
		return err
	}
	if ufound && urow.Lifecycle != corrosion.ConditionResolved {
		var ev nvramFlushEvidence
		if err := json.Unmarshal([]byte(urow.Evidence), &ev); err != nil {
			slog.Error("the nvram_flush_unrecorded evidence cannot be read; the failures it held are not known", "error", err)
		} else {
			f.Seed(ev.Files)
		}
	}
	row, found, err := readNvramFlushCondition(ctx, d.db, nvramFlushEvaluator, CondNvramFlushFailed, "host", d.cfg.HostName)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	if row.Lifecycle == corrosion.ConditionResolved {
		var ev nvramFlushEvidence
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			slog.Error("nvram_flush_failed is resolved but its evidence cannot be read; nothing is acknowledged", "error", err)
			return nil
		}
		f.Acknowledge(ev.Files)
		return nil
	}
	var ev nvramFlushEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		slog.Error("the nvram_flush_failed evidence cannot be read; the condition is kept raised until a new failure rewrites it", "error", err)
		st.holdResolve = true
		return nil
	}
	f.Seed(ev.Files)
	return nil
}

// syncNvramCondition raises, rewrites or resolves one condition when files
// differ from what it was last written as. last moves only once the write
// (or the finding that there is nothing to resolve) succeeded, so a failed
// write is retried on the next tick.
func (d *Daemon) syncNvramCondition(ctx context.Context, code, severity string, files []libvirt.NvramFlushFailure, remedy string, last *string) {
	b, _ := json.Marshal(files)
	key := string(b)
	if key == *last {
		return
	}
	open := len(files) > 0
	if !open {
		row, found, err := readNvramFlushCondition(ctx, d.db, nvramFlushEvaluator, code, "host", d.cfg.HostName)
		if err != nil {
			return
		}
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			*last = key
			return
		}
	}
	if d.writeSelfConditionAs(ctx, nvramFlushEvaluator, code, open, severity, nvramFlushEvidence{Files: files, Remedy: remedy}) {
		*last = key
	}
}

// stopAndWait cancels and waits up to bound for done.
func stopAndWait(cancel func(), done <-chan struct{}, bound time.Duration) {
	cancel()
	select {
	case <-done:
	case <-time.After(bound):
		slog.Warn("UEFI vars flusher's last sweep did not finish in time; exiting without it", "waited", bound)
	}
}

// withoutFailures is failed less the episodes in drop.
func withoutFailures(failed, drop []libvirt.NvramFlushFailure) []libvirt.NvramFlushFailure {
	out := make([]libvirt.NvramFlushFailure, 0, len(failed))
	for _, v := range failed {
		if !slices.ContainsFunc(drop, func(x libvirt.NvramFlushFailure) bool {
			return x.Path == v.Path && x.Ino == v.Ino && x.Episode == v.Episode
		}) {
			out = append(out, v)
		}
	}
	return out
}

// acknowledgedFiles is the failures this host wrote that the resolved row
// also names, matched on path, inode and episode.
func acknowledgedFiles(wrote, named []libvirt.NvramFlushFailure) []libvirt.NvramFlushFailure {
	var out []libvirt.NvramFlushFailure
	for _, w := range wrote {
		for _, n := range named {
			if w.Path == n.Path && w.Ino == n.Ino && w.Episode == n.Episode {
				out = append(out, w)
				break
			}
		}
	}
	return out
}
