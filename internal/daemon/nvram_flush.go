package daemon

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// nvramFlushEvaluator raises the conditions about this host's UEFI vars
// flusher (libvirt.NvramFlusher).
const nvramFlushEvaluator = "uefi-vars"

// CondNvramFlushFailed is raised by a node about itself while an fsync of a
// UEFI vars file on it has failed. A file stops counting once the guest has
// written it again and that write is fsynced, or once it is removed or
// replaced. A later fsync with nothing written since proves nothing: the
// kernel reports a writeback error once and the lost pages are clean.
const CondNvramFlushFailed = "nvram_flush_failed"

// nvramFlushConditionEvery is how often the condition follows the flusher.
const nvramFlushConditionEvery = 10 * time.Second

const nvramFlushRemedy = "the listed vars files may be missing UEFI variable writes their guests made; " +
	"qemu still holds the whole store in memory while the VM runs, but a stop does not rewrite it. " +
	"Check the disk (dmesg, smartctl). Then have the guest write its variables again " +
	"(the file's next clean fsync after that write clears it), " +
	"or restore the VM's firmware state from a backup, or remove the VM"

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

// startNvramFlusher starts flushing this host's UEFI vars files. It needs
// nothing but the data directory, so it runs from the start of Run. stop
// ends it with one last sweep and waits for that, bounded.
func (d *Daemon) startNvramFlusher(ctx context.Context) (f *libvirt.NvramFlusher, stop func()) {
	f = libvirt.NewNvramFlusher(nvramDirs(d.cfg.DataDir)...)
	fctx, cancel := context.WithCancel(ctx)
	go f.Run(fctx, libvirt.NvramFlushInterval)
	return f, func() { stopAndWait(cancel, f.Done(), nvramFinalSweepWait) }
}

// runNvramFlushCondition keeps nvram_flush_failed in step with the flusher's
// failures, after carrying over those an earlier run recorded.
func (d *Daemon) runNvramFlushCondition(ctx context.Context, f *libvirt.NvramFlusher) {
	d.seedNvramFlushFailures(ctx, f)
	var last string
	t := time.NewTicker(nvramFlushConditionEvery)
	defer t.Stop()
	for {
		d.syncNvramFlushCondition(ctx, f.Failures(), &last)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// seedNvramFlushFailures hands the flusher the failures the open condition
// names, so a restart does not forget a write that never reached disk.
func (d *Daemon) seedNvramFlushFailures(ctx context.Context, f *libvirt.NvramFlusher) {
	row, found, err := corrosion.GetHealthCondition(ctx, d.db, nvramFlushEvaluator, CondNvramFlushFailed, "host", d.cfg.HostName)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	var ev nvramFlushEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		slog.Warn("could not read the nvram_flush_failed evidence; its files are not carried over", "error", err)
		return
	}
	f.Seed(ev.Files)
}

// syncNvramFlushCondition raises, rewrites or resolves the condition when the
// failures differ from the last ones written.
func (d *Daemon) syncNvramFlushCondition(ctx context.Context, failures []libvirt.NvramFlushFailure, last *string) {
	b, _ := json.Marshal(failures)
	if string(b) == *last {
		return
	}
	d.writeSelfConditionAs(ctx, nvramFlushEvaluator, CondNvramFlushFailed, len(failures) > 0,
		corrosion.SeverityCritical, nvramFlushEvidence{Files: failures, Remedy: nvramFlushRemedy})
	*last = string(b)
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
