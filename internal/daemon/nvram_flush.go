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
// UEFI vars file on it has failed. It resolves only when every such file is
// removed or replaced: a later fsync that succeeds proves nothing, because the
// kernel reports a writeback error once and the lost pages are clean.
const CondNvramFlushFailed = "nvram_flush_failed"

// nvramFlushConditionEvery is how often the condition follows the flusher.
const nvramFlushConditionEvery = 10 * time.Second

const nvramFlushRemedy = "the listed vars files may be missing UEFI variable writes their guests made; " +
	"qemu still holds the whole store in memory while the VM runs, but a stop does not rewrite it. " +
	"Check the disk (dmesg, smartctl). Then have the guest write its variables again, " +
	"or restore the VM's firmware state from a backup. " +
	"The condition clears when each file is removed or replaced"

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

// startNvramFlusher starts flushing this host's UEFI vars files. It needs
// nothing but the data directory, so it runs from the start of Run, and it
// sweeps once more when ctx ends.
func (d *Daemon) startNvramFlusher(ctx context.Context) *libvirt.NvramFlusher {
	f := libvirt.NewNvramFlusher(nvramDirs(d.cfg.DataDir)...)
	go f.Run(ctx, libvirt.NvramFlushInterval)
	return f
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
