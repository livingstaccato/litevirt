package daemon

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
)

const vtpmEvaluator = "vtpm"

// CondVTPMStateNotDurable is raised by a node about itself while swtpm is
// installed, vtpm_state_sync is on, and its swtpm tree could not be made
// synchronous: the filesystem refuses the attribute, a new file does not
// inherit it, the filesystem does not commit the rename synchronously, or a
// pass failed or did not finish. A vTPM write made shortly before a power cut
// can then be lost.
const CondVTPMStateNotDurable = "vtpm_state_not_durable"

// vtpmPassWait is how long the vTPM capability probe waits for a pass. A pass
// on a local filesystem takes milliseconds; one that hangs (a hard NFS mount
// whose server stopped answering) goes on in the background.
const vtpmPassWait = 10 * time.Second

// stateTimedOut is the condition's state while a pass has run past its wait.
const stateTimedOut = "timed_out"

// vtpmStateSync keeps libvirt's swtpm tree synchronous (libvirt.SyncSwtpmState)
// and reports when it cannot. The vTPM capability probe drives it, at start
// and every minute; a pass runs in its own goroutine, so a hung one blocks
// neither daemon start nor the label loop.
type vtpmStateSync struct {
	on     bool
	base   string
	wait   time.Duration
	sync   func(on bool) libvirt.SwtpmSyncReport
	report func(open bool, evidence map[string]any) bool

	mu       sync.Mutex
	running  chan struct{} // closed when the pass in flight ends; nil when none runs
	passed   bool          // a pass completed since swtpm was last seen installed
	overran  bool          // the pass in flight ran past wait and was reported
	last     string        // what the condition was last synced to say
	reported bool          // the condition says it
	open     bool
}

// probe is the vTPM capability: swtpm is installed (present) and a pass over
// the swtpm tree has completed, so placement offers vTPM here only after the
// attempt to make its state synchronous. A pass that fails or cannot work on
// this filesystem still completes, and raises the condition: vTPM keeps
// working where its state is not durable. Without swtpm the condition is
// resolved, so a host that drops swtpm is not left degraded.
func (v *vtpmStateSync) probe(present bool) bool {
	if !present {
		v.absent()
		return false
	}
	done := v.start()
	t := time.NewTimer(v.wait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
		v.overrun()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.passed
}

// start starts a pass unless one is in flight, and returns its done channel.
func (v *vtpmStateSync) start() <-chan struct{} {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.running != nil {
		return v.running
	}
	ch := make(chan struct{})
	v.running = ch
	go func() {
		rep := v.sync(v.on)
		v.finish(rep)
		close(ch)
	}()
	return ch
}

func (v *vtpmStateSync) finish(rep libvirt.SwtpmSyncReport) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.running, v.passed, v.overran = nil, true, false
	open := v.on && rep.State != libvirt.SwtpmSyncOn
	if rep.State != v.last || rep.Changed > 0 {
		switch {
		case !open && v.on:
			slog.Info("vTPM state writes are synchronous", "path", rep.Base, "fs", rep.FS, "entries_set", rep.Changed)
		case !open:
			slog.Info("vtpm_state_sync is off: vTPM state writes are not synchronous", "path", rep.Base, "entries_cleared", rep.Changed)
		default:
			slog.Warn("vTPM state writes are not synchronous; a vTPM write made shortly before a power cut can be lost",
				"state", rep.State, "path", rep.Base, "fs", rep.FS, "error", rep.Err)
		}
	}
	var evidence map[string]any
	if open {
		errText := ""
		if rep.Err != nil {
			errText = rep.Err.Error()
		}
		evidence = map[string]any{"state": rep.State, "path": rep.Base, "fs": rep.FS, "error": errText,
			"remedy": vtpmRemedy(rep)}
	}
	v.sync1(rep.State, open, evidence)
}

// overrun raises the condition once for a pass still running past wait.
func (v *vtpmStateSync) overrun() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.overran {
		return
	}
	v.overran = true
	slog.Warn("a pass over the vTPM state tree has not finished; vTPM is not offered on this host until one does",
		"path", v.base, "waited", v.wait)
	if !v.on {
		return
	}
	v.sync1(stateTimedOut, true, map[string]any{
		"state": stateTimedOut, "path": v.base,
		"error":  fmt.Sprintf("a pass over %s has not finished after %v", v.base, v.wait),
		"remedy": "check that the filesystem holding " + v.base + " answers (a hung NFS server); the pass resumes on its own",
	})
}

// absent resolves the condition once swtpm is not installed, and forgets the
// last pass, so a reinstalled swtpm waits for a new one.
func (v *vtpmStateSync) absent() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.passed = false
	v.sync1("absent", false, nil)
}

// sync1 writes the condition when what it says changes, or its last write
// failed. The caller holds mu.
func (v *vtpmStateSync) sync1(state string, open bool, evidence map[string]any) {
	if v.reported && open == v.open && state == v.last {
		return
	}
	v.reported = v.report(open, evidence)
	v.open, v.last = open, state
}

// vtpmRemedy is what makes a host's vTPM state durable, for its filesystem.
func vtpmRemedy(rep libvirt.SwtpmSyncReport) string {
	switch {
	case rep.State == libvirt.SwtpmSyncFailed:
		return "fix the entries named in error; the next pass, within a minute, retries"
	case rep.FS == "zfs":
		return "zfs set sync=always on the dataset holding " + rep.Base + ", then set vtpm_state_sync: false"
	case rep.FS == "nfs":
		return "export " + rep.Base + " sync and mount it with the sync option, then set vtpm_state_sync: false"
	case rep.FS == "xfs":
		return "mount the xfs filesystem holding " + rep.Base + " with dirsync"
	}
	return "put " + rep.Base + " on an ext4 filesystem, or set vtpm_state_sync: false to accept the loss window"
}

// tpmCapableProbe is the vTPM capability label's probe: swtpm and swtpm_setup
// are installed, and probe agrees (vtpmStateSync.probe).
func tpmCapableProbe(lookPath func(string) (string, error), probe func(present bool) bool) func() bool {
	return func() bool {
		_, errSwtpm := lookPath("swtpm")
		_, errSetup := lookPath("swtpm_setup")
		return probe(errSwtpm == nil && errSetup == nil)
	}
}

// syncVTPMCondition raises or resolves vtpm_state_not_durable about this
// host. A resolve with no open row has nothing to write and counts as done.
func (d *Daemon) syncVTPMCondition(ctx context.Context, open bool, evidence map[string]any) bool {
	if !open {
		row, found, err := corrosion.GetHealthCondition(ctx, d.db, vtpmEvaluator, CondVTPMStateNotDurable, "host", d.cfg.HostName)
		if err != nil {
			return false
		}
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return true
		}
	}
	return d.writeSelfConditionAs(ctx, vtpmEvaluator, CondVTPMStateNotDurable, open, corrosion.SeverityWarning, evidence)
}
