package daemon

import (
	"log/slog"
	"sync"

	"github.com/litevirt/litevirt/internal/libvirt"
)

const vtpmEvaluator = "vtpm"

// CondVTPMStateNotDurable is raised by a node about itself while
// vtpm_state_sync is on and its swtpm tree could not be made synchronous: the
// filesystem refuses the attribute, a new file does not inherit it, or a pass
// failed. A vTPM write made shortly before a power cut can then be lost.
const CondVTPMStateNotDurable = "vtpm_state_not_durable"

// vtpmStateSync keeps libvirt's swtpm tree synchronous (libvirt.SyncSwtpmState)
// and reports when it cannot. It runs where the daemon prepares the host for
// vTPM VMs: the vTPM capability probe, at start and every minute.
type vtpmStateSync struct {
	on     bool
	sync   func(on bool) libvirt.SwtpmSyncReport
	report func(open bool, evidence map[string]any) bool

	mu       sync.Mutex
	last     string // the last pass's state
	reported bool   // the condition says what the last pass found
	open     bool
}

// ensure runs one pass, logs a change of state and writes the condition when
// what it says changes (or its last write failed).
func (v *vtpmStateSync) ensure() {
	v.mu.Lock()
	defer v.mu.Unlock()
	rep := v.sync(v.on)
	open := v.on && rep.State != libvirt.SwtpmSyncOn
	if rep.State != v.last || rep.Changed > 0 {
		switch {
		case !open && v.on:
			slog.Info("vTPM state writes are synchronous", "path", rep.Base, "entries_set", rep.Changed)
		case !open:
			slog.Info("vtpm_state_sync is off: vTPM state writes are not synchronous", "path", rep.Base, "entries_cleared", rep.Changed)
		default:
			slog.Warn("vTPM state writes are not synchronous; a vTPM write made shortly before a power cut can be lost",
				"state", rep.State, "path", rep.Base, "error", rep.Err)
		}
	}
	if !v.reported || open != v.open || rep.State != v.last {
		var evidence map[string]any
		if open {
			errText := ""
			if rep.Err != nil {
				errText = rep.Err.Error()
			}
			evidence = map[string]any{
				"state": rep.State,
				"path":  rep.Base,
				"error": errText,
				"remedy": "put " + rep.Base + " on an ext4 or xfs filesystem, or set vtpm_state_sync: false " +
					"to accept the loss window",
			}
		}
		v.reported = v.report(open, evidence)
		v.open = open
	}
	v.last = rep.State
}

// tpmCapableProbe is the vTPM capability label's probe: swtpm and swtpm_setup
// are installed. On a capable host it brings the swtpm tree in line first, so
// the label that lets placement put a vTPM VM here never lands before it.
func tpmCapableProbe(lookPath func(string) (string, error), ensure func()) func() bool {
	return func() bool {
		if _, err := lookPath("swtpm"); err != nil {
			return false
		}
		if _, err := lookPath("swtpm_setup"); err != nil {
			return false
		}
		ensure()
		return true
	}
}
