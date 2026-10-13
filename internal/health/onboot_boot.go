package health

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Whether this daemon start follows a HOST boot (lab 2 F-4).
//
// onboot means "start when the host boots" (docs/compose.md): every onboot VM
// not running, including one its operator stopped before the reboot — that is
// what sets onboot apart from a restart policy, which never restarts an
// operator stop. A plain daemon restart (an upgrade) starts nothing.
//
// StartOnbootVMs used to tell the two apart only by "the domain is not
// running", which an operator-stopped VM also is after a plain daemon
// restart. So the boot-time attempt included such a VM on every daemon
// restart, and the retry after the split-brain gate's warm-up refusal (which
// every boot-time attempt meets) then dropped it as operator-stopped — on a
// real host boot as well, so an onboot VM its operator had stopped never
// started at boot.
//
// The kernel's boot ID tells them apart: it is new on every boot of the host
// and unchanged across daemon restarts. The ID the last onboot decision was
// made under is recorded in the data dir. It is recorded only once nothing
// the host boot owes is left (onbootOverride): a daemon restarted in the
// same boot before then still owes it.

// onbootBootFile, in the data dir, is the boot ID onboot last ran under.
const onbootBootFile = "onboot-boot-id"

// kernelBootIDPath is where Linux publishes the current boot's ID.
const kernelBootIDPath = "/proc/sys/kernel/random/boot_id"

func readKernelBootID() (string, error) {
	b, err := os.ReadFile(kernelBootIDPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// onbootHostBoot reports whether this start follows a boot of the host since
// onboot last ran, and the current boot ID ("" when it cannot be read). No
// record (the first start of this build, a new data dir) or no readable boot
// ID is not a host boot: an operator stop is then honoured, as before.
func (r *Reconciler) onbootHostBoot() (bool, string) {
	read := r.bootID
	if read == nil {
		read = readKernelBootID
	}
	cur, err := read()
	if err != nil || cur == "" {
		slog.Warn("onboot: cannot read this boot's ID; a VM its operator stopped is left stopped", "error", err)
		return false, ""
	}
	prev, err := os.ReadFile(filepath.Join(r.dataDir, onbootBootFile))
	if err != nil {
		if !os.IsNotExist(err) {
			slog.Warn("onboot: cannot read the boot onboot last ran in; a VM its operator stopped is left stopped", "error", err)
		}
		return false, cur
	}
	return strings.TrimSpace(string(prev)) != cur, cur
}

// recordOnbootBoot records id as the boot onboot has run in.
func (r *Reconciler) recordOnbootBoot(id string) {
	if id == "" {
		return
	}
	if err := writeOnbootBoot(r.dataDir, id); err != nil {
		// The next daemon start in this boot then takes itself for a host
		// boot and starts an onboot VM its operator has stopped since.
		slog.Error("onboot: could not record this boot; a daemon restart before it is recorded starts onboot VMs stopped by their operator",
			"error", err)
	}
}

func writeOnbootBoot(dataDir, id string) error {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, onbootBootFile+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(id + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dataDir, onbootBootFile)); err != nil {
		return fmt.Errorf("record the boot: %w", err)
	}
	return nil
}
