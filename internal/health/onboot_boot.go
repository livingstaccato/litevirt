package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Whether this daemon start follows a HOST boot, and which onboot starts the
// boot still owes (lab 2 F-4).
//
// onboot means "start when the host boots" (docs/compose.md): every onboot VM
// not running, including one its operator stopped before the reboot — that is
// what sets onboot apart from a restart policy, which never restarts an
// operator stop. A plain daemon restart (an upgrade) starts nothing its
// operator stopped.
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
// and unchanged across daemon restarts. The record in the data dir holds the
// boot ID onboot last ran under and, beside it, the VMs whose operator stop
// that boot still has to override, each with the stop it found. It is written
// on every change, before any start is attempted: a daemon restarted later in
// the same boot overrides exactly those VMs — still carrying that stop — and
// no operator stop made after the boot (review I-1), and a VM the boot owes is
// never forgotten because another one finished first (review I-2).

// onbootBootFile, in the data dir, is the onboot record.
const onbootBootFile = "onboot-boot-id"

// kernelBootIDPath is where Linux publishes the current boot's ID.
const kernelBootIDPath = "/proc/sys/kernel/random/boot_id"

// bootIDPattern is the form of a kernel boot ID (a random UUID). A record or
// a kernel answer of any other form is not trusted (review M-3).
var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// onbootStop is the operator stop a host boot found on a VM's row and starts
// it over.
type onbootStop struct {
	VM          string `json:"vm"`
	State       string `json:"state"`
	StateDetail string `json:"state_detail"`
}

// onbootRecord is the content of onbootBootFile.
type onbootRecord struct {
	BootID string       `json:"boot_id"`
	Owed   []onbootStop `json:"owed,omitempty"`
}

func readKernelBootID() (string, error) {
	b, err := os.ReadFile(kernelBootIDPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

// errOnbootRecordCorrupt: the record is there and cannot be trusted.
var errOnbootRecordCorrupt = errors.New("the onboot record is not one this daemon wrote")

// readOnbootRecord reads the record in dataDir. A missing record is
// os.ErrNotExist; one that does not parse, or names no boot ID of the
// kernel's form, is errOnbootRecordCorrupt.
func readOnbootRecord(dataDir string) (onbootRecord, error) {
	b, err := os.ReadFile(filepath.Join(dataDir, onbootBootFile))
	if err != nil {
		return onbootRecord{}, err
	}
	var rec onbootRecord
	if err := json.Unmarshal(b, &rec); err != nil || !bootIDPattern.MatchString(rec.BootID) {
		return onbootRecord{}, errOnbootRecordCorrupt
	}
	return rec, nil
}

// onbootBoot is what a daemon start knows about the boot it runs in.
type onbootBoot struct {
	// id is this boot's ID; "" when it cannot be read, and nothing is
	// recorded then.
	id string
	// hostBoot: the host booted since onboot last ran.
	hostBoot bool
	// owed: on a restart in the same boot, the stops the boot still has to
	// override, by VM.
	owed map[string]onbootStop
}

// onbootBootState reads this boot's ID and the record. Anything it cannot
// trust — no boot ID, no record (the first start of this build, a new data
// dir), an unreadable or corrupt record — is NOT a host boot: an operator
// stop is honoured, as before this record existed.
func (r *Reconciler) onbootBootState() onbootBoot {
	read := r.bootID
	if read == nil {
		read = readKernelBootID
	}
	cur, err := read()
	if err != nil || !bootIDPattern.MatchString(cur) {
		slog.Warn("onboot: cannot read this boot's ID; a VM its operator stopped is left stopped", "boot_id", cur, "error", err)
		return onbootBoot{}
	}
	rec, err := readOnbootRecord(r.dataDir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return onbootBoot{id: cur}
	case err != nil:
		slog.Warn("onboot: the record of the boot onboot last ran in cannot be read or trusted; taken as no record, so a VM its operator stopped is left stopped",
			"file", filepath.Join(r.dataDir, onbootBootFile), "error", err)
		return onbootBoot{id: cur}
	case rec.BootID != cur:
		return onbootBoot{id: cur, hostBoot: true}
	}
	owed := map[string]onbootStop{}
	for _, s := range rec.Owed {
		owed[s.VM] = s
	}
	return onbootBoot{id: cur, owed: owed}
}

// onbootOverrides decides which of the onboot VMs not running have their
// operator stop overridden by b. Only an operator's own stop is ever
// overridden: a drain's or a re-key's is not a choice a reboot answers. On a
// restart in the same boot, only a stop the record still owes, unchanged.
func onbootOverrides(b onbootBoot, vm corrosion.VMRecord) bool {
	if vm.StateDetail != operatorStopDetail {
		return false
	}
	if b.hostBoot {
		return true
	}
	s, ok := b.owed[vm.Name]
	return ok && s.State == vm.State && s.StateDetail == vm.StateDetail
}

// persistOnbootLocked writes the record: this boot, and the overrides still
// owed. Under onbootMu, so two writes never cross. Nothing is written
// without a boot ID.
func (r *Reconciler) persistOnbootLocked() {
	if r.onbootBootID == "" {
		return
	}
	rec := onbootRecord{BootID: r.onbootBootID}
	for _, s := range r.onbootOverride {
		rec.Owed = append(rec.Owed, s)
	}
	sort.Slice(rec.Owed, func(i, j int) bool { return rec.Owed[i].VM < rec.Owed[j].VM })
	if err := writeOnbootRecord(r.dataDir, rec); err != nil {
		// A daemon restart in this boot then reads the previous record: an
		// older owed set, or none (a host boot) — it may start an onboot VM
		// whose operator stopped it since.
		slog.Error("onboot: could not record this boot and the onboot starts it owes; a daemon restart before it is recorded may start an onboot VM its operator stopped",
			"error", err)
	}
}

func writeOnbootRecord(dataDir string, rec onbootRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dataDir, onbootBootFile+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
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
