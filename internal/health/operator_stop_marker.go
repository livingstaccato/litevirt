package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// The local record of an operator's forced stop made under write quarantine.
//
// A host in write quarantine refuses every replicated write, so `lv stop
// --force` cannot record "operator-stop" on the VM's row: the row keeps
// "running", and once the quarantine lifts the reconciler would record the
// killed domain as an out-of-band destroy that the restart policy starts
// again. So the stop first writes this file, durably, under
// <data_dir>/operator-stops/<vm>.json, and only then kills the domain; no
// marker, no kill.
//
// While the marker names the VM's current incarnation (its row's created_at)
// on this host, nothing on this host starts the VM: the restart policy, the
// reconciler's self-heal and onboot starts, and `lv start`. Once the
// quarantine lifts, the owner replays the stop into the row through the
// ordinary stop record (grpcapi), then removes the marker. A marker for
// another incarnation of the name, or another host's, holds nothing. A
// marker that cannot be read or parsed holds its VM (fail closed) and is
// alerted on, never replayed.
//
// A file and not a table, for the partition-pause record's reason: it is what
// this host did to its own runtime, it must survive a daemon restart, and it
// costs no schema version and no statement shape. An older binary does not
// know it: a host rolled back below this build ignores the marker
// (docs/upgrades.md).

// operatorStopSyncDir fsyncs a directory; a test seam over syncDir, so the
// fsync that makes the rename durable can be seen to happen.
var operatorStopSyncDir = syncDir

// operatorStopDir is the marker directory under the daemon's data dir.
const operatorStopDir = "operator-stops"

// operatorStopMarkerVersion is the marker format this build writes and reads.
// A marker of another version is not understood, and holds its VM.
const operatorStopMarkerVersion = 1

// OperatorStopMarker is one forced stop made under write quarantine.
type OperatorStopMarker struct {
	Version int    `json:"version"`
	VM      string `json:"vm"`
	Host    string `json:"host"`
	// Incarnation is the row's created_at at the stop
	// (corrosion.IncarnationOf): the marker holds only that incarnation.
	Incarnation string `json:"incarnation"`
	// OwnerEpoch is the row's vm_owner_epoch at the stop: an ownership
	// that left this host and came back (a later generation) is not held,
	// and the replay never records the stop over it.
	OwnerEpoch int64  `json:"owner_epoch"`
	StoppedAt  string `json:"stopped_at"` // RFC3339, for operators; nothing decides on it
	Quarantine string `json:"quarantine"` // why writes were refused, for operators
}

// ErrOperatorStopMarkerCorrupt is a marker that exists and cannot be read,
// parsed or understood.
var ErrOperatorStopMarkerCorrupt = errors.New("operator-stop marker is corrupt")

// OperatorStopMarkerDir is where markers live under dataDir.
func OperatorStopMarkerDir(dataDir string) string {
	return filepath.Join(dataDir, operatorStopDir)
}

// OperatorStopMarkerPath is vm's marker file under dataDir.
func OperatorStopMarkerPath(dataDir, vm string) (string, error) {
	if dataDir == "" {
		return "", errors.New("operator-stop marker: no data directory")
	}
	if err := safename.ValidateVMName(vm); err != nil {
		return "", err
	}
	return filepath.Join(OperatorStopMarkerDir(dataDir), vm+".json"), nil
}

// WriteOperatorStopMarker writes m durably: the directory made and synced
// into the data dir, a temp file written and fsynced, renamed over the
// marker, and the directory fsynced. Any failure is returned, and the caller
// must not kill the VM.
func WriteOperatorStopMarker(dataDir string, m OperatorStopMarker) error {
	p, err := OperatorStopMarkerPath(dataDir, m.VM)
	if err != nil {
		return err
	}
	if m.Version == 0 {
		m.Version = operatorStopMarkerVersion
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	// The directory's own entry in the data dir, so the marker is not lost
	// with a directory a crash forgot.
	if err := syncDir(dataDir); err != nil {
		return fmt.Errorf("fsync %s: %w", dataDir, err)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+m.VM+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("write %s: %w", tmp.Name(), err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("fsync %s: %w", tmp.Name(), err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return err
	}
	if err := operatorStopSyncDir(dir); err != nil {
		return fmt.Errorf("fsync %s: %w", dir, err)
	}
	return nil
}

// ReadOperatorStopMarker reads vm's marker. ok is false when there is none.
// A marker that exists and cannot be read, parsed or understood returns an
// error wrapping ErrOperatorStopMarkerCorrupt.
func ReadOperatorStopMarker(dataDir, vm string) (m OperatorStopMarker, ok bool, err error) {
	p, err := OperatorStopMarkerPath(dataDir, vm)
	if err != nil {
		return m, false, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return m, false, nil
	}
	if err != nil {
		return m, false, fmt.Errorf("%w: read %s: %v", ErrOperatorStopMarkerCorrupt, p, err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return m, false, fmt.Errorf("%w: %s: %v", ErrOperatorStopMarkerCorrupt, p, err)
	}
	switch {
	case m.Version != operatorStopMarkerVersion:
		return m, false, fmt.Errorf("%w: %s: version %d, this build reads %d", ErrOperatorStopMarkerCorrupt, p, m.Version, operatorStopMarkerVersion)
	case m.VM != vm || m.Host == "" || m.Incarnation == "":
		return m, false, fmt.Errorf("%w: %s: names VM %q host %q incarnation %q", ErrOperatorStopMarkerCorrupt, p, m.VM, m.Host, m.Incarnation)
	}
	return m, true, nil
}

// RemoveOperatorStopMarker removes vm's marker durably. Absent is success.
func RemoveOperatorStopMarker(dataDir, vm string) error {
	p, err := OperatorStopMarkerPath(dataDir, vm)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	return syncDir(filepath.Dir(p))
}

// ListOperatorStopMarkers returns the VM names that have a marker file,
// sorted. No directory is none.
func ListOperatorStopMarkers(dataDir string) ([]string, error) {
	if dataDir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(OperatorStopMarkerDir(dataDir))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
			continue
		}
		out = append(out, strings.TrimSuffix(n, ".json"))
	}
	sort.Strings(out)
	return out, nil
}

// OperatorStopHold says why vm must not be started on host because of its
// operator-stop marker, or "" when no marker holds it. corrupt says the
// marker could not be read or understood: it holds the VM (fail closed) and
// is the operator's to look at.
func OperatorStopHold(dataDir, host string, vm *corrosion.VMRecord) (why string, corrupt bool) {
	if dataDir == "" || vm == nil {
		return "", false
	}
	m, ok, err := ReadOperatorStopMarker(dataDir, vm.Name)
	switch {
	case err != nil:
		p, _ := OperatorStopMarkerPath(dataDir, vm.Name)
		return fmt.Sprintf("its operator-stop marker %s cannot be read (%v); the VM is held stopped until it is", p, err), true
	case !ok:
		return "", false
	case m.Host != host || m.Incarnation != corrosion.IncarnationOf(vm.CreatedAt) || m.OwnerEpoch != vm.OwnerEpoch:
		return "", false // another host's, another incarnation of the name, or a later ownership of it
	}
	return fmt.Sprintf("its operator stopped it with `lv stop --force` at %s while this host was in write quarantine; "+
		"the stop is recorded once the quarantine lifts", m.StoppedAt), false
}

// operatorStopHoldLog rate-limits the log line a held VM makes: every pass
// of the reconciler and the restart policy asks.
var operatorStopHoldLog = struct {
	mu   sync.Mutex
	last map[string]time.Time
}{}

// logOperatorStopHold logs that who did not start vm, at most every
// ioPausedWarnEvery per VM; a corrupt marker is logged as an error.
func logOperatorStopHold(who, vm, why string, corrupt bool) {
	operatorStopHoldLog.mu.Lock()
	now := time.Now()
	if t, ok := operatorStopHoldLog.last[vm]; ok && now.Sub(t) < ioPausedWarnEvery {
		operatorStopHoldLog.mu.Unlock()
		return
	}
	if operatorStopHoldLog.last == nil {
		operatorStopHoldLog.last = map[string]time.Time{}
	}
	operatorStopHoldLog.last[vm] = now
	operatorStopHoldLog.mu.Unlock()
	if corrupt {
		slog.Error(who+": not starting the VM — its operator-stop marker is corrupt (repeated at most every 10m)", "vm", vm, "why", why)
		return
	}
	slog.Info(who+": not starting the VM — "+why+" (repeated at most every 10m)", "vm", vm)
}

// operatorStopHeld is OperatorStopHold, logged for who.
func operatorStopHeld(who, dataDir, host string, vm *corrosion.VMRecord) bool {
	why, corrupt := OperatorStopHold(dataDir, host, vm)
	if why == "" {
		return false
	}
	logOperatorStopHold(who, vm.Name, why, corrupt)
	return true
}

const (
	// OperatorStopMarkerEvaluator is the evaluator of
	// operator_stop_marker_corrupt.
	OperatorStopMarkerEvaluator = "operator_stop_marker"
	// CondOperatorStopMarkerCorrupt is the condition code of a VM held
	// stopped on its host by an operator-stop marker that cannot be read.
	CondOperatorStopMarkerCorrupt = "operator_stop_marker_corrupt"
)

// operatorStopMarkerEvidence is the evidence JSON of an
// operator_stop_marker_corrupt row.
type operatorStopMarkerEvidence struct {
	Host   string `json:"host"`
	Path   string `json:"path"`
	Error  string `json:"error"`
	Remedy string `json:"remedy"`
}

// OperatorStopMarkerCorruptRemedy is what an operator does about vm's
// corrupt marker.
func OperatorStopMarkerCorruptRemedy(vm string) string {
	return "the VM is held stopped on this host and is not started by its restart policy, onboot or `lv start`: " +
		"look at the file, then record the stop with `lv stop " + vm + "` (which removes the marker once the stop " +
		"is recorded) and start it with `lv start " + vm + "`. While the host is in write quarantine, leave the file " +
		"and wait for the quarantine to lift, then `lv stop " + vm + "`: removing it then loses the stop. Only if the VM " +
		"was deleted (`lv stop` answers NotFound) remove the file by hand on this host: rm <data_dir>/" + operatorStopDir +
		"/" + vm + ".json"
}

// ReportCorruptOperatorStopMarkers raises operator_stop_marker_corrupt,
// critical, for every VM in corrupt (name -> read error) that has none open
// from host, and resolves each open one host raised whose VM is no longer in
// corrupt. A host in write quarantine cannot write it; its log and the
// litevirt_operator_stop_markers gauge carry the alert meanwhile.
func ReportCorruptOperatorStopMarkers(ctx context.Context, db *corrosion.Client, dataDir, host string, corrupt map[string]string) error {
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, db, OperatorStopMarkerEvaluator, CondOperatorStopMarkerCorrupt)
	if err != nil {
		return err
	}
	openHere := map[string]corrosion.HealthCondition{}
	for _, row := range open {
		if row.SubjectKind == "vm" && row.Reporter == host {
			openHere[row.SubjectID] = row
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	var errs []error
	for name, why := range corrupt {
		if _, ok := openHere[name]; ok {
			continue
		}
		p, _ := OperatorStopMarkerPath(dataDir, name)
		ev, _ := json.Marshal(operatorStopMarkerEvidence{Host: host, Path: p, Error: why, Remedy: OperatorStopMarkerCorruptRemedy(name)})
		row := corrosion.HealthCondition{
			Evaluator: OperatorStopMarkerEvaluator, Code: CondOperatorStopMarkerCorrupt,
			SubjectKind: "vm", SubjectID: name,
			Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityCritical,
			Hosts: []string{host}, Evidence: string(ev), ObserveCount: 1,
			FirstSeen: now, LastSeen: now, ConfirmedAt: now, Reporter: host,
		}
		if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
			errs = append(errs, err)
		}
	}
	for name, row := range openHere {
		if _, ok := corrupt[name]; ok {
			continue
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen = corrosion.ConditionResolved, now, now
		if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// operatorStopBackfillWait rate-limits the reconciler's log line about a
// backfill waiting for a marker's replay.
var operatorStopBackfillWait struct {
	mu   sync.Mutex
	last time.Time
}

// operatorStopBackfillWaitDue reports whether the wait may be logged at now,
// and if so records it.
func operatorStopBackfillWaitDue(now time.Time) bool {
	operatorStopBackfillWait.mu.Lock()
	defer operatorStopBackfillWait.mu.Unlock()
	if !operatorStopBackfillWait.last.IsZero() && now.Sub(operatorStopBackfillWait.last) < ioPausedWarnEvery {
		return false
	}
	operatorStopBackfillWait.last = now
	return true
}
