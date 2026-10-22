package health

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/safename"
)

// The local record of an operator's forced container stop made under write
// quarantine: the container analogue of operator_stop_marker.go.
//
// `lv ct stop` records "operator-stop" on the container's row, and that is
// what keeps the container checker's restart policy from starting it again.
// A host in write quarantine cannot write the row, so `lv ct stop --force`
// first writes this file durably, under
// <data_dir>/ct-operator-stops/<name>.json, and only then stops the
// container; no marker, no stop. While it names the row's current
// incarnation (created_at) and owner epoch on this host, nothing on this
// host starts the container: the restart policy and `lv ct start`. Once the
// quarantine lifts, the replay (grpcapi) records the stop on the row and
// removes the marker.
//
// Its own directory, not operator-stops/: a build that knows only VM markers
// reads every file there as a VM's, and would take a container's for a
// corrupt VM marker (and hold a VM of that name). A build older than this
// one ignores this directory: rolled back onto it, the container's restart
// policy may start the container again (docs/upgrades.md).

// containerOperatorStopDir is the container marker directory under the
// daemon's data dir.
const containerOperatorStopDir = "ct-operator-stops"

// containerOperatorStopMarkerVersion is the container marker format this
// build writes and reads.
const containerOperatorStopMarkerVersion = 1

// ContainerOperatorStopMarker is one forced container stop made under write
// quarantine.
type ContainerOperatorStopMarker struct {
	Version   int    `json:"version"`
	Container string `json:"container"`
	Host      string `json:"host"`
	// Incarnation is the row's created_at at the stop
	// (corrosion.IncarnationOf), and OwnerEpoch its owner_epoch: the marker
	// holds, and is replayed onto, only that incarnation and ownership.
	Incarnation string `json:"incarnation"`
	OwnerEpoch  int64  `json:"owner_epoch"`
	StoppedAt   string `json:"stopped_at"` // RFC3339, for operators; nothing decides on it
	Quarantine  string `json:"quarantine"` // why writes were refused, for operators
}

// ContainerOperatorStopMarkerDir is where container markers live under
// dataDir.
func ContainerOperatorStopMarkerDir(dataDir string) string {
	return filepath.Join(dataDir, containerOperatorStopDir)
}

// ContainerOperatorStopMarkerPath is container name's marker file under
// dataDir.
func ContainerOperatorStopMarkerPath(dataDir, name string) (string, error) {
	if dataDir == "" {
		return "", fmt.Errorf("container operator-stop marker: no data directory")
	}
	if err := safename.ValidateContainerName(name); err != nil {
		return "", err
	}
	return filepath.Join(ContainerOperatorStopMarkerDir(dataDir), name+".json"), nil
}

// WriteContainerOperatorStopMarker writes m durably, as
// WriteOperatorStopMarker does. Any failure is returned, and the caller must
// not stop the container.
func WriteContainerOperatorStopMarker(dataDir string, m ContainerOperatorStopMarker) error {
	p, err := ContainerOperatorStopMarkerPath(dataDir, m.Container)
	if err != nil {
		return err
	}
	if m.Version == 0 {
		m.Version = containerOperatorStopMarkerVersion
	}
	return writeStopMarkerFile(dataDir, p, m.Container, m)
}

// ReadContainerOperatorStopMarker reads name's marker. ok is false when
// there is none. A marker that exists and cannot be read, parsed or
// understood returns an error wrapping ErrOperatorStopMarkerCorrupt.
func ReadContainerOperatorStopMarker(dataDir, name string) (m ContainerOperatorStopMarker, ok bool, err error) {
	p, err := ContainerOperatorStopMarkerPath(dataDir, name)
	if err != nil {
		return m, false, err
	}
	if ok, err := readStopMarkerFile(p, &m); !ok || err != nil {
		return m, false, err
	}
	switch {
	case m.Version != containerOperatorStopMarkerVersion:
		return m, false, fmt.Errorf("%w: %s: version %d, this build reads %d", ErrOperatorStopMarkerCorrupt, p, m.Version, containerOperatorStopMarkerVersion)
	case m.Container != name || m.Host == "" || m.Incarnation == "":
		return m, false, fmt.Errorf("%w: %s: names container %q host %q incarnation %q", ErrOperatorStopMarkerCorrupt, p, m.Container, m.Host, m.Incarnation)
	}
	return m, true, nil
}

// RemoveContainerOperatorStopMarker removes name's marker durably. Absent is
// success.
func RemoveContainerOperatorStopMarker(dataDir, name string) error {
	p, err := ContainerOperatorStopMarkerPath(dataDir, name)
	if err != nil {
		return err
	}
	return removeStopMarkerFile(p)
}

// ListContainerOperatorStopMarkers returns the container names that have a
// marker file, sorted. No directory is none.
func ListContainerOperatorStopMarkers(dataDir string) ([]string, error) {
	if dataDir == "" {
		return nil, nil
	}
	return listStopMarkerFiles(ContainerOperatorStopMarkerDir(dataDir))
}

// ContainerOperatorStopHold says why ct must not be started on host because
// of its operator-stop marker, or "" when no marker holds it. corrupt says
// the marker could not be read or understood: it holds the container (fail
// closed).
func ContainerOperatorStopHold(dataDir, host string, ct *corrosion.ContainerRecord) (why string, corrupt bool) {
	if dataDir == "" || ct == nil {
		return "", false
	}
	m, ok, err := ReadContainerOperatorStopMarker(dataDir, ct.Name)
	switch {
	case err != nil:
		p, _ := ContainerOperatorStopMarkerPath(dataDir, ct.Name)
		return fmt.Sprintf("its operator-stop marker %s cannot be read (%v); the container is held stopped until it is", p, err), true
	case !ok:
		return "", false
	case m.Host != host || ct.HostName != host || m.Incarnation != corrosion.IncarnationOf(ct.CreatedAt) || m.OwnerEpoch != ct.OwnerEpoch:
		return "", false // another host's, another incarnation of the name, or a later ownership of it
	}
	return fmt.Sprintf("its operator stopped it with `lv ct stop --force` at %s while this host was in write quarantine; "+
		"the stop is recorded once the quarantine lifts", m.StoppedAt), false
}

// ContainerOperatorStopMarkerCorruptRemedy is what an operator does about
// container name's corrupt marker.
func ContainerOperatorStopMarkerCorruptRemedy(name string) string {
	return "the container is held stopped on this host and is not started by its restart policy or `lv ct start`: " +
		"look at the file, then record the stop with `lv ct stop " + name + "` (which removes the marker once the stop " +
		"is recorded) and start it with `lv ct start " + name + "`. While the host is in write quarantine, leave the file " +
		"and wait for the quarantine to lift, then `lv ct stop " + name + "`: removing it then loses the stop. Only if the " +
		"container was deleted remove the file by hand on this host: rm <data_dir>/" + containerOperatorStopDir +
		"/" + name + ".json"
}

// ReportCorruptContainerOperatorStopMarkers is ReportCorruptOperatorStopMarkers
// for container markers: operator_stop_marker_corrupt with subject
// container/<name>.
func ReportCorruptContainerOperatorStopMarkers(ctx context.Context, db *corrosion.Client, dataDir, host string, corrupt map[string]string) error {
	return reportCorruptStopMarkers(ctx, db, host, "container", corrupt, func(name string) (string, string) {
		p, _ := ContainerOperatorStopMarkerPath(dataDir, name)
		return p, ContainerOperatorStopMarkerCorruptRemedy(name)
	})
}

// containerOperatorStopHeld is ContainerOperatorStopHold, logged for who at
// most every ioPausedWarnEvery per container.
func containerOperatorStopHeld(who, dataDir, host string, ct *corrosion.ContainerRecord) bool {
	why, corrupt := ContainerOperatorStopHold(dataDir, host, ct)
	if why == "" {
		return false
	}
	operatorStopHoldLog.mu.Lock()
	now := time.Now()
	key := "ct/" + ct.Name
	due := true
	if t, ok := operatorStopHoldLog.last[key]; ok && now.Sub(t) < ioPausedWarnEvery {
		due = false
	} else {
		if operatorStopHoldLog.last == nil {
			operatorStopHoldLog.last = map[string]time.Time{}
		}
		operatorStopHoldLog.last[key] = now
	}
	operatorStopHoldLog.mu.Unlock()
	if due {
		if corrupt {
			slog.Error(who+": not starting the container — its operator-stop marker is corrupt (repeated at most every 10m)", "container", ct.Name, "why", why)
		} else {
			slog.Info(who+": not starting the container — "+why+" (repeated at most every 10m)", "container", ct.Name)
		}
	}
	return true
}
