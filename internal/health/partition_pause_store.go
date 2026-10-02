package health

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// The durable record of a partition pause (docs/design/partition-pause.md §3.3).
//
// One file per workload this host paused ITSELF on losing the voter majority,
// under <data_dir>/partition-pause/<kind>-<name>.json. A file and not a table,
// for the owner-epoch marker's reason: it is a statement about what THIS host
// did to its own runtime, which must survive a restart and must never be
// replicated, repaired or merged — and a file costs no schema version and no
// statement shape.
//
// It is written BEFORE the pause, so a crash between the two leaves a record
// for a running workload (resuming a running domain is a no-op) rather than a
// paused workload with no record, which the pauser would read as an operator's
// and never resume.

// Pause record kinds.
const (
	PauseKindVM        = "vm"
	PauseKindContainer = "ct"
)

// partitionPauseDir is the record directory under the daemon's data dir.
const partitionPauseDir = "partition-pause"

// PauseRecord is one self-paused workload.
type PauseRecord struct {
	Kind        string `json:"kind"` // PauseKindVM | PauseKindContainer
	Name        string `json:"name"`
	Host        string `json:"host"`
	OwnerEpoch  int64  `json:"owner_epoch"`
	Incarnation string `json:"incarnation"` // the row's created_at at the pause (corrosion.IncarnationOf)
	PausedAt    string `json:"paused_at"`   // RFC3339, for operators; nothing decides on it
	Reason      string `json:"reason"`
}

// Key identifies a record: kind/name.
func (r PauseRecord) Key() string { return r.Kind + "/" + r.Name }

// pauseStore reads and writes the record directory. The zero value (no dir)
// stores nothing and lists nothing.
type pauseStore struct{ dir string }

func newPauseStore(dataDir string) pauseStore {
	if dataDir == "" {
		return pauseStore{}
	}
	return pauseStore{dir: filepath.Join(dataDir, partitionPauseDir)}
}

func pauseFileName(kind, name string) (string, error) {
	switch kind {
	case PauseKindVM:
		if err := safename.ValidateVMName(name); err != nil {
			return "", err
		}
	case PauseKindContainer:
		if err := safename.ValidateContainerName(name); err != nil {
			return "", err
		}
	default:
		return "", fmt.Errorf("partition pause: unknown workload kind %q", kind)
	}
	return kind + "-" + name + ".json", nil
}

// put writes rec durably: temp file, fsync, rename, directory fsync.
func (s pauseStore) put(rec PauseRecord) error {
	if s.dir == "" {
		return errors.New("partition pause: no data directory to record the pause in")
	}
	fn, err := pauseFileName(rec.Kind, rec.Name)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", s.dir, err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.dir, fn+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(b); err != nil {
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
	if err := os.Rename(tmp.Name(), filepath.Join(s.dir, fn)); err != nil {
		return err
	}
	return syncDir(s.dir)
}

// remove deletes kind/name's record. Absent is success.
func (s pauseStore) remove(kind, name string) error {
	if s.dir == "" {
		return nil
	}
	fn, err := pauseFileName(kind, name)
	if err != nil {
		return err
	}
	if err := os.Remove(filepath.Join(s.dir, fn)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDir(s.dir)
}

// get reads kind/name's record; ok=false when absent.
func (s pauseStore) get(kind, name string) (PauseRecord, bool, error) {
	if s.dir == "" {
		return PauseRecord{}, false, nil
	}
	fn, err := pauseFileName(kind, name)
	if err != nil {
		return PauseRecord{}, false, err
	}
	return readPauseRecord(filepath.Join(s.dir, fn))
}

// list returns every record, sorted by key. A record that does not parse is
// an error, never a skip: a skipped record is a paused workload nothing will
// ever resume.
func (s pauseStore) list() ([]PauseRecord, error) {
	if s.dir == "" {
		return nil, nil
	}
	ents, err := os.ReadDir(s.dir)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []PauseRecord
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		rec, ok, err := readPauseRecord(filepath.Join(s.dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key() < out[j].Key() })
	return out, nil
}

func readPauseRecord(path string) (PauseRecord, bool, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return PauseRecord{}, false, nil
	}
	if err != nil {
		return PauseRecord{}, false, err
	}
	var rec PauseRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return PauseRecord{}, false, fmt.Errorf("corrupt partition-pause record %s: %w", path, err)
	}
	if rec.Kind == "" || rec.Name == "" {
		return PauseRecord{}, false, fmt.Errorf("corrupt partition-pause record %s: no kind or name", path)
	}
	return rec, true, nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ReadPauseRecord reads the partition-pause record for kind/name under
// dataDir, for Layer 3 (settle.go): the record is this host's own evidence of
// which incarnation and epoch its local copy is.
func ReadPauseRecord(dataDir, kind, name string) (PauseRecord, bool, error) {
	return newPauseStore(dataDir).get(kind, name)
}

// RemovePauseRecord drops kind/name's record under dataDir (absent is fine).
func RemovePauseRecord(dataDir, kind, name string) error {
	return newPauseStore(dataDir).remove(kind, name)
}
