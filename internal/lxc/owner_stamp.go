package lxc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/safename"
)

// ContainerOwner is the owner record of a container's on-disk directory: the
// project and the lineage (the create spec's owner_id) it belongs to. A
// container's name is per host and reusable, so the directory a name finds is
// matched against this record before it is adopted as a row's container.
type ContainerOwner struct {
	Project string `json:"project"`
	OwnerID string `json:"owner_id,omitempty"`
}

// OwnerStamper is the optional runtime capability behind the owner record,
// kept like the managed stamp inside <lxcpath>/<name>/ so it dies with the
// directory and travels with it on export and import.
type OwnerStamper interface {
	// StampOwner writes the record; it refuses a container with no directory.
	StampOwner(name string, o ContainerOwner) error
	// ReadOwner returns the record, or nil when the directory has none (a
	// container an earlier build made, or none at all).
	ReadOwner(name string) (*ContainerOwner, error)
}

const ownerStampFile = "litevirt-owner"

var _ OwnerStamper = (*LxcRunner)(nil)

// StampOwner implements OwnerStamper.
func (r *LxcRunner) StampOwner(name string, o ContainerOwner) error {
	if err := safename.ValidateContainerName(name); err != nil {
		return err
	}
	dir := filepath.Join(r.lxcpath(), name)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("stamp container %q owner: no container directory at %s", name, dir)
	}
	b, _ := json.Marshal(o)
	if err := writeOwnerRecord(dir, b); err != nil {
		return fmt.Errorf("stamp container %q owner: %w", name, err)
	}
	return nil
}

// writeOwnerBytes writes the record's bytes to the temp file. A variable so a
// test can fail the write part-way.
var writeOwnerBytes = func(f *os.File, b []byte) error {
	_, err := f.Write(b)
	return err
}

// writeOwnerRecord replaces dir's owner record atomically: a temp file in the
// same directory, written and synced, renamed over the record, then the
// directory synced. ReadOwner treats a record it cannot parse as foreign, so a
// record torn by a crash mid-write would refuse the container's OWN directory
// on every later sweep; at the record's name there is only ever the old
// record, the new one, or none.
func writeOwnerRecord(dir string, b []byte) error {
	tmp, err := os.CreateTemp(dir, ownerStampFile+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // nothing left behind on failure; a no-op after the rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := writeOwnerBytes(tmp, b); err != nil {
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
	if err := os.Rename(tmp.Name(), filepath.Join(dir, ownerStampFile)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// ReadOwner implements OwnerStamper.
func (r *LxcRunner) ReadOwner(name string) (*ContainerOwner, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(r.lxcpath(), name, ownerStampFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var o ContainerOwner
	if err := json.Unmarshal(b, &o); err != nil {
		return nil, fmt.Errorf("container %q owner record: %w", name, err)
	}
	return &o, nil
}
