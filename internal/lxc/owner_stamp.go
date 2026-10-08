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
	if err := os.WriteFile(filepath.Join(dir, ownerStampFile), b, 0o600); err != nil {
		return fmt.Errorf("stamp container %q owner: %w", name, err)
	}
	return nil
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
