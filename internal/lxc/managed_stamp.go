package lxc

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/litevirt/litevirt/internal/safename"
)

// ManagedStamper is the optional runtime capability behind the container
// managed stamp: a file inside the container's own LXC directory that says only
// "litevirt manages this container". The orphan-runtime report
// (internal/health/orphan_runtime.go) recognises a litevirt container by it
// after the container's row is gone.
//
// It lives INSIDE <lxcpath>/<name>/ on purpose. lxc-destroy removes that whole
// directory, so the stamp dies with the container, and a container an operator
// later makes by hand under the same name starts without it — the property a
// host-local file elsewhere (under the daemon's data dir) cannot give, since it
// outlives the container unless every delete path remembers to remove it. It
// also travels with the directory on an export/import.
//
// Optional rather than part of Runtime so every Runtime implementation need not
// grow it; a runtime without it just never recognises a container this way.
type ManagedStamper interface {
	// StampManaged writes the stamp. It refuses when the container has no
	// directory: a stamp must never create the directory that makes a
	// container look present.
	StampManaged(name string) error
	// IsManaged reports whether the stamp is present.
	IsManaged(name string) (bool, error)
}

// managedStampFile is the stamp's name inside the container directory.
const managedStampFile = "litevirt-managed"

var _ ManagedStamper = (*LxcRunner)(nil)

// StampManaged implements ManagedStamper.
func (r *LxcRunner) StampManaged(name string) error {
	if err := safename.ValidateContainerName(name); err != nil {
		return err
	}
	dir := filepath.Join(r.lxcpath(), name)
	if fi, err := os.Stat(dir); err != nil || !fi.IsDir() {
		return fmt.Errorf("stamp container %q: no container directory at %s", name, dir)
	}
	// O_EXCL-free create is fine: the content is fixed, so a concurrent writer
	// writes the same bytes.
	if err := os.WriteFile(filepath.Join(dir, managedStampFile), []byte("litevirt\n"), 0o600); err != nil {
		return fmt.Errorf("stamp container %q: %w", name, err)
	}
	return nil
}

// IsManaged implements ManagedStamper.
func (r *LxcRunner) IsManaged(name string) (bool, error) {
	if err := safename.ValidateContainerName(name); err != nil {
		return false, err
	}
	_, err := os.Stat(filepath.Join(r.lxcpath(), name, managedStampFile))
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}
