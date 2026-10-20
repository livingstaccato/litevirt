package libvirtfake

import (
	"fmt"
	"os"

	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The point-in-time copy's external-snapshot layer (grpcapi.PointInTimeSnapshotter,
// libvirt.Client.SnapshotDiskExternal and friends), modelled: a snapshot of a
// running or paused domain creates the overlay — a real qcow2 backed by the
// disk, so qemu-img can commit it offline — and puts the domain on it; a
// commit takes the domain off it. The domain's disk file itself is never
// written, so a copy of the "frozen" file is the disk's content. A failed
// commit models a pivot that never landed: the domain stays on the overlay.

// SetPITFailures makes every later snapshot or commit fail with the error
// given (nil: succeed).
func (f *Fake) SetPITFailures(snapshot, commit error) {
	f.daemon()
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pitSnapErr, f.pitCommitErr = snapshot, commit
}

func (f *Fake) SnapshotDiskExternal(domain, diskPath, overlay string) (bool, error) {
	f.daemon()
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pitSnapErr != nil {
		return false, f.pitSnapErr
	}
	if st := f.domains[domain]; st != StateRunning && st != StatePaused {
		return false, fmt.Errorf("libvirtfake: domain %s is %q; no live snapshot", domain, st)
	}
	if _, err := os.Lstat(overlay); err == nil {
		return false, fmt.Errorf("libvirtfake: overlay %s exists", overlay)
	}
	if err := qcow2.CreateWithBackingFormat(overlay, diskPath, "qcow2", 0, nil); err != nil {
		return false, err
	}
	if f.pitOn == nil {
		f.pitOn = map[string]string{}
	}
	f.pitOn[overlay] = domain
	return false, nil
}

func (f *Fake) CommitDiskOverlay(domain, diskPath, overlay, diskFormat string, beforePivot func() error) error {
	f.daemon()
	// As libvirt.Client: the commit ends in a redefine.
	if err := f.fwCheck(libvirt.FirmwareCall{Op: libvirt.OpDefine, Name: domain}); err != nil {
		return fmt.Errorf("commit %s into %s: %w", overlay, diskPath, err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if st := f.domains[domain]; st == StateRunning || st == StatePaused {
		if f.pitCommitErr != nil {
			return f.pitCommitErr
		}
	}
	if f.pitOn[overlay] == domain {
		if beforePivot != nil {
			if err := beforePivot(); err != nil {
				return err
			}
		}
		delete(f.pitOn, overlay)
	}
	return nil
}

// DomainRunsOnFile is DomainUsesFile: the model keeps one definition.
func (f *Fake) DomainRunsOnFile(domain, path string) (bool, error) {
	f.daemon()
	return f.DomainUsesFile(domain, path)
}

func (f *Fake) DomainUsesFile(domain, path string) (bool, error) {
	f.daemon()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pitOn[path] == domain, nil
}
