package libvirtfake

import (
	"fmt"
	"os"
)

// The point-in-time copy's external-snapshot layer (grpcapi.PointInTimeSnapshotter,
// libvirt.Client.SnapshotDiskExternal and friends), modelled: a snapshot
// creates the overlay file and puts the domain on it, a commit takes the
// domain off it. The domain's disk file itself is never written, so a copy
// of the "frozen" file is the disk's content.

// SetPITFailures makes every later snapshot or commit fail with the error
// given (nil: succeed).
func (f *Fake) SetPITFailures(snapshot, commit error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pitSnapErr, f.pitCommitErr = snapshot, commit
}

func (f *Fake) SnapshotDiskExternal(domain, diskPath, overlay string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pitSnapErr != nil {
		return false, f.pitSnapErr
	}
	if _, err := os.Lstat(overlay); err == nil {
		return false, fmt.Errorf("libvirtfake: overlay %s exists", overlay)
	}
	if err := os.WriteFile(overlay, []byte("libvirtfake overlay"), 0o600); err != nil {
		return false, err
	}
	if f.pitOn == nil {
		f.pitOn = map[string]string{}
	}
	f.pitOn[overlay] = domain
	return false, nil
}

func (f *Fake) CommitDiskOverlay(domain, diskPath, overlay string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pitCommitErr != nil {
		return f.pitCommitErr
	}
	if f.pitOn[overlay] == domain {
		delete(f.pitOn, overlay)
	}
	return nil
}

func (f *Fake) DomainUsesFile(domain, path string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.pitOn[path] == domain, nil
}
