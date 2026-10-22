//go:build !linux && !darwin

package pressure

import "errors"

// OSFS has no statfs on this platform.
type OSFS struct{}

// Statfs always fails here.
func (OSFS) Statfs(string) (FSStat, error) {
	return FSStat{}, errors.New("statfs: not supported on this platform")
}

func processFDs() (used, limit uint64, ok bool) { return 0, 0, false }
