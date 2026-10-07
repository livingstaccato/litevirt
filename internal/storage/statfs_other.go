//go:build !linux

package storage

import "errors"

// statfsInfo returns the filesystem magic and f_fsid of path; tests replace it.
var statfsInfo = func(string) (uint32, string, error) {
	return 0, "", errors.New("statfs: not supported on this platform")
}
