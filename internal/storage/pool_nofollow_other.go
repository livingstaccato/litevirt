//go:build !linux

package storage

import "os"

// openat2Beneath: no openat2 off Linux; the O_NOFOLLOW walk is used.
func openat2Beneath(root, rel string, flag int, perm os.FileMode, name string) (*os.File, error) {
	return nil, errNoOpenat2
}

// openat2Disabled has no effect off Linux.
var openat2Disabled = false

// kernelHasNosymfollow: off Linux there is no NFS pool mount to harden; it is
// required, as on a current kernel.
var kernelHasNosymfollow = func() bool { return true }
