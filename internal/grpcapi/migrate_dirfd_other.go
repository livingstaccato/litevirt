//go:build !linux

package grpcapi

// openat2Beneath: there is no openat2 off Linux. The daemon only runs on Linux
// (its held directories are /proc/self/fd forms, which fail closed elsewhere:
// openPinnedDirChecked refuses with errNoProcFD); this only lets the client
// build compile.
func openat2Beneath(dirfd int, name string) (fd int, used bool, err error) {
	return -1, false, nil
}
