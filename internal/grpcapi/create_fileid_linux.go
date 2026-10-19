//go:build linux

package grpcapi

import "golang.org/x/sys/unix"

// fileBirth is p's birth time in nanoseconds, or 0 where the filesystem keeps
// none or it cannot be read.
func fileBirth(p string) int64 {
	var stx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, p, 0, unix.STATX_BTIME, &stx); err != nil || stx.Mask&unix.STATX_BTIME == 0 {
		return 0
	}
	return stx.Btime.Sec*1e9 + int64(stx.Btime.Nsec)
}
