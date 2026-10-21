//go:build linux || darwin

package pressure

import (
	"os"
	"syscall"

	"github.com/litevirt/litevirt/internal/storage"
)

// OSFS is statfs(2) under storage.Bounded: a pool on a network mount whose
// server stops answering yields an error, not a sampler blocked in the
// kernel.
type OSFS struct{}

// Statfs reads path's filesystem.
func (OSFS) Statfs(path string) (FSStat, error) {
	return storage.Bounded("statfs (pressure)", path, func() (FSStat, error) {
		var st syscall.Statfs_t
		if err := syscall.Statfs(path, &st); err != nil {
			return FSStat{}, err
		}
		bs := uint64(st.Bsize)
		return FSStat{
			AvailBytes:  uint64(st.Bavail) * bs,
			TotalBytes:  uint64(st.Blocks) * bs,
			FreeInodes:  uint64(st.Ffree),
			TotalInodes: uint64(st.Files),
		}, nil
	})
}

// processFDs counts this process's open descriptors against its soft
// RLIMIT_NOFILE.
func processFDs() (used, limit uint64, ok bool) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil || rl.Cur == 0 {
		return 0, 0, false
	}
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		ents, err := os.ReadDir(dir)
		if err == nil {
			return uint64(len(ents)), uint64(rl.Cur), true
		}
	}
	return 0, 0, false
}
