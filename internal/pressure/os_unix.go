//go:build linux || darwin

package pressure

import (
	"io"
	"os"
	"sync"
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

// fdDir is a descriptor for the process's descriptor directory, opened on
// the first count and held: counting through a fresh open needs a free
// descriptor, which there is not at the limit, the one moment the count
// matters.
var fdDir struct {
	sync.Mutex
	f *os.File
}

// processFDs counts this process's open descriptors against its soft
// RLIMIT_NOFILE. ok is false when they cannot be counted.
func processFDs() (used, limit uint64, ok bool) {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil || rl.Cur == 0 {
		return 0, 0, false
	}
	fdDir.Lock()
	defer fdDir.Unlock()
	if fdDir.f == nil {
		for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
			if f, err := os.Open(dir); err == nil {
				fdDir.f = f
				break
			}
		}
		if fdDir.f == nil {
			return 0, 0, false
		}
	}
	if _, err := fdDir.f.Seek(0, io.SeekStart); err != nil {
		return 0, 0, false
	}
	names, err := fdDir.f.Readdirnames(-1)
	if err != nil {
		return 0, 0, false
	}
	return uint64(len(names)), uint64(rl.Cur), true
}
