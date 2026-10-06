package grpcapi

import (
	"os"
	"syscall"
)

// linkCount reports the file's hard-link count where the platform exposes it.
func linkCount(fi os.FileInfo) (uint64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return uint64(st.Nlink), true
}
