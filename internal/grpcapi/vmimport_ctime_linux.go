package grpcapi

import (
	"os"
	"syscall"
)

// fileCtimeNs is fi's change time in nanoseconds, or 0.
func fileCtimeNs(fi os.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int64(st.Ctim.Sec)*1e9 + int64(st.Ctim.Nsec)
	}
	return 0
}
