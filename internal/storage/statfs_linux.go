package storage

import (
	"fmt"
	"syscall"
)

// statfsInfo returns the filesystem magic and f_fsid of path; tests replace it.
var statfsInfo = func(path string) (uint32, string, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, "", err
	}
	return uint32(st.Type), fmt.Sprintf("%08x%08x", uint32(st.Fsid.X__val[0]), uint32(st.Fsid.X__val[1])), nil
}
