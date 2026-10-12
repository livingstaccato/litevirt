package grpcapi

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// processesHolding is, for each of paths a process holds open (a running
// qemu holds every layer of its disks' chains), that process, described.
// A process this daemon may not look into (it runs as root, so none) or one
// that exits during the read is passed over.
func processesHolding(paths []string) (map[string]string, error) {
	type fileID struct{ dev, ino uint64 }
	want := map[fileID]string{}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			want[fileID{uint64(st.Dev), st.Ino}] = p
		}
	}
	out := map[string]string{}
	if len(want) == 0 {
		return out, nil
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, pe := range procs {
		pid := pe.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue
		}
		fdDir := filepath.Join("/proc", pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrPermission) || errors.Is(err, syscall.ESRCH) {
				continue
			}
			return nil, fmt.Errorf("read %s: %w", fdDir, err)
		}
		for _, fd := range fds {
			fi, err := os.Stat(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if p, hit := want[fileID{uint64(st.Dev), st.Ino}]; hit && out[p] == "" {
				comm, _ := os.ReadFile(filepath.Join("/proc", pid, "comm"))
				out[p] = fmt.Sprintf("process %s (%s)", pid, strings.TrimSpace(string(comm)))
			}
		}
	}
	return out, nil
}

// networkFilesystems are the filesystems (statfs f_type) another host may
// mount too.
var networkFilesystems = map[uint32]string{
	0x6969:     "nfs",
	0x517b:     "smb",
	0xff534d42: "cifs",
	0xfe534d42: "smb2",
	0x65735546: "fuse",
	0x00c36400: "ceph",
	0x01161970: "gfs2",
	0x7461636f: "ocfs2",
	0x5346414f: "afs",
	0x01021997: "9p",
	0x0bd00bd0: "lustre",
	0x47504653: "gpfs",
	0x013111a8: "ibrix",
	0x6b414653: "kafs",
}

// networkFilesystem is the network filesystem dir is on ("" for a local one).
func networkFilesystem(dir string) (string, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return "", err
	}
	// f_type is a 32-bit magic, whatever width the field has on the arch.
	return networkFilesystems[uint32(st.Type)], nil
}
