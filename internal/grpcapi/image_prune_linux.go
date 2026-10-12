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
// qemu holds every layer of its disks' chains), that process, described. It
// reads every process in /proc (processesHoldingIn).
func processesHolding(paths []string) (map[string]string, error) {
	return processesHoldingIn("/proc", func(string) bool { return true }, paths)
}

// processesHoldingIn is processesHolding over the processes under procRoot
// that want accepts. A process that exits during the read is passed over. One
// whose open files cannot be read (a daemon not running as root cannot read
// another user's) fails the answer closed: the error says which, and the
// holders found are still returned, so a caller keeps every file either way.
func processesHoldingIn(procRoot string, want func(pid string) bool, paths []string) (map[string]string, error) {
	type fileID struct{ dev, ino uint64 }
	targets := map[fileID]string{}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		if st, ok := fi.Sys().(*syscall.Stat_t); ok {
			targets[fileID{uint64(st.Dev), st.Ino}] = p
		}
	}
	out := map[string]string{}
	if len(targets) == 0 {
		return out, nil
	}
	procs, err := os.ReadDir(procRoot)
	if err != nil {
		return nil, err
	}
	gone := func(err error) bool { return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) }
	var unreadable []string
	for _, pe := range procs {
		pid := pe.Name()
		if _, err := strconv.Atoi(pid); err != nil || !want(pid) {
			continue
		}
		fdDir := filepath.Join(procRoot, pid, "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			if !gone(err) {
				unreadable = append(unreadable, fmt.Sprintf("%s (%v)", fdDir, err))
			}
			continue
		}
		for _, fd := range fds {
			fi, err := os.Stat(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				if !gone(err) {
					unreadable = append(unreadable, fmt.Sprintf("%s/%s (%v)", fdDir, fd.Name(), err))
				}
				continue
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok {
				continue
			}
			if p, hit := targets[fileID{uint64(st.Dev), st.Ino}]; hit && out[p] == "" {
				comm, _ := os.ReadFile(filepath.Join(procRoot, pid, "comm"))
				out[p] = fmt.Sprintf("process %s (%s)", pid, strings.TrimSpace(string(comm)))
			}
		}
	}
	if len(unreadable) > 0 {
		return out, fmt.Errorf("the open files of %d process(es) could not be read, first %s", len(unreadable), unreadable[0])
	}
	return out, nil
}

// networkFilesystems are the filesystems (statfs f_type) another host may
// mount too: network filesystems, and FUSE, which may be one.
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

// statfsType is the statfs f_type of the filesystem dir is on, as the 32-bit
// magic it is, whatever width the field has on the arch.
var statfsType = func(dir string) (uint32, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return 0, err
	}
	return uint32(st.Type), nil
}

// networkFilesystem is the network filesystem dir is on ("" for a local one).
func networkFilesystem(dir string) (string, error) {
	t, err := statfsType(dir)
	if err != nil {
		return "", err
	}
	return networkFilesystems[t], nil
}
