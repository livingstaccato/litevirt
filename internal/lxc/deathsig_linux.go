//go:build linux

package lxc

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// The daemon runs under KillMode=process, so a tool it spawned outlives it
// unless told otherwise. A tool working in a staging directory (umoci
// unpacking a replacing pull, lxc-create fetching a recreate's image) gets
// SIGKILL when the daemon dies (dieWithDaemon); what it spawned in turn is
// not covered by that, so the start-up sweep stops any process still
// working inside a staging directory before removing it (stopWorkersIn).

// dieWithDaemon makes cmd receive SIGKILL when the daemon dies. The signal
// is tied to the OS thread that starts cmd, so run it with runPinned.
func dieWithDaemon(cmd *exec.Cmd) *exec.Cmd {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	return cmd
}

// runPinned runs fn (which starts and waits for a dieWithDaemon command) on
// one locked OS thread, so the thread the parent-death signal is tied to
// lives until the command has exited.
func runPinned(fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return fn()
}

// stopWorkersIn sends SIGKILL to every other process working inside dir,
// and waits up to five seconds for them to exit. /proc/<pid>/{cwd,root,fd}
// read as paths only within the reader's own mount namespace: a process in
// another one (a container, a nested litevirt) renders its own paths, which
// may be spelled like dir without being in it. So a process whose links
// read as inside dir is stopped only when it shares this mount namespace,
// or when the object a link leads to is dir or an entry under it (same
// device and inode). Each is signalled through a pidfd opened before its
// links are read again, so a reused PID is never hit.
func stopWorkersIn(dir string) {
	dir = canonPath(dir)
	objs := stageObjects(dir)
	selfNS, _ := os.Readlink("/proc/self/ns/mnt")
	ents, err := os.ReadDir("/proc")
	if err != nil {
		return
	}
	self := os.Getpid()
	var fds []int
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid == self || !worksIn(pid, dir, objs, selfNS) {
			continue
		}
		pfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			continue
		}
		// The pidfd pins this process: if the PID was reused before it was
		// opened, the links read again now are the new process's.
		if !worksIn(pid, dir, objs, selfNS) || unix.PidfdSendSignal(pfd, unix.SIGKILL, nil, 0) != nil {
			_ = unix.Close(pfd)
			continue
		}
		fds = append(fds, pfd)
	}
	deadline := time.Now().Add(5 * time.Second)
	for _, pfd := range fds {
		for {
			ms := int(time.Until(deadline) / time.Millisecond)
			if ms <= 0 {
				break
			}
			if _, err := unix.Poll([]unix.PollFd{{Fd: int32(pfd), Events: unix.POLLIN}}, ms); err != unix.EINTR {
				break
			}
		}
		_ = unix.Close(pfd)
	}
}

// worksIn reports whether process pid has its cwd, root or an open file
// inside dir (see stopWorkersIn for what counts).
func worksIn(pid int, dir string, objs map[devIno]bool, selfNS string) bool {
	base := filepath.Join("/proc", strconv.Itoa(pid))
	under := func(p string) bool { return p == dir || strings.HasPrefix(p, dir+"/") }
	links := []string{filepath.Join(base, "cwd"), filepath.Join(base, "root")}
	if fds, err := os.ReadDir(filepath.Join(base, "fd")); err == nil {
		for _, fd := range fds {
			links = append(links, filepath.Join(base, "fd", fd.Name()))
		}
	}
	var sameNS *bool
	for _, l := range links {
		t, err := os.Readlink(l)
		if err != nil || !under(strings.TrimSuffix(t, " (deleted)")) {
			continue
		}
		if sameNS == nil {
			ns, _ := os.Readlink(filepath.Join(base, "ns", "mnt"))
			v := ns != "" && ns == selfNS
			sameNS = &v
		}
		if *sameNS {
			return true
		}
		if st, err := os.Stat(l); err == nil && objs[devInoOf(st)] {
			return true
		}
	}
	return false
}

type devIno struct{ dev, ino uint64 }

func devInoOf(fi os.FileInfo) devIno {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return devIno{uint64(st.Dev), st.Ino}
	}
	return devIno{}
}

// stageObjects is the (device, inode) of dir and of every entry under it.
func stageObjects(dir string) map[devIno]bool {
	objs := map[devIno]bool{}
	_ = filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if fi, err := os.Lstat(p); err == nil {
			objs[devInoOf(fi)] = true
		}
		return nil
	})
	return objs
}

// flockTry takes an exclusive flock on f without waiting: false while
// another open file description holds it.
func flockTry(f *os.File) (bool, error) {
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		switch err {
		case nil:
			return true, nil
		case unix.EWOULDBLOCK:
			return false, nil
		case unix.EINTR:
			continue
		default:
			return false, err
		}
	}
}

// openedFilePath is the path the open file f really is, symlinks resolved
// (/proc/self/fd), or its name when that cannot be read.
func openedFilePath(f *os.File) (string, error) {
	p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(f.Fd())))
	if err != nil {
		return "", fmt.Errorf("cannot tell what %s is: %w", f.Name(), err)
	}
	if strings.HasSuffix(p, " (deleted)") {
		return "", fmt.Errorf("%s was removed while it was opened", f.Name())
	}
	return p, nil
}

// openNoFollow opens path as a reference only (O_PATH): no driver's open
// runs and a FIFO cannot block, and a link at its own name is the link
// itself. The caller judges it (fstat, the path check) before reopenRead.
func openNoFollow(path string, dir bool) (*os.File, error) {
	flags := unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if dir {
		flags |= unix.O_DIRECTORY
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

// reopenRead opens for reading the object ref (from openNoFollow) refers to,
// through /proc/self/fd: the same object, never the path again.
func reopenRead(ref *os.File, dir bool) (*os.File, error) {
	flags := os.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if dir {
		flags |= unix.O_DIRECTORY
	}
	return os.OpenFile("/proc/self/fd/"+strconv.Itoa(int(ref.Fd())), flags, 0)
}

// stagingStatfs is a directory's filesystem free space for an unprivileged
// writer and its size.
func stagingStatfs(dir string) (avail, total uint64, err error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}
