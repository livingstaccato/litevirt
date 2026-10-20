//go:build linux

package lxc

import (
	"errors"
	"fmt"
	"log/slog"
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

// stopWorkersIn sends SIGKILL to every other process working inside dir and
// waits for each to exit, then scans again: a worker can fork a child after a
// scan read /proc, and that child is in no earlier snapshot. It returns nil
// only once a scan finds nobody working in dir; it fails (and the caller
// keeps the stage) when a worker cannot be signalled or waited for, or when
// workers keep appearing.
//
// /proc/<pid>/{cwd,root,fd} read as paths only within the reader's own mount
// namespace: a process in another one (a container, a nested litevirt)
// renders its own paths, which may be spelled like dir without being in it.
// So a process whose links read as inside dir is stopped only when it shares
// this mount namespace, or when the object a link leads to is dir or an entry
// under it (same device and inode). Each is signalled through a pidfd opened
// before its links are read again, so a reused PID is never hit.
func stopWorkersIn(dir string) error {
	dir = canonPath(dir)
	selfNS, _ := os.Readlink("/proc/self/ns/mnt")
	self := os.Getpid()
	for round := 0; round < stopRounds; round++ {
		objs := stageObjects(dir)
		ents, err := os.ReadDir("/proc")
		if err != nil {
			return fmt.Errorf("list processes: %w", err)
		}
		afterProcScan()
		var fds []int
		fail := func(err error) error {
			for _, fd := range fds {
				_ = unix.Close(fd)
			}
			return err
		}
		for _, e := range ents {
			pid, err := strconv.Atoi(e.Name())
			if err != nil || pid == self {
				continue
			}
			if hit, _ := worksIn(pid, dir, objs, selfNS); !hit {
				continue
			}
			pfd, err := pidfdOpen(pid, 0)
			if err != nil {
				if errors.Is(err, unix.ESRCH) {
					continue // it exited meanwhile
				}
				return fail(fmt.Errorf("cannot stop pid %d working in %s: %w", pid, dir, err))
			}
			// The pidfd pins this process: if the PID was reused before it
			// was opened, the links read again now are the new process's.
			hit, why := worksIn(pid, dir, objs, selfNS)
			if !hit {
				_ = unix.Close(pfd)
				continue
			}
			comm, _ := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
			if err := unix.PidfdSendSignal(pfd, unix.SIGKILL, nil, 0); err != nil && !errors.Is(err, unix.ESRCH) {
				_ = unix.Close(pfd)
				return fail(fmt.Errorf("cannot stop pid %d working in %s: %w", pid, dir, err))
			}
			slog.Info("container staging: stopped a process still working in a stage",
				"pid", pid, "comm", strings.TrimSpace(string(comm)), "stage", dir, "why", why)
			fds = append(fds, pfd)
		}
		if len(fds) == 0 {
			return nil // a whole scan found nobody: the stage is quiet
		}
		deadline := time.Now().Add(5 * time.Second)
		var waitErr error
		for _, pfd := range fds {
			if err := waitPidfd(pfd, deadline); err != nil && waitErr == nil {
				waitErr = err
			}
			_ = unix.Close(pfd)
		}
		if waitErr != nil {
			return fmt.Errorf("a process working in %s did not exit: %w", dir, waitErr)
		}
	}
	return fmt.Errorf("processes kept appearing in %s after %d rounds", dir, stopRounds)
}

// stopRounds bounds how many times stopWorkersIn scans for workers.
const stopRounds = 20

// waitPidfd waits until the process pfd refers to has exited, or deadline.
func waitPidfd(pfd int, deadline time.Time) error {
	for {
		ms := int(time.Until(deadline) / time.Millisecond)
		if ms <= 0 {
			return errors.New("timed out waiting for it to exit")
		}
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(pfd), Events: unix.POLLIN}}, ms)
		switch {
		case err == unix.EINTR:
			continue
		case err != nil:
			return err
		case n > 0:
			return nil
		}
	}
}

// test seams
var (
	afterProcScan = func() {}
	pidfdOpen     = unix.PidfdOpen
)

// worksIn reports whether process pid has its cwd, root or an open file
// inside dir (see stopWorkersIn for what counts).
func worksIn(pid int, dir string, objs map[devIno]bool, selfNS string) (bool, string) {
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
		what := filepath.Base(l)
		if filepath.Base(filepath.Dir(l)) == "fd" {
			what = "an open file"
		}
		if *sameNS {
			return true, what + " in the stage (" + t + "), in the daemon's mount namespace"
		}
		if st, err := os.Stat(l); err == nil && objs[devInoOf(st)] {
			return true, what + " is the stage's own object (" + t + "), in another mount namespace"
		}
	}
	return false, ""
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
