package libvirt

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// partitionKillExitWait bounds how long KillPartitionPaused waits, after the
// SIGKILL, for the QEMU to have exited. It stays inside the partition
// pauser's per-call timeout (2 s), so a QEMU that has not exited by then is
// this call's own error, not the pauser's timeout.
const partitionKillExitWait = 1500 * time.Millisecond

// waitPidfdExit waits up to d for the process behind pidfd to have exited,
// and reports whether it has. A pidfd turns readable only once the process
// has exited, after its files are closed (and their writeback flushed or
// failed) and its aio drained. A variable so a test can stand in a process
// that never gets there, as a QEMU in an uninterruptible wait on cut
// storage does not.
var waitPidfdExit = func(pidfd int, d time.Duration) (bool, error) {
	deadline := time.Now().Add(d)
	for {
		left := time.Until(deadline)
		if left < 0 {
			left = 0
		}
		fds := []unix.PollFd{{Fd: int32(pidfd), Events: unix.POLLIN}}
		n, err := unix.Poll(fds, int(left.Milliseconds()))
		if errors.Is(err, unix.EINTR) {
			if left == 0 {
				return false, nil
			}
			continue
		}
		if err != nil {
			return false, err
		}
		if n > 0 && fds[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0 {
			return true, nil
		}
		if left == 0 || time.Now().After(deadline) {
			return false, nil
		}
	}
}

// KillPartitionPaused SIGKILLs the QEMU process of domain name without going
// through libvirt. The partition pauser calls it for a domain whose resume
// it abandoned while that libvirt call is still out under a lost majority:
// the call may land at any moment, and a suspend issued after it is not
// sure to come after it, while a killed process runs no guest code again —
// the fatal signal makes every vCPU thread leave KVM_RUN and never enter it
// again, even while some other thread of the process sits in an
// uninterruptible wait. libvirt then reports the domain shut off, crashed.
//
// The pid is libvirt's own pid file for the domain, and the process is
// killed only if its command line is that domain's QEMU: -uuid uuid, or,
// with uuid "", -name guest=name. A pidfd taken before the check is what is
// signalled, so a pid that ended and was reused in between is never hit.
// No pid file is an error (nothing proves no QEMU runs); a pid file whose
// process is gone is success: nothing is left for the call to land on.
//
// Success means the QEMU has EXITED, not that the signal is queued. A QEMU
// killed with dirty writeback-cache pages for its disks flushes them on
// exit, and with its storage cut it sits in an uninterruptible wait with
// them still in this host's page cache, to be written over the
// replacement's disk when the storage returns. So the kill waits for the
// exit (partitionKillExitWait), and a QEMU that has not exited by then is
// an error: the pauser reports the pause failed and self-fences, as for a
// suspend whose flush hangs.
func (c *Client) KillPartitionPaused(name, uuid string) error {
	return killQEMU(DefaultQEMURunDir, DefaultProcRoot, name, uuid)
}

func killQEMU(runDir, procRoot, name, uuid string) error {
	if name == "" || strings.ContainsAny(name, "/\x00") {
		return fmt.Errorf("kill qemu: invalid domain name %q", name)
	}
	pid, err := readPidFile(filepath.Join(runDir, name+".pid"))
	if err != nil {
		return fmt.Errorf("kill qemu of %s: pid file: %w", name, err)
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if errors.Is(err, unix.ESRCH) {
		return nil // the process is gone: nothing can land on it
	}
	if err != nil {
		return fmt.Errorf("kill qemu of %s: pidfd of %d: %w", name, pid, err)
	}
	defer unix.Close(pidfd)
	argv, err := readCmdline(dirProc(procRoot), pid)
	if errors.Is(err, fs.ErrNotExist) {
		return nil // exited since the pidfd was taken
	}
	if err != nil {
		return fmt.Errorf("kill qemu of %s: cmdline of %d: %w", name, pid, err)
	}
	if !isQEMUOf(argv, name, uuid) {
		return fmt.Errorf("kill qemu of %s: pid %d is not its QEMU (stale or reused pid file)", name, pid)
	}
	if err := unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return nil
		}
		return fmt.Errorf("kill qemu of %s: pid %d: %w", name, pid, err)
	}
	exited, err := waitPidfdExit(pidfd, partitionKillExitWait)
	if err != nil {
		return fmt.Errorf("kill qemu of %s: pid %d killed, waiting for its exit: %w", name, pid, err)
	}
	if !exited {
		return fmt.Errorf("kill qemu of %s: pid %d killed but has not exited within %s (its I/O may still be pending)", name, pid, partitionKillExitWait)
	}
	return nil
}

// isQEMUOf reports whether argv is the QEMU libvirt started for domain name:
// it carries -uuid uuid, or, with uuid "", -name guest=name[,...] (or the
// older -name name).
func isQEMUOf(argv []string, name, uuid string) bool {
	if uuid != "" {
		return argPairEqualFold(argv, "-uuid", uuid)
	}
	for i := 0; i+1 < len(argv); i++ {
		if argv[i] != "-name" {
			continue
		}
		v := argv[i+1]
		if g, ok := strings.CutPrefix(v, "guest="); ok {
			v = g
		}
		if first, _, _ := strings.Cut(v, ","); first == name {
			return true
		}
	}
	return false
}
