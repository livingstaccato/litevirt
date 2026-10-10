//go:build linux

package agent

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// IsAgent reports whether this process is the restore agent: PID 1 of a
// restore VM, started by a kernel command line carrying the agent marker
// (the kernel hands unknown name=value parameters to init as environment).
func IsAgent() bool {
	return os.Getpid() == 1 && os.Getenv(wire.EnvAgent) == "1"
}

// RunAgent is the restore VM's init. It never returns: whatever happens, the
// VM powers off at the end (and the host kills it after its idle timeout
// anyway).
func RunAgent() {
	log.SetFlags(0)
	log.SetPrefix("litevirt-file-restore: ")
	if err := runAgent(); err != nil {
		log.Printf("error: %v", err)
	}
	unix.Sync()
	_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
	for {
		time.Sleep(time.Hour)
	}
}

// defaultIdle is the agent's idle timeout when the command line names none.
const defaultIdle = 10 * time.Minute

// idleTimeout is how long the agent waits for a request before powering the
// VM off on its own (wire.EnvIdle). It is the backstop for a host that went
// away without killing its VM: a daemon that died, or restarted.
func idleTimeout() time.Duration {
	if n, err := strconv.Atoi(os.Getenv(wire.EnvIdle)); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return defaultIdle
}

// watchdog powers the VM off once last (unix nanoseconds) is older than idle.
func watchdog(last *atomic.Int64, idle time.Duration) {
	for {
		time.Sleep(time.Second)
		if time.Since(time.Unix(0, last.Load())) > idle {
			log.Printf("no request for %v: powering off", idle)
			unix.Sync()
			_ = unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		}
	}
}

func runAgent() error {
	var last atomic.Int64
	last.Store(time.Now().UnixNano())
	go watchdog(&last, idleTimeout())

	for _, m := range []struct{ src, dst, fs string }{
		{"proc", "/proc", "proc"},
		{"sysfs", "/sys", "sysfs"},
		{"devtmpfs", "/dev", "devtmpfs"},
	} {
		_ = os.MkdirAll(m.dst, 0o755)
		if err := unix.Mount(m.src, m.dst, m.fs, unix.MS_NOSUID|unix.MS_NOEXEC, ""); err != nil && !errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("mount %s: %w", m.dst, err)
		}
	}
	loadModules("/modules")

	dev := "/dev/vda"
	if err := waitFor(dev, 20*time.Second); err != nil {
		return err
	}
	// The disk is attached read-only; make the kernel's view say so too.
	if f, err := os.Open(dev); err == nil {
		one := 1
		_, _, _ = unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKROSET, uintptr(unsafe.Pointer(&one)))
		f.Close()
	}

	vols := map[string]Volume{}
	switch os.Getenv(wire.EnvKind) {
	case wire.KindArchive:
		f, err := os.Open(dev)
		if err != nil {
			return err
		}
		size, err := f.Seek(0, io.SeekEnd)
		if err != nil {
			return err
		}
		v, name, err := indexTar(f, size)
		if err != nil {
			return err
		}
		vols[name] = v
	default:
		for _, cand := range blockCandidates("vda") {
			if v, err := mountReadOnly(cand); err == nil {
				vols[cand] = v
			} else {
				log.Printf("%s: %v", cand, err)
			}
		}
	}
	names := make([]string, 0, len(vols))
	for n := range vols {
		names = append(names, n)
	}
	sort.Strings(names)
	log.Printf("ready: volumes %v", names)

	srv := NewServer(vols, os.Getenv(wire.EnvNonce))
	srv.touch = func() { last.Store(time.Now().UnixNano()) }
	return serveVsock(srv)
}

// loadModules loads every module the initramfs lists, in order. A module
// that fails to load is logged; whatever it provided is then missing, which
// the host sees as a missing volume or no vsock.
func loadModules(dir string) {
	b, err := os.ReadFile(filepath.Join(dir, "order"))
	if err != nil {
		return
	}
	for _, name := range strings.Fields(string(b)) {
		f, err := os.Open(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		flags := 0
		if strings.HasSuffix(name, ".xz") {
			flags = unix.MODULE_INIT_COMPRESSED_FILE
		}
		if err := unix.FinitModule(int(f.Fd()), "", flags); err != nil && !errors.Is(err, unix.EEXIST) {
			log.Printf("module %s: %v", name, err)
		}
		f.Close()
	}
}

func waitFor(path string, d time.Duration) error {
	deadline := time.Now().Add(d)
	for {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("%s did not appear", path)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// blockCandidates lists disk's partitions (the guest kernel parsed its
// partition table), or the whole disk when it has none.
func blockCandidates(disk string) []string {
	ents, _ := os.ReadDir(filepath.Join("/sys/block", disk))
	var parts []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), disk) {
			if _, err := os.Stat(filepath.Join("/sys/block", disk, e.Name(), "partition")); err == nil {
				parts = append(parts, e.Name())
			}
		}
	}
	sort.Strings(parts)
	if len(parts) == 0 {
		return []string{disk}
	}
	return parts
}

// mountReadOnly mounts /dev/<name> read-only on /mnt/<name>, trying the
// filesystems the agent knows. Journal replay is off: the disk is read-only
// and a backup is never modified.
func mountReadOnly(name string) (Volume, error) {
	dst := filepath.Join("/mnt", name)
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil, err
	}
	flags := uintptr(unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC)
	var errs []string
	for _, t := range []struct{ fs, data string }{
		{"ext4", "noload"},
		{"xfs", "norecovery"},
		{"btrfs", "rescue=nologreplay"},
		{"vfat", ""},
		{"iso9660", ""},
	} {
		err := unix.Mount("/dev/"+name, dst, t.fs, flags, t.data)
		if err == nil {
			return &dirVolume{root: dst, fs: t.fs}, nil
		}
		errs = append(errs, t.fs+": "+err.Error())
	}
	return nil, fmt.Errorf("no supported filesystem (%s)", strings.Join(errs, "; "))
}

// serveVsock listens on wire.AgentPort and serves one host connection at a time
// until the host asks for shutdown.
func serveVsock(a *Server) error {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("vsock socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrVM{CID: unix.VMADDR_CID_ANY, Port: wire.AgentPort}); err != nil {
		return fmt.Errorf("vsock bind: %w", err)
	}
	if err := unix.Listen(fd, 1); err != nil {
		return fmt.Errorf("vsock listen: %w", err)
	}
	for {
		nfd, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC)
		if err != nil {
			if errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("vsock accept: %w", err)
		}
		conn := os.NewFile(uintptr(nfd), "vsock")
		shutdown, err := a.ServeConn(conn)
		conn.Close()
		if err != nil {
			log.Printf("connection: %v", err)
		}
		if shutdown {
			return nil
		}
	}
}
