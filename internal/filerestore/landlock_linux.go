//go:build linux

package filerestore

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Landlock confines the restore qemu on every host whose kernel has it,
// whatever else runs there (it stacks with AppArmor and SELinux), and is the
// only MAC barrier on a host without AppArmor. The trampoline's exec stage
// applies the ruleset to itself after no_new_privs and immediately before it
// execs qemu, so qemu starts inside it and can never leave it.
//
// What the ruleset allows qemu (landlockPolicy, built by the daemon):
//   - read and execute: its own binary, /usr, /lib*, /bin, /sbin;
//   - read: /etc/ld.so.cache, its boot files and their cache, its session
//     directory, its own /proc/<pid>, a few /proc/sys and /sys files,
//     /dev/urandom;
//   - read-write (and device ioctls): /dev/kvm and /dev/null.
//
// Everything else is refused: /var/lib/litevirt and every VM disk (which may
// be world-readable), data_dir, other sessions' directories, writes anywhere.
// With Landlock ABI 4 (Linux 6.7) TCP bind and connect are refused; with ABI
// 6 (Linux 6.12) abstract unix sockets and signals to processes outside the
// ruleset are too. Older ABIs give the filesystem part only. The vhost-vsock
// fd qemu inherits was opened before the ruleset and is not affected.

// Landlock scopes (ABI 6), not yet named in x/sys.
const (
	landlockScopeAbstractUnix = 0x1
	landlockScopeSignal       = 0x2
)

// landlockAvailable is the kernel's Landlock ABI version; 0 when it has
// none or it is not enabled (lsm=).
func landlockAvailable() int {
	r, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0
	}
	return int(r)
}

// landlockPolicy is what a restore qemu may reach once restricted. Paths
// that do not exist are skipped.
type landlockPolicy struct {
	ABI  int      `json:"abi"`
	Exec []string `json:"x,omitempty"` // read and execute (files and trees)
	Read []string `json:"r,omitempty"` // read
	Dev  []string `json:"d,omitempty"` // read, write, device ioctls (device nodes)
	RW   []string `json:"w,omitempty"` // read, create and write files (tests only)
}

func (p *landlockPolicy) merge(o landlockPolicy) {
	p.Exec = append(p.Exec, o.Exec...)
	p.Read = append(p.Read, o.Read...)
	p.Dev = append(p.Dev, o.Dev...)
	p.RW = append(p.RW, o.RW...)
}

// landlockFSHandled is every filesystem access right abi knows: all of them
// are refused unless a rule grants them.
func landlockFSHandled(abi int) uint64 {
	h := uint64(unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_READ_FILE |
		unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE |
		unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM)
	if abi >= 2 {
		h |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 3 {
		h |= unix.LANDLOCK_ACCESS_FS_TRUNCATE
	}
	if abi >= 5 {
		h |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	return h
}

// landlockFileRights are the rights a rule on a file (not a directory) may
// carry.
const landlockFileRights = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV

// restrictSelf applies p to the calling thread (which must have
// no_new_privs set and must be the thread that then execs): every access
// right the kernel's ABI knows is handled, and only the policy's paths are
// granted. It then checks the ruleset took: the root directory must no
// longer be readable.
func (p landlockPolicy) restrictSelf() error {
	abi := landlockAvailable()
	if abi < 1 {
		return errors.New("this kernel has no Landlock")
	}
	if p.ABI > 0 && abi < p.ABI {
		return fmt.Errorf("Landlock ABI %d, the daemon saw %d", abi, p.ABI)
	}
	handled := landlockFSHandled(abi)
	attr := unix.LandlockRulesetAttr{Access_fs: handled}
	if abi >= 4 {
		// No rule grants either: no TCP at all.
		attr.Access_net = unix.LANDLOCK_ACCESS_NET_BIND_TCP | unix.LANDLOCK_ACCESS_NET_CONNECT_TCP
	}
	if abi >= 6 {
		attr.Scoped = landlockScopeAbstractUnix | landlockScopeSignal
	}
	fd, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr), 0)
	if e != 0 {
		return fmt.Errorf("landlock_create_ruleset: %v", e)
	}
	defer unix.Close(int(fd))

	const rx = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	const ro = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	const dev = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	const rw = ro | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_REG |
		unix.LANDLOCK_ACCESS_FS_TRUNCATE | unix.LANDLOCK_ACCESS_FS_REMOVE_FILE
	for _, g := range []struct {
		paths  []string
		access uint64
	}{{p.Exec, rx}, {p.Read, ro}, {p.Dev, dev}, {p.RW, rw}} {
		for _, path := range g.paths {
			if err := landlockAllow(int(fd), path, g.access&handled); err != nil {
				return err
			}
		}
	}
	if _, _, e := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, fd, 0, 0); e != 0 {
		return fmt.Errorf("landlock_restrict_self: %v", e)
	}
	// It took: nothing grants the root directory.
	if d, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); err == nil {
		unix.Close(d)
		return errors.New("the Landlock ruleset did not take effect (/ is still readable)")
	}
	return nil
}

// landlockAllow grants access beneath path (a missing path is skipped).
func landlockAllow(ruleset int, path string, access uint64) error {
	pfd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("landlock: open %s: %v", path, err)
	}
	defer unix.Close(pfd)
	var st unix.Stat_t
	if err := unix.Fstat(pfd, &st); err != nil {
		return fmt.Errorf("landlock: stat %s: %v", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		access &= landlockFileRights
	}
	if access == 0 {
		return nil
	}
	rule := unix.LandlockPathBeneathAttr{Allowed_access: access, Parent_fd: int32(pfd)}
	if _, _, e := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(ruleset), unix.LANDLOCK_RULE_PATH_BENEATH,
		uintptr(unsafe.Pointer(&rule)), 0, 0, 0); e != 0 {
		return fmt.Errorf("landlock: allow %s: %v", path, e)
	}
	return nil
}

// restorePolicy is the Landlock ruleset of one restore VM's qemu (spec);
// nil when the kernel has no Landlock.
func (l *Launcher) restorePolicy(h *host, sessionDir string, spec VMSpec) *landlockPolicy {
	if h.landlock < 1 {
		return nil
	}
	p := &landlockPolicy{
		ABI:  h.landlock,
		Exec: []string{h.qemu, "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/bin", "/sbin"},
		Read: []string{
			"/etc/ld.so.cache", l.cfg.CacheDir, sessionDir,
			// Its boot files: in the cache, but a non-root daemon's qemu
			// reads the kernel where it is.
			spec.Kernel, spec.Initrd,
			// Its own /proc/<pid>: the exec stage resolves /proc/self, and
			// qemu keeps that pid.
			"/proc/self",
			"/proc/sys/vm/overcommit_memory", "/proc/sys/kernel/cap_last_cap",
			"/sys/devices/system/cpu", "/sys/devices/system/node",
			"/sys/kernel/mm/transparent_hugepage", "/sys/module/vhost/parameters",
			"/dev/urandom",
		},
		Dev: []string{l.kvmPath, os.DevNull},
	}
	p.merge(l.landlockExtra)
	return p
}
