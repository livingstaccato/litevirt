//go:build linux

package lxc

import (
	"errors"
	"fmt"
	"log/syslog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// hostAccessSupported reports whether this kernel has what the start hook
// needs: openat2 (5.6) and mount_setattr (5.12, the last of the new mount
// API). Without them host bind mounts are refused rather than mounted by path.
var hostAccessSupported = func() error {
	probeOnce.Do(func() { probeErr = probeMountAPI() })
	return probeErr
}

var (
	probeOnce sync.Once
	probeErr  error
)

func probeMountAPI() error {
	fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{
		Flags: unix.O_PATH | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return fmt.Errorf("openat2: %w", err)
	}
	unix.Close(fd)
	// An invalid fd: EBADF means the syscall exists, ENOSYS that it does not.
	if err := unix.MountSetattr(-1, "", 0, &unix.MountAttr{}); errors.Is(err, unix.ENOSYS) {
		return fmt.Errorf("mount_setattr: %w", err)
	}
	return nil
}

// openBeneath opens rel beneath the allowed prefix — the prefix itself with
// no symlink anywhere in it, and rel with no symlink, no magic link and no
// escape — as an O_PATH fd. A symlink swapped in anywhere along the way is
// refused by the kernel (ELOOP / EXDEV), never followed. A filesystem mounted
// beneath the prefix (a NAS) is crossed: what was opened is judged by the
// path the kernel resolved it to (stageMount, hookPolicy.judgeOpened).
func openBeneath(prefix, rel string) (int, error) {
	dirfd, err := unix.Openat2(unix.AT_FDCWD, prefix, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, fmt.Errorf("open allowed prefix %s: %w", prefix, err)
	}
	defer unix.Close(dirfd)
	fd, err := unix.Openat2(dirfd, rel, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return -1, fmt.Errorf("open %s beneath %s: %w", rel, prefix, err)
	}
	return fd, nil
}

// hookMounts reads the managed block's mount markers and the staging paths
// their entries name.
func hookMounts(cfg string) ([]hookMount, error) {
	block, ok := hostAccessBlockOf(cfg)
	if !ok {
		return nil, fmt.Errorf("host-access block is not closed")
	}
	var out []hookMount
	var pending *hookMount
	for _, line := range strings.Split(block, "\n") {
		if rest, ok := strings.CutPrefix(line, mountMarker+" "); ok {
			f := strings.Fields(rest)
			if len(f) != 4 || (f[0] != "ro" && f[0] != "rw") || (f[1] != "dir" && f[1] != "file") {
				return nil, fmt.Errorf("bad mount marker %q", line)
			}
			pending = &hookMount{ro: f[0] == "ro", file: f[1] == "file", prefix: f[2], rel: f[3]}
			continue
		}
		if k, v := configKey(line); k == "lxc.mount.entry" && pending != nil {
			f := strings.Fields(v)
			if len(f) < 2 || !strings.HasPrefix(f[0], stagingRoot+"/") {
				return nil, fmt.Errorf("mount entry %q does not name a staging path", line)
			}
			pending.staging = f[0]
			out = append(out, *pending)
			pending = nil
		}
	}
	return out, nil
}

// checkStagingPaths refuses a config any of whose entries does not name
// exactly its own staging path under stagingRoot, in order.
func checkStagingPaths(name string, mounts []hookMount) error {
	for i, m := range mounts {
		if want := stagingPath(name, i); m.staging != want {
			return fmt.Errorf("entry %d names %s, not %s", i, m.staging, want)
		}
	}
	return nil
}

// ensureStagingDir makes p a directory its owner (root, for the hook) alone
// can list, create or rename in, and refuses anything else found there — a
// symlink is never followed, so one planted at a staging path cannot redirect
// where host trees are staged. The mode is 0711, traverse only: LXC binds an
// unprivileged container's entries as that container's mapped root, which
// must reach its staged mounts through these directories. What it reaches
// there is governed by each staged tree's own mode, as it is at the source.
func ensureStagingDir(p string) error {
	if err := os.Mkdir(p, stagingDirMode); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	st, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("staging path %s is not a directory (%s)", p, st.Mode().Type())
	}
	if sys, ok := st.Sys().(*unix.Stat_t); ok && int(sys.Uid) != os.Geteuid() {
		return fmt.Errorf("staging path %s is owned by uid %d, not %d", p, sys.Uid, os.Geteuid())
	}
	return os.Chmod(p, stagingDirMode)
}

// stagingDirMode is the staging directories' mode: root's, traverse only.
const stagingDirMode = 0o711

// ensurePrivateStagingRoot makes root a root-owned, traverse-only directory
// on a mount of its own with private propagation, so staged mounts neither leak into nor
// arrive from other mount namespaces. The stock AppArmor profile of
// lxc-start allows each of these mounts beneath LXC's store (stagingRoot).
func ensurePrivateStagingRoot(root string) error {
	if err := os.MkdirAll(filepath.Dir(root), 0o755); err != nil {
		return err
	}
	if err := ensureStagingDir(root); err != nil {
		return err
	}
	if !isMountpoint(root) {
		if err := unix.Mount(root, root, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", root, err)
		}
	}
	return unix.Mount("", root, "", unix.MS_PRIVATE|unix.MS_REC, "")
}

// isMountpoint reports whether p is listed as a mount point in mountinfo.
func isMountpoint(p string) bool {
	b, err := os.ReadFile(mountinfoPath)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if f := strings.Fields(line); len(f) > 4 && f[4] == p {
			return true
		}
	}
	return false
}

// unmountAll detaches every mount stacked on p.
func unmountAll(p string) {
	for i := 0; i < 16; i++ {
		// Never through a symlink at p: one planted there would detach
		// whatever host mount it points at.
		if unmount(p, unix.MNT_DETACH|unix.UMOUNT_NOFOLLOW) != nil {
			return
		}
	}
}

// unmount is unix.Unmount (tests).
var unmount = unix.Unmount

// stageMount mounts one source onto its staging path from an fd: open
// beneath the prefix, clone exactly that tree (no submounts), set its
// attributes, move it into place. Nothing between the open and the mount
// goes through a path a container could rename.
func stageMount(m hookMount, policy hookPolicy) error {
	fd, err := openBeneath(m.prefix, m.rel)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// Judge what was opened, by the path the kernel resolved it to and the
	// mount it is on: a store or protected tree mounted over the source, or
	// reached through another mount of its filesystem, is refused here.
	opened, err := openedPath(fd)
	if err != nil {
		return fmt.Errorf("resolve the opened %s/%s: %w", m.prefix, m.rel, err)
	}
	mntID, err := openedMountID(fd)
	if err != nil {
		return fmt.Errorf("the mount of the opened %s/%s: %w", m.prefix, m.rel, err)
	}
	if err := policy.judgeOpened(m.prefix, opened, mntID); err != nil {
		return err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	isDir := st.Mode&unix.S_IFMT == unix.S_IFDIR
	isReg := st.Mode&unix.S_IFMT == unix.S_IFREG
	if (m.file && !isReg) || (!m.file && !isDir) {
		return fmt.Errorf("%s/%s changed kind since it was authorized", m.prefix, m.rel)
	}
	tree, err := unix.OpenTree(fd, "", unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC|unix.AT_EMPTY_PATH)
	if err != nil {
		return fmt.Errorf("clone %s/%s: %w", m.prefix, m.rel, err)
	}
	defer unix.Close(tree)
	attr := uint64(unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV)
	if m.ro {
		attr |= unix.MOUNT_ATTR_RDONLY
	}
	if err := unix.MountSetattr(tree, "", unix.AT_EMPTY_PATH, &unix.MountAttr{Attr_set: attr}); err != nil {
		return fmt.Errorf("set attributes on %s/%s: %w", m.prefix, m.rel, err)
	}
	unmountAll(m.staging)
	if m.file {
		f, err := os.OpenFile(m.staging, os.O_CREATE|os.O_RDONLY|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return err
		}
		f.Close()
	} else if err := ensureStagingDir(m.staging); err != nil {
		return err
	}
	if err := unix.MoveMount(tree, "", unix.AT_FDCWD, m.staging, unix.MOVE_MOUNT_F_EMPTY_PATH); err != nil {
		return fmt.Errorf("mount %s/%s at %s: %w", m.prefix, m.rel, m.staging, err)
	}
	return nil
}

// RunHook is the LXC start hook (`litevirt __lxc-hook`, configured as both
// lxc.hook.pre-start and lxc.hook.post-stop by the managed block). LXC runs it
// as root in the host's namespaces, with LXC_NAME, LXC_CONFIG_FILE and
// LXC_HOOK_TYPE set, on every start — a reboot from inside the container
// included. pre-start stages every mount from an fd (stageMount); a refusal
// fails the start. post-stop takes the staging mounts down. It returns the
// process exit code.
func RunHook(args []string) int {
	name, cfgPath, hook := os.Getenv("LXC_NAME"), os.Getenv("LXC_CONFIG_FILE"), os.Getenv("LXC_HOOK_TYPE")
	if hook == "" && len(args) >= 3 {
		hook = args[2]
	}
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		hookLog("no valid LXC_NAME")
		return 1
	}
	switch hook {
	case "post-stop":
		clearStaging(filepath.Join(stagingRoot, name))
		return 0
	case "pre-start":
	default:
		hookLog("unexpected hook type %q", hook)
		return 1
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		hookLog("read %s: %v", cfgPath, err)
		return 1
	}
	mounts, err := hookMounts(string(b))
	if err != nil {
		hookLog("%s: %v", name, err)
		return 1
	}
	devices, err := hookDevices(string(b))
	if err != nil {
		hookLog("%s: %v", name, err)
		return 1
	}
	// Re-judged against this host's policy as it is now (the daemon rewrites
	// it before every start it drives), not against the config: a reboot from
	// inside the container runs this hook with no daemon in the loop.
	policy, err := readHookPolicy(name)
	if err != nil {
		hookLog("%s: refusing to start: %v", name, err)
		return 1
	}
	for _, m := range mounts {
		if err := policy.coversMount(m); err != nil {
			hookLog("%s: refusing to start: %v", name, err)
			return 1
		}
		if err := policy.judgeMount(m.prefix, filepath.Join(m.prefix, m.rel)); err != nil {
			hookLog("%s: refusing to start: %v", name, err)
			return 1
		}
	}
	for _, d := range devices {
		if err := policy.coversDevice(d); err != nil {
			hookLog("%s: refusing to start: %v", name, err)
			return 1
		}
		if err := policy.judgeDevice(d.source, d.kind, d.major, d.minor); err != nil {
			hookLog("%s: refusing to start: %v", name, err)
			return 1
		}
	}
	if err := checkStagingPaths(name, mounts); err != nil {
		hookLog("%s: %v", name, err)
		return 1
	}
	dir := filepath.Join(stagingRoot, name)
	if err := ensurePrivateStagingRoot(stagingRoot); err != nil {
		hookLog("%v", err)
		return 1
	}
	if err := ensureStagingDir(dir); err != nil {
		hookLog("%v", err)
		return 1
	}
	for _, m := range mounts {
		if err := stageMount(m, policy); err != nil {
			// Unwind what was staged: a failed start leaves no host mount
			// behind for post-stop (which LXC does not run) to miss.
			clearStaging(dir)
			hookLog("%s: refusing to start: %v", name, err)
			return 1
		}
	}
	return 0
}

// hookLog says one thing the hook did or refused, on stderr (LXC's log, when
// the container has one) and in the system log under the tag
// litevirt-lxc-hook, so a refused start — a reboot from inside the container
// included, which no daemon call sees — leaves a record.
func hookLog(format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintln(os.Stderr, "litevirt lxc hook: "+msg)
	if w, err := syslog.New(syslog.LOG_WARNING|syslog.LOG_DAEMON, "litevirt-lxc-hook"); err == nil {
		_ = w.Warning(msg)
		_ = w.Close()
	}
}

// openedMountID is the id of the mount an fd is on (statx STATX_MNT_ID,
// Linux 5.8), as /proc/self/mountinfo lists it.
func openedMountID(fd int) (uint64, error) {
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err != nil {
		return 0, err
	}
	if stx.Mask&unix.STATX_MNT_ID == 0 || stx.Mnt_id == 0 {
		return 0, fmt.Errorf("the kernel reports no mount id")
	}
	return stx.Mnt_id, nil
}

// openedPath is the path the kernel resolved an O_PATH fd to.
func openedPath(fd int) (string, error) {
	return os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
}

// clearStaging takes a container's staging mounts down and removes each
// entry by itself — never RemoveAll, which would walk into a host tree still
// mounted there and delete its contents. An entry still mounted, or a
// directory not empty, stays and is said.
func clearStaging(dir string) {
	// Never through a symlink: its target's entries are not staging entries.
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		if err == nil {
			hookLog("%s is not a directory (%s); left in place", dir, st.Mode().Type())
		}
		return
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		p := filepath.Join(dir, e.Name())
		unmountAll(p)
		if isMountpoint(p) {
			hookLog("%s is still mounted; left in place", p)
			continue
		}
		if err := os.Remove(p); err != nil {
			hookLog("remove %s: %v", p, err)
		}
	}
	_ = os.Remove(dir)
}

// exclusiveOpenBusyOS opens a block node O_EXCL: EBUSY means some kernel
// claimant (a mount, swap, md, dm, btrfs, ZFS) holds it. Any other error
// proves nothing either way.
func exclusiveOpenBusyOS(p string) bool {
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_EXCL|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.Is(err, unix.EBUSY)
	}
	unix.Close(fd)
	return false
}
