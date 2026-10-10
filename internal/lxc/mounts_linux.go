//go:build linux

package lxc

import (
	"errors"
	"fmt"
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
// refused by the kernel (ELOOP / EXDEV), never followed.
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

// hookMount is one mount the hook stages, read from the config's markers.
type hookMount struct {
	ro, file    bool
	prefix, rel string
	staging     string
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

// ensurePrivateStagingRoot makes the staging root a root-only directory on a
// mount of its own with private propagation, so staged mounts neither leak
// into nor arrive from other mount namespaces.
func ensurePrivateStagingRoot() error {
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(stagingRoot, 0o700); err != nil {
		return err
	}
	if !isMountpoint(stagingRoot) {
		if err := unix.Mount(stagingRoot, stagingRoot, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", stagingRoot, err)
		}
	}
	return unix.Mount("", stagingRoot, "", unix.MS_PRIVATE|unix.MS_REC, "")
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
		if unix.Unmount(p, unix.MNT_DETACH) != nil {
			return
		}
	}
}

// stageMount mounts one source onto its staging path from an fd: open
// beneath the prefix, clone exactly that tree (no submounts), set its
// attributes, move it into place. Nothing between the open and the mount
// goes through a path a container could rename.
func stageMount(m hookMount) error {
	fd, err := openBeneath(m.prefix, m.rel)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
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
		f, err := os.OpenFile(m.staging, os.O_CREATE|os.O_RDONLY, 0o600)
		if err != nil {
			return err
		}
		f.Close()
	} else if err := os.MkdirAll(m.staging, 0o700); err != nil {
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
		fmt.Fprintln(os.Stderr, "litevirt lxc hook: no valid LXC_NAME")
		return 1
	}
	dir := filepath.Join(stagingRoot, name)
	switch hook {
	case "post-stop":
		ents, _ := os.ReadDir(dir)
		for _, e := range ents {
			unmountAll(filepath.Join(dir, e.Name()))
		}
		_ = os.RemoveAll(dir)
		return 0
	case "pre-start":
	default:
		fmt.Fprintf(os.Stderr, "litevirt lxc hook: unexpected hook type %q\n", hook)
		return 1
	}
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "litevirt lxc hook: read %s: %v\n", cfgPath, err)
		return 1
	}
	mounts, err := hookMounts(string(b))
	if err != nil {
		fmt.Fprintf(os.Stderr, "litevirt lxc hook: %s: %v\n", name, err)
		return 1
	}
	if err := ensurePrivateStagingRoot(); err != nil {
		fmt.Fprintf(os.Stderr, "litevirt lxc hook: %v\n", err)
		return 1
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "litevirt lxc hook: %v\n", err)
		return 1
	}
	for i, m := range mounts {
		if want := stagingPath(name, i); m.staging != want {
			fmt.Fprintf(os.Stderr, "litevirt lxc hook: %s: entry %d names %s, not %s\n", name, i, m.staging, want)
			return 1
		}
		if err := stageMount(m); err != nil {
			fmt.Fprintf(os.Stderr, "litevirt lxc hook: %s: refusing to start: %v\n", name, err)
			return 1
		}
	}
	return 0
}
