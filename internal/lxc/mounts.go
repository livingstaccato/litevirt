package lxc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Host bind mounts and device nodes (Proxmox mpN / devN).
//
// Mounting a host path into a container is a host privilege escalation: on
// Proxmox only root@pam may do it. The gRPC layer requires the admin role (on
// the entry node, before any forward); this layer, which runs ON the host,
// decides what the host allows and makes sure that is what gets mounted.
//
//   - A mount's host path must resolve, symlinks followed, under a prefix in
//     this host's containers.bind_mount_paths, and never into — or be an
//     ancestor of — a protected tree (hardDenyTrees, the litevirt and LXC
//     stores). A device must be one of containers.device_paths EXACTLY, a
//     character or block node, and not a kernel-memory, KVM or vhost node, or
//     a block device that holds a mounted filesystem.
//   - What the admin authorized is recorded in the container's directory
//     (hostAccessFile), written only by litevirt from an authorized spec and
//     never taken from an archive. The managed config block is rendered from
//     it, and every start renders it again and refuses a config whose block is
//     anything else.
//   - The config never names the user's tree. A mount entry names a staging
//     path under /var/lib/lxc/.litevirt+staging (root's, traverse only;
//     stagingRoot). The LXC pre-start hook — which LXC
//     runs on EVERY start, including a reboot from inside the container, where
//     litevirt is not involved — opens each source beneath its allowed prefix
//     with openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS), clones that exact
//     tree, sets read-only/nosuid/nodev on it, and moves it onto the staging
//     path. A symlink swapped into the tree after any check is refused by the
//     kernel, not followed (mounts_linux.go).
//   - Mounts are read-only unless asked otherwise, and always nosuid,nodev.
//   - Nothing about the user namespace changes: an unprivileged container
//     keeps its id map.

// Mount is one host path bind-mounted into a container.
type Mount struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
	ReadWrite     bool   `json:"read_write,omitempty"`
}

// Device is one host device node passed into a container. ContainerPath ""
// means the host path.
type Device struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path,omitempty"`
}

// HostAccess is what this host lets containers reach.
type HostAccess struct {
	// MountPaths are the prefixes a bind mount's source must resolve under.
	MountPaths []string
	// DevicePaths are the device nodes that may be passed through, exactly.
	DevicePaths []string
	// Deny are further static trees no mount may come from or be an ancestor
	// of: litevirt's data and PKI directories (from the daemon config). The
	// dynamic stores — pools, backup repos, the image store — come from
	// DenyFunc, at every resolve.
	Deny []string
	// HookBinary is the executable LXC runs as the container's start hook
	// (the litevirt binary, `<HookBinary> __lxc-hook`).
	HookBinary string
	// DenyFunc returns this host's stores as they are now — every storage
	// pool's source and target, every backup repo, the image store, the
	// restore cache — re-read at every resolve, so at every start. The daemon
	// wires it; nil adds nothing. An error (the list cannot be read) refuses
	// every mount, and a refresh keeps the policy it last wrote.
	DenyFunc func() ([]string, error)
	// BlockInUse reports why a block device (by number) is litevirt's — a VM
	// disk on this host, compared by device number. The daemon wires it. An
	// error (the disks cannot be read) refuses the device, and a refresh
	// keeps the policy it last wrote.
	BlockInUse func(major, minor uint32) (string, error)
}

// hardDenyTrees are host trees no bind mount may come from, or be an
// ancestor of, whatever the allowed prefixes say. "/" is refused by being an
// ancestor of every one of them.
var hardDenyTrees = []string{
	"/etc", "/root", "/boot", "/proc", "/sys", "/dev", "/run", "/var/run",
	"/var/lib/lxc", "/var/lib/libvirt", "/var/lib/litevirt", "/etc/litevirt",
	"/usr", "/bin", "/sbin", "/lib", "/lib64",
}

// resolvedMount is a mount after the host judged it.
type resolvedMount struct {
	Prefix string // the allowed prefix, resolved
	Rel    string // the source relative to Prefix ("." for Prefix itself)
	Target string // container path, relative to the rootfs
	RW     bool
	File   bool // a regular file rather than a directory
}

// resolvedDevice is a device after the host judged it.
type resolvedDevice struct {
	Source string // the exact device node path
	Target string // container path, relative to the rootfs
	Kind   byte   // 'c' or 'b'
	Major  uint32
	Minor  uint32
}

// safePathRe is the characters a mount path may hold. lxc.mount.entry is an
// fstab line inside a key = value config: whitespace would split fields and a
// newline would start a config line of its own, so neither — nor anything
// else unusual — is accepted.
var safePathRe = regexp.MustCompile(`^/[A-Za-z0-9._@+/-]*$`)

// cleanAbs validates an absolute path of safe characters and returns it
// cleaned. A ".." element is refused outright rather than cleaned away.
func cleanAbs(what, p string) (string, error) {
	if !safePathRe.MatchString(p) {
		return "", fmt.Errorf("%s %q: want an absolute path of letters, digits and . _ @ + / -", what, p)
	}
	for _, el := range strings.Split(p, "/") {
		if el == ".." {
			return "", fmt.Errorf("%s %q: contains ..", what, p)
		}
	}
	return filepath.Clean(p), nil
}

// containerTarget validates a container-side path and returns it relative to
// the rootfs, as lxc.mount.entry names it.
func containerTarget(p string) (string, error) {
	c, err := cleanAbs("container path", p)
	if err != nil {
		return "", err
	}
	if c == "/" {
		return "", fmt.Errorf("container path %q: cannot mount over the container's root", p)
	}
	return strings.TrimPrefix(c, "/"), nil
}

// within reports whether p is root or lies under it.
func within(p, root string) bool {
	if root == "/" {
		return true
	}
	return p == root || strings.HasPrefix(p, root+"/")
}

// resolveIfExists resolves symlinks in p when it exists, else cleans it.
func resolveIfExists(p string) string {
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	return filepath.Clean(p)
}

// transientError is a judgment that could not be made — a read or a lookup
// failed — as opposed to a refusal: a refresh keeps the policy it last wrote
// on one (m-2); every other caller refuses, as for any error.
type transientError struct{ err error }

func (e transientError) Error() string { return e.err.Error() }
func (e transientError) Unwrap() error { return e.err }

// transient marks err as a judgment that could not be made.
func transient(err error) error { return transientError{err} }

// isTransient reports whether err is (or wraps) a judgment that could not be
// made.
func isTransient(err error) bool {
	var t transientError
	return errors.As(err, &t)
}

// definiteLookup reports a path lookup error that is an answer — the path is
// not there (or not a directory, or a symlink loop) — rather than a failed
// read (ESTALE, ETIMEDOUT, EIO on a network filesystem).
func definiteLookup(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR) || errors.Is(err, syscall.ELOOP)
}

// deniedTreeByPath reports the protected tree p touches by path — p inside
// it, or p an ancestor of it — or "".
func deniedTreeByPath(p string, trees []string) string {
	if p == "/" {
		return "/"
	}
	for _, d := range trees {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		for _, form := range []string{filepath.Clean(d), resolveIfExists(d)} {
			if within(p, form) || within(form, p) {
				return form
			}
		}
	}
	return ""
}

// deniedTree reports the protected tree p touches — p inside it, or p an
// ancestor of it, by path or by filesystem identity (the same tree mounted
// somewhere else: deniedTreeByIdentity) — or "" when it touches none. An
// error is a check that could not be made (transient).
func deniedTree(p string, extra []string) (string, error) {
	trees := append(append([]string(nil), hardDenyTrees...), extra...)
	if d := deniedTreeByPath(p, trees); d != "" {
		return d, nil
	}
	return deniedTreeByIdentity(p, 0, trees)
}

// deniedDeviceName reports device nodes never passed through by name.
func deniedDeviceName(p string) bool {
	switch p {
	case "/dev/mem", "/dev/kmem", "/dev/port", "/dev/kvm":
		return true
	}
	// Raw access to disks with no block-layer check at all: SCSI generic,
	// block SCSI generic, NVMe generic namespaces and NVMe controllers.
	// Host console and input: virtual terminals, the console, their screen
	// memory, input injection and every input device, and the watchdog
	// (which reboots the host). Serial ports (ttyS, ttyUSB, ttyACM, ...) pass.
	// Device-mapper control (a dm target over any host disk), the CPU MSRs
	// and the hibernation image (host RAM) are host trust too.
	return strings.HasPrefix(p, "/dev/vhost-") || strings.HasPrefix(p, "/dev/bsg/") || strings.HasPrefix(p, "/dev/input/") ||
		rawDiskCharRe.MatchString(p) || hostConsoleRe.MatchString(p) || hostTrustRe.MatchString(p)
}

var hostTrustRe = regexp.MustCompile(`^/dev/(mapper/control|cpu/[0-9]+/msr|snapshot)$`)

var hostConsoleRe = regexp.MustCompile(`^/dev/(tty[0-9]*|console|vcs[au]?[0-9]*|uinput|watchdog[0-9]*)$`)

var rawDiskCharRe = regexp.MustCompile(`^/dev/(sg[0-9]+|ng[0-9]+n[0-9]+|nvme[0-9]+)$`)

// procDevicesPath is where the kernel lists its device majors (the bsg and
// NVMe char majors are allocated dynamically).
var procDevicesPath = "/proc/devices"

// rawDiskCharMajors reads the dynamic char majors of bsg, nvme-generic and
// nvme from /proc/devices.
func rawDiskCharMajors() map[uint32]bool {
	out := map[uint32]bool{}
	b, err := os.ReadFile(procDevicesPath)
	if err != nil {
		return out
	}
	inChar := false
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "Character devices"):
			inChar = true
			continue
		case strings.HasPrefix(t, "Block devices"):
			inChar = false
			continue
		}
		f := strings.Fields(t)
		if !inChar || len(f) != 2 {
			continue
		}
		switch f[1] {
		case "bsg", "nvme-generic", "nvme", "watchdog":
			if n, err := strconv.ParseUint(f[0], 10, 32); err == nil {
				out[uint32(n)] = true
			}
		}
	}
	return out
}

// deniedDeviceNumber reports device numbers never passed through: physical
// and kernel memory, I/O ports, KVM and the vhost devices.
func deniedDeviceNumber(kind byte, major, minor uint32) bool {
	if kind != 'c' {
		return false
	}
	switch {
	case major == 1 && (minor == 1 || minor == 2 || minor == 4):
		return true
	case major == 10 && (minor == 232 || minor == 238 || minor == 241):
		return true
	case major == 21: // SCSI generic
		return true
	case major == 10 && (minor == 223 || minor == 130): // uinput, watchdog
		return true
	case major == 4 && minor < 64: // virtual terminals (ttyS starts at 64)
		return true
	case major == 5 && (minor == 0 || minor == 1): // /dev/tty, /dev/console
		return true
	case major == 7, major == 13: // vcs*, input
		return true
	case major == 10 && (minor == 236 || minor == 231): // device-mapper control, snapshot
		return true
	case major == 202: // cpu/N/msr
		return true
	}
	return rawDiskCharMajors()[major]
}

// ValidateHostAccess refuses an allowed-prefix list a host must not run with:
// a mount prefix that is, lies in, or is an ancestor of a protected tree by
// path (so never "/"), and a device entry that is not an exact node under
// /dev or is a denied one. The daemon runs it on its config at load.
//
// A prefix that reaches a protected tree only by filesystem identity (the
// same filesystem mounted elsewhere) is not refused here: such a config
// loaded before identity was checked, and a config that loaded must still
// load (m-6). HostAccessOverlaps reports it, for a warning and a health
// condition, and every mount source is still judged by identity when it is
// resolved, so a source inside the protected tree is refused there.
func ValidateHostAccess(a HostAccess) error {
	trees := append(append([]string(nil), hardDenyTrees...), a.Deny...)
	for _, p := range a.MountPaths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("containers.bind_mount_paths: %q is not an absolute path", p)
		}
		r := resolveIfExists(p)
		if d := deniedTreeByPath(r, trees); d != "" {
			return fmt.Errorf("containers.bind_mount_paths: %q (%s) is, lies in, or contains the protected tree %s", p, r, d)
		}
	}
	for _, p := range a.DevicePaths {
		c := filepath.Clean(p)
		if !filepath.IsAbs(p) || c == "/dev" || !strings.HasPrefix(c, "/dev/") {
			return fmt.Errorf("containers.device_paths: %q is not a device node under /dev (list each node exactly; a directory is never allowed)", p)
		}
		if deniedDeviceName(c) {
			return fmt.Errorf("containers.device_paths: %q is never passed through (host memory, I/O ports, KVM and vhost are host-trust devices)", p)
		}
		if fi, err := os.Lstat(c); err == nil && fi.IsDir() {
			return fmt.Errorf("containers.device_paths: %q is a directory; list each device node exactly", p)
		}
	}
	return nil
}

// HostAccessOverlaps lists each bind_mount_paths prefix that shares files
// with a protected tree by filesystem identity — on the same filesystem as a
// tree and inside it, or containing it — though not by path (m-6), and a
// prefix whose identity could not be judged. Each entry names the prefix and
// the tree. Mount sources beneath such a prefix that lie in the tree are
// refused when they are resolved; the rest of the prefix keeps working.
func HostAccessOverlaps(a HostAccess) []string {
	trees := append(append([]string(nil), hardDenyTrees...), a.Deny...)
	var out []string
	for _, p := range a.MountPaths {
		if !filepath.IsAbs(p) {
			continue
		}
		r := resolveIfExists(p)
		if deniedTreeByPath(r, trees) != "" {
			continue
		}
		d, err := deniedTreeByIdentity(r, 0, trees)
		switch {
		case err != nil:
			out = append(out, fmt.Sprintf("containers.bind_mount_paths %s (%s) could not be judged by filesystem identity: %v", p, r, err))
		case d != "":
			out = append(out, fmt.Sprintf("containers.bind_mount_paths %s (%s) shares a filesystem with the protected tree %s; mount sources in that tree are refused", p, r, d))
		}
	}
	return out
}

// resolveMount judges one mount on this host.
func resolveMount(m Mount, a HostAccess) (resolvedMount, error) {
	src, err := cleanAbs("host path", m.HostPath)
	if err != nil {
		return resolvedMount{}, err
	}
	target, err := containerTarget(m.ContainerPath)
	if err != nil {
		return resolvedMount{}, err
	}
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		err = fmt.Errorf("host path %q: %w", m.HostPath, err)
		if !definiteLookup(err) {
			err = transient(err)
		}
		return resolvedMount{}, err
	}
	if !safePathRe.MatchString(resolved) {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, which holds characters a mount entry cannot carry", m.HostPath, resolved)
	}
	d, derr := deniedTree(resolved, a.Deny)
	if derr != nil {
		return resolvedMount{}, fmt.Errorf("host path %q (%s): the protected trees cannot be checked: %w", m.HostPath, resolved, derr)
	}
	if d != "" {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, which is, lies in or contains the protected tree %s", m.HostPath, resolved, d)
	}
	var prefix string
	var prefixErr error
	for _, p := range a.MountPaths {
		if !filepath.IsAbs(p) {
			continue
		}
		rp, perr := filepath.EvalSymlinks(filepath.Clean(p))
		// The prefix is not judged against the protected trees as a whole:
		// a store created beneath it refuses only sources that lie in it or
		// contain it (the source check above), never a disjoint one.
		if perr != nil && !definiteLookup(perr) && prefixErr == nil {
			prefixErr = fmt.Errorf("containers.bind_mount_paths %s: %w", p, perr)
		}
		if perr != nil || rp == "/" || !safePathRe.MatchString(rp) {
			continue
		}
		if within(resolved, rp) && len(rp) > len(prefix) {
			prefix = rp
		}
	}
	if prefix == "" {
		if prefixErr != nil {
			// A prefix that could not be read may be the one it lies under.
			return resolvedMount{}, transient(fmt.Errorf("host path %q resolves to %q, under no prefix that could be read: %w", m.HostPath, resolved, prefixErr))
		}
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, outside every containers.bind_mount_paths prefix on this host", m.HostPath, resolved)
	}
	rel, err := filepath.Rel(prefix, resolved)
	if err != nil || strings.HasPrefix(rel, "..") {
		return resolvedMount{}, fmt.Errorf("host path %q is not beneath %s", resolved, prefix)
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		err = fmt.Errorf("host path %q: %w", resolved, err)
		if !definiteLookup(err) {
			err = transient(err)
		}
		return resolvedMount{}, err
	}
	rm := resolvedMount{Prefix: prefix, Rel: rel, Target: target, RW: m.ReadWrite}
	switch {
	case fi.IsDir():
		return rm, nil
	case fi.Mode().IsRegular():
		rm.File = true
		return rm, nil
	}
	return resolvedMount{}, fmt.Errorf("host path %q is neither a directory nor a regular file", resolved)
}

// Where block-device use is read; tests point them at fixtures.
var (
	mountinfoPath = "/proc/self/mountinfo"
	sysDevBlock   = "/sys/dev/block"
	procRoot      = "/proc"
	swapsPath     = "/proc/swaps"
	// statRdev reads a node's device numbers.
	statRdev = func(p string) (byte, uint32, uint32, bool) {
		fi, err := os.Stat(p)
		if err != nil {
			return 0, 0, 0, false
		}
		return deviceNumbers(fi)
	}
	// lstatDevice reads a device node without following a symlink.
	lstatDevice = os.Lstat
	// exclusiveOpenBusy reports whether the kernel refuses an exclusive open
	// of the block node (EBUSY): a claim by a mount, swap, md, dm, btrfs, ZFS
	// or anything else that holds it.
	exclusiveOpenBusy = exclusiveOpenBusyOS
)

// blockDeviceInUse reports why a block device must not be passed through,
// judged by its NUMBER (never a path, which a rename changes): it, one of its
// partitions or the disk it is a partition of holds a mounted filesystem, is
// swap, has a device built on it, is an attached loop or nbd device, is held
// open by any process (qemu's VM disks), or the kernel refuses an exclusive
// open of it.
func blockDeviceInUse(major, minor uint32) string {
	mounted := map[string]bool{}
	if b, err := os.ReadFile(mountinfoPath); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if f := strings.Fields(line); len(f) > 2 {
				mounted[f[2]] = true
			}
		}
	} else {
		return "this host's mount table cannot be read (" + err.Error() + ")"
	}
	swap := map[string]bool{}
	if b, err := os.ReadFile(swapsPath); err == nil {
		for _, line := range strings.Split(string(b), "\n")[1:] {
			if f := strings.Fields(line); len(f) > 0 {
				if k, ma, mi, ok := statRdev(f[0]); ok && k == 'b' {
					swap[fmt.Sprintf("%d:%d", ma, mi)] = true
				}
			}
		}
	}
	held := openDeviceNumbers()
	check := func(dev string) string {
		switch {
		case mounted[dev]:
			return "it holds a mounted filesystem"
		case swap[dev]:
			return "it is swap"
		case held[dev] != "":
			return "process " + held[dev] + " holds it open"
		}
		if ents, err := os.ReadDir(filepath.Join(sysDevBlock, dev, "holders")); err == nil && len(ents) > 0 {
			return "another block device (" + ents[0].Name() + ") is built on it"
		}
		if _, err := os.Stat(filepath.Join(sysDevBlock, dev, "loop", "backing_file")); err == nil {
			return "it is a loop device with a backing file"
		}
		if _, err := os.Stat(filepath.Join(sysDevBlock, dev, "pid")); err == nil {
			return "it is a connected nbd device"
		}
		if exclusiveOpenBusy("/dev/block/" + dev) {
			return "the kernel refuses an exclusive open (a mount, swap, md, dm, btrfs or ZFS holds it)"
		}
		return ""
	}
	for _, f := range blockFamily(major, minor) {
		if why := check(f.dev); why != "" {
			return f.what + why
		}
	}
	return ""
}

// blockKin is one device of a block device's family, and how to name it.
type blockKin struct{ dev, what string }

// blockFamily is a block device, its partitions and — for a partition — the
// disk it belongs to: passing any one through reaches the others' data.
func blockFamily(major, minor uint32) []blockKin {
	self := fmt.Sprintf("%d:%d", major, minor)
	out := []blockKin{{self, ""}}
	ents, _ := os.ReadDir(filepath.Join(sysDevBlock, self))
	for _, e := range ents {
		if dev := partitionDev(filepath.Join(sysDevBlock, self, e.Name())); dev != "" {
			out = append(out, blockKin{dev, "its partition " + e.Name() + ": "})
		}
	}
	if parent := parentDisk(self); parent != "" {
		out = append(out, blockKin{parent, "the disk it is a partition of (" + parent + "): "})
	}
	return out
}

// partitionDev is the dev number of the partition whose sysfs dir is dir, or
// "" when dir is not a partition.
func partitionDev(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "partition")); err != nil {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(dir, "dev"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// parentDisk is the dev number of the disk dev is a partition of, or "".
func parentDisk(dev string) string {
	disks, _ := os.ReadDir(sysDevBlock)
	for _, d := range disks {
		parts, _ := os.ReadDir(filepath.Join(sysDevBlock, d.Name()))
		for _, p := range parts {
			if partitionDev(filepath.Join(sysDevBlock, d.Name(), p.Name())) == dev {
				return d.Name()
			}
		}
	}
	return ""
}

// openDeviceNumbers maps the device numbers any process holds open (its fds
// naming a /dev node) to that process's pid. qemu opens a VM's raw disk
// without a kernel claim, so this is how such a disk is seen.
func openDeviceNumbers() map[string]string {
	out := map[string]string{}
	pids, _ := os.ReadDir(procRoot)
	for _, p := range pids {
		if _, err := strconv.Atoi(p.Name()); err != nil {
			continue
		}
		fdDir := filepath.Join(procRoot, p.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, fd := range fds {
			target, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil || !strings.HasPrefix(target, "/dev/") {
				continue
			}
			if k, ma, mi, ok := statRdev(target); ok && k == 'b' {
				out[fmt.Sprintf("%d:%d", ma, mi)] = p.Name()
			}
		}
	}
	return out
}

// resolveDevice judges one device on this host. live adds the checks of who
// holds a block device NOW (blockDeviceInUse: mounts, swap, open fds, holders,
// the exclusive-open probe); without it the device is judged on what it is.
func resolveDevice(d Device, a HostAccess, live bool) (resolvedDevice, error) {
	src, err := cleanAbs("device path", d.HostPath)
	if err != nil {
		return resolvedDevice{}, err
	}
	cpath := d.ContainerPath
	if cpath == "" {
		cpath = src
	}
	target, err := containerTarget(cpath)
	if err != nil {
		return resolvedDevice{}, err
	}
	listed := false
	for _, p := range a.DevicePaths {
		if filepath.Clean(p) == src {
			listed = true
		}
	}
	if !listed {
		return resolvedDevice{}, fmt.Errorf("device %q is not listed in containers.device_paths on this host (devices are listed exactly)", src)
	}
	if deniedDeviceName(src) {
		return resolvedDevice{}, fmt.Errorf("device %q is never passed through (host memory, I/O ports, KVM and vhost are host-trust devices)", src)
	}
	fi, err := lstatDevice(src)
	if err != nil {
		err = fmt.Errorf("device %q: %w", src, err)
		if !definiteLookup(err) {
			err = transient(err)
		}
		return resolvedDevice{}, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return resolvedDevice{}, fmt.Errorf("device %q is a symlink; name the device node itself", src)
	}
	kind, major, minor, ok := deviceNumbers(fi)
	if !ok {
		return resolvedDevice{}, fmt.Errorf("device %q is not a character or block device node", src)
	}
	if deniedDeviceNumber(kind, major, minor) {
		return resolvedDevice{}, fmt.Errorf("device %q (%c %d:%d) is never passed through (host memory, I/O ports, KVM and vhost)", src, kind, major, minor)
	}
	if kind == 'b' {
		if live {
			if why := blockDeviceInUse(major, minor); why != "" {
				return resolvedDevice{}, fmt.Errorf("block device %q is the host's: %s", src, why)
			}
		}
		why, err := litevirtBlockUse(a, major, minor)
		if err != nil {
			return resolvedDevice{}, transient(fmt.Errorf("block device %q: whether it is a VM's disk cannot be read: %w", src, err))
		}
		if why != "" {
			return resolvedDevice{}, fmt.Errorf("block device %q is litevirt's: %s", src, why)
		}
	}
	return resolvedDevice{Source: src, Target: target, Kind: kind, Major: major, Minor: minor}, nil
}

// ResolveHostAccess judges a container's mounts and devices on this host,
// returning the resolved forms its config names, or the first refusal.
func ResolveHostAccess(mounts []Mount, devices []Device, access HostAccess) ([]resolvedMount, []resolvedDevice, error) {
	return resolveHostAccess(mounts, devices, access, true)
}

// resolveHostAccess is ResolveHostAccess; live=false leaves out who holds a
// block device now (resolveDevice) — the judgment of a RUNNING container's
// grant, whose own processes may hold it.
func resolveHostAccess(mounts []Mount, devices []Device, access HostAccess, live bool) ([]resolvedMount, []resolvedDevice, error) {
	if len(mounts) > 0 {
		if err := hostAccessSupported(); err != nil {
			return nil, nil, fmt.Errorf("host bind mounts need the kernel's openat2 and new mount API (Linux 5.12+): %w", err)
		}
	}
	if len(mounts) > 0 || len(devices) > 0 {
		if err := validateHookBinary(access.HookBinary); err != nil {
			return nil, nil, fmt.Errorf("host mounts and devices are judged again by litevirt's start hook, and %w", err)
		}
	}
	deny, err := effectiveDeny(access, len(mounts) > 0)
	if err != nil {
		// No mount is judged against a store list that could not be read.
		return nil, nil, transient(fmt.Errorf("this host's stores (pools, backup repos) cannot be read, so no host mount can be judged: %w", err))
	}
	access.Deny = deny
	var rm []resolvedMount
	for _, m := range mounts {
		r, err := resolveMount(m, access)
		if err != nil {
			return nil, nil, err
		}
		rm = append(rm, r)
	}
	var rd []resolvedDevice
	for _, d := range devices {
		r, err := resolveDevice(d, access, live)
		if err != nil {
			return nil, nil, err
		}
		rd = append(rd, r)
	}
	return rm, rd, nil
}

// CheckHostAccessShape validates the paths of mounts and devices without
// touching the host: the check an entry node can make before forwarding. The
// host that creates the container judges them again (ResolveHostAccess).
func CheckHostAccessShape(mounts []Mount, devices []Device) error {
	for _, m := range mounts {
		if _, err := cleanAbs("host path", m.HostPath); err != nil {
			return err
		}
		if _, err := containerTarget(m.ContainerPath); err != nil {
			return err
		}
	}
	for _, d := range devices {
		src, err := cleanAbs("device path", d.HostPath)
		if err != nil {
			return err
		}
		if deniedDeviceName(src) {
			return fmt.Errorf("device %q is never passed through (host memory, I/O ports, KVM and vhost are host-trust devices)", src)
		}
		cp := d.ContainerPath
		if cp == "" {
			cp = src
		}
		if _, err := containerTarget(cp); err != nil {
			return err
		}
	}
	return nil
}

const (
	mountBlockBegin = "# litevirt:host-access-begin"
	mountBlockEnd   = "# litevirt:host-access-end"
	// Each entry is preceded by a marker. The hook reads a mount's marker:
	// "mount <ro|rw> <dir|file> <prefix> <rel>".
	mountMarker  = "# litevirt:mount"
	deviceMarker = "# litevirt:device"
	// HookArg is the first argument LXC's start hook is run with.
	HookArg = "__lxc-hook"
)

// stagingRoot is where the hook mounts each source before LXC binds it into
// the container: root's and traverse only (0711), so nothing unprivileged
// can list, create or rename in it.
//
// It lies beneath LXC's store because that is the one tree the stock
// AppArmor profile of lxc-start lets a pre-start hook mount on ("mount ->
// /var/lib/lxc/{**,}", abstractions/lxc/start-container on Ubuntu): a hook
// mounting anywhere else is denied, and every container with a host mount
// or device fails to start. It is directly beneath the store rather than in
// the container's own directory, which belongs to an unprivileged
// container's mapped root (secureContainerDir), and its name is not a valid
// container name (the '+'), so no container can own it.
var stagingRoot = defaultLxcpath + "/" + stagingDirName

// stagingDirName is stagingRoot's directory in LXC's store.
const stagingDirName = ".litevirt+staging"

// legacyStagingRoot is where earlier builds staged. A config they rendered
// still names it until a daemon-driven start renders it again, so the hook
// stages such a config there, as before.
const legacyStagingRoot = "/run/litevirt/ct"

// stagingPath is the staging mount point of a container's i-th mount.
func stagingPath(name string, i int) string {
	return stagingPathUnder(stagingRoot, name, i)
}

// stagingPathUnder is the staging mount point of a container's i-th mount
// under root.
func stagingPathUnder(root, name string, i int) string {
	return filepath.Join(root, name, fmt.Sprintf("m%d", i))
}

// renderHostAccessBlock is the litevirt-owned config block for a container's
// resolved mounts and devices; "" when there are none.
func renderHostAccessBlock(name, hookBinary string, mounts []resolvedMount, devices []resolvedDevice) string {
	if len(mounts) == 0 && len(devices) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(mountBlockBegin + "\n")
	// The hook runs for devices too: an in-container reboot judges them
	// again against the host's policy.
	fmt.Fprintf(&b, "lxc.hook.pre-start = %s %s\n", hookBinary, HookArg)
	fmt.Fprintf(&b, "lxc.hook.post-stop = %s %s\n", hookBinary, HookArg)
	for i, m := range mounts {
		mode, kind, create := "ro", "dir", "create=dir"
		opts := "bind,ro,nosuid,nodev"
		if m.RW {
			mode, opts = "rw", "bind,nosuid,nodev"
		}
		if m.File {
			kind, create = "file", "create=file"
		}
		fmt.Fprintf(&b, "%s %s %s %s %s\n", mountMarker, mode, kind, m.Prefix, m.Rel)
		fmt.Fprintf(&b, "lxc.mount.entry = %s %s none %s,%s 0 0\n", stagingPath(name, i), m.Target, opts, create)
	}
	for _, d := range devices {
		fmt.Fprintf(&b, "%s %c %d:%d\n", deviceMarker, d.Kind, d.Major, d.Minor)
		fmt.Fprintf(&b, "lxc.cgroup2.devices.allow = %c %d:%d rwm\n", d.Kind, d.Major, d.Minor)
		fmt.Fprintf(&b, "lxc.mount.entry = %s %s none bind,create=file 0 0\n", d.Source, d.Target)
	}
	b.WriteString(mountBlockEnd + "\n")
	return b.String()
}

// withHostAccessBlock returns cfg with block in place of any earlier one.
func withHostAccessBlock(cfg, block string) string {
	var out []string
	in := false
	for _, line := range strings.Split(strings.TrimRight(cfg, "\n"), "\n") {
		switch t := strings.TrimSpace(line); {
		case t == mountBlockBegin:
			in = true
			continue
		case t == mountBlockEnd:
			in = false
			continue
		case in:
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n") + "\n" + block
}

// hostAccessBlockOf returns the managed block of a config rendering, markers
// included, or "" when it has none. ok is false for a block that is not closed.
func hostAccessBlockOf(cfg string) (block string, ok bool) {
	var b strings.Builder
	in := false
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		if t == mountBlockBegin {
			in = true
		}
		if in {
			b.WriteString(t + "\n")
		}
		if t == mountBlockEnd {
			in = false
		}
	}
	return b.String(), !in
}

// withoutHookLines drops a block's hook lines, which name the binary that
// rendered it and so change with an upgrade, whatever was authorized.
func withoutHookLines(block string) string {
	var out []string
	for _, line := range strings.Split(block, "\n") {
		if strings.HasPrefix(line, "lxc.hook.") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// hostAccessFile records, in the container's directory, the mounts and
// devices an admin authorized: written only by litevirt from an authorized
// spec, removed from anything imported, and the source every start renders
// the managed block from.
const hostAccessFile = "litevirt-host-access.json"

type authorizedHostAccess struct {
	Mounts  []Mount  `json:"mounts,omitempty"`
	Devices []Device `json:"devices,omitempty"`
}

// readAuthorizedHostAccess reads a container's authorized host access. Only a
// genuinely missing record means "none"; any other read or decode error
// refuses, rather than reading as nothing authorized (or everything).
func readAuthorizedHostAccess(dir string) (authorizedHostAccess, error) {
	var a authorizedHostAccess
	b, err := os.ReadFile(filepath.Join(dir, hostAccessFile))
	if errors.Is(err, fs.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return a, fmt.Errorf("read the authorized host access: %w", err)
	}
	if err := json.Unmarshal(b, &a); err != nil {
		return a, fmt.Errorf("the authorized host access record is corrupt: %w", err)
	}
	return a, nil
}

// SetHostAccess records mounts and devices as the container's authorized
// host access and renders its managed block from them, judged against this
// host now. Empty removes both. The caller has authorized them (the admin
// role at create or convert, or a peer-verified source row).
func (r *LxcRunner) SetHostAccess(name string, mounts []Mount, devices []Device) error {
	unlock, err := r.lockHostAccess(name)
	if err != nil {
		return err
	}
	defer unlock()
	dir := filepath.Join(r.lxcpath(), name)
	cfgPath := filepath.Join(dir, "config")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read container config %s: %w", cfgPath, err)
	}
	rm, rd, err := ResolveHostAccess(mounts, devices, r.hostAccess())
	if err != nil {
		return fmt.Errorf("container %q: %w", name, err)
	}
	if len(mounts) == 0 && len(devices) == 0 {
		if err := os.Remove(filepath.Join(dir, hostAccessFile)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	} else {
		rec, _ := json.Marshal(authorizedHostAccess{Mounts: mounts, Devices: devices})
		if err := writeFileAtomic(filepath.Join(dir, hostAccessFile), rec, 0o600); err != nil {
			return err
		}
	}
	if err := r.syncHookPolicy(name, rm, rd); err != nil {
		return err
	}
	cfg := withHostAccessBlock(string(b), renderHostAccessBlock(name, r.hostAccess().HookBinary, rm, rd))
	return writeFileAtomic(cfgPath, []byte(cfg), 0o644)
}

// syncHookPolicy writes name's hook policy when it has host access, and
// removes it when it has none.
func (r *LxcRunner) syncHookPolicy(name string, rm []resolvedMount, rd []resolvedDevice) error {
	if len(rm) == 0 && len(rd) == 0 {
		if err := os.Remove(hookPolicyFile(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	if err := r.writeHookPolicy(name, rm, rd); err != nil {
		return fmt.Errorf("record container %q's host-access policy for the start hook: %w", name, err)
	}
	return nil
}

// effectiveDeny is every protected tree beyond the hard ones: the static
// list, the host's stores as they are now (DenyFunc), and the start hook's
// own binary — a mount that contains it would let a container rewrite what
// LXC runs as root.
//
// The stores are read only when stores is set (the container has mounts):
// a container with none never queries the database at its start.
func effectiveDeny(a HostAccess, stores bool) ([]string, error) {
	out := append([]string(nil), a.Deny...)
	if stores && a.DenyFunc != nil {
		d, err := a.DenyFunc()
		if err != nil {
			return nil, err
		}
		out = append(out, d...)
	}
	if a.HookBinary != "" {
		out = append(out, a.HookBinary)
	}
	return out, nil
}

// validateHookBinary refuses a start-hook binary LXC must not run as root: a
// path a config line cannot carry, or a file or parent directory that is not
// root-owned or is group- or world-writable. Tests replace it.
var validateHookBinary = func(bin string) error {
	if !safePathRe.MatchString(bin) {
		return fmt.Errorf("its binary path %q holds characters a config line cannot carry", bin)
	}
	for p := bin; ; p = filepath.Dir(p) {
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("its binary %s: %w", bin, err)
		}
		if !ownedByRoot(fi) || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("its binary %s (at %s) is not root-owned and closed to group and others", bin, p)
		}
		if p == "/" {
			return nil
		}
	}
}

// hostAccess is the runner's HostAccess with this runner's own LXC store
// added to the protected trees.
func (r *LxcRunner) hostAccess() HostAccess {
	a := r.HostAccess
	a.Deny = append(append([]string(nil), a.Deny...), r.lxcpath())
	if a.HookBinary == "" {
		a.HookBinary = "/usr/local/bin/litevirt"
	}
	return a
}

// checkHostAccessForStart re-judges a container's host access on this host
// as it is now, before lxc-start: the authorized record is resolved afresh
// and rendered, and the config's managed block is replaced by that rendering
// when it says anything else (the difference is logged). A record that
// cannot be read, a block that is not closed, or a path the host no longer
// allows refuses the start.
func (r *LxcRunner) checkHostAccessForStart(name string) error {
	unlock, err := r.lockHostAccess(name)
	if err != nil {
		return err
	}
	defer unlock()
	dir := filepath.Join(r.lxcpath(), name)
	auth, err := readAuthorizedHostAccess(dir)
	if err != nil {
		return err
	}
	cfgPath := filepath.Join(dir, "config")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return err
	}
	have, closed := hostAccessBlockOf(string(b))
	if !closed {
		return fmt.Errorf("its host-access block is not closed")
	}
	rm, rd, err := ResolveHostAccess(auth.Mounts, auth.Devices, r.hostAccess())
	if err != nil {
		return err
	}
	want := renderHostAccessBlock(name, r.hostAccess().HookBinary, rm, rd)
	// The hook re-judges every mount and device against this host's policy
	// as it is now, bounded by this record; it stages nothing without one.
	if err := r.syncHookPolicy(name, rm, rd); err != nil {
		return err
	}
	if have != want {
		// The record is the authority: whatever the block says — tampered
		// options, an extra devices.allow, a device renumbered by a reboot, a
		// longer allowed prefix — it is rendered again from the record, and
		// the difference said, never kept.
		// A block an earlier build rendered names its staging root
		// (legacyStagingRoot); moving it to this build's is no difference
		// from the record.
		moved := strings.ReplaceAll(have, legacyStagingRoot+"/", stagingRoot+"/")
		switch {
		case withoutHookLines(moved) != withoutHookLines(want):
			slog.Warn("container: host-access block differed from its authorized record; rendered again from the record",
				"container", name, "had", have, "now", want)
		case moved != have:
			slog.Info("container: host mounts were staged at the old path until this start; rendered again under the new staging root",
				"container", name, "old", legacyStagingRoot, "new", stagingRoot)
		}
		cfg := withHostAccessBlock(string(b), want)
		return writeFileAtomic(cfgPath, []byte(cfg), 0o644)
	}
	return nil
}

// ── config sanitization (import / restore / revert / clone) ──

// keptConfigKeys are the config keys an imported (untrusted) container
// config may keep: litevirt's own rendering, minus everything that grants host
// access or decides confinement (mounts, hooks, includes outside LXC's own
// config dir, device rules, AppArmor/seccomp/capabilities, id maps, rootfs
// options, init and environment, namespaces, sysctls, prlimits). Security
// and host access are rendered again from the authorized spec.
var keptConfigKeys = []string{
	"lxc.rootfs.path", "lxc.uts.name", "lxc.arch",
	"lxc.pty.max", "lxc.tty.max", "lxc.tty.dir",
	"lxc.signal.halt", "lxc.signal.reboot", "lxc.signal.stop",
	"lxc.start.auto", "lxc.start.delay", "lxc.start.order",
	"lxc.console.size",
}

var keptConfigPrefixes = []string{
	"lxc.net.",
	"lxc.cgroup2.memory.", "lxc.cgroup2.cpu.", "lxc.cgroup2.pids.",
	"lxc.cgroup.memory.", "lxc.cgroup.cpu.", "lxc.cgroup.pids.",
}

// lxcSystemConfigDir is where LXC's own (root-owned, packaged) config
// fragments live; an include of one of them is kept.
const lxcSystemConfigDir = "/usr/share/lxc/config/"

// keepConfigLine reports whether an imported config line survives.
func keepConfigLine(key, val string) bool {
	if key == "lxc.include" {
		// Only the fragments litevirt's own create writes: LXC's common and
		// userns baselines, generic or per distro. Not nesting.conf or any other.
		c := filepath.Clean(val)
		base := filepath.Base(c)
		return filepath.Dir(c)+"/" == lxcSystemConfigDir && !strings.Contains(val, "..") &&
			(base == "common.conf" || base == "userns.conf" ||
				strings.HasSuffix(base, ".common.conf") || strings.HasSuffix(base, ".userns.conf"))
	}
	if strings.Contains(key, ".script.") || strings.Contains(key, ".hook") {
		return false // lxc.net.N.script.up runs a host program as root
	}
	for _, k := range keptConfigKeys {
		if key == k {
			return true
		}
	}
	for _, p := range keptConfigPrefixes {
		if strings.HasPrefix(key, p) {
			return true
		}
	}
	return false
}

// SanitizeImportedConfig returns cfg with only the lines an imported config
// may keep, and the dropped config keys. The managed host-access block and
// the security block go too: both are rendered again from the authorized spec
// (RebuildConfig). Comments and blank lines outside those blocks are kept.
func SanitizeImportedConfig(cfg string) (string, []string) { return sanitizeConfig(cfg, false) }

// sanitizeConfig is SanitizeImportedConfig that, with keepSecurity, keeps the
// litevirt security block (an import keeps it until RebuildConfig renders it
// from the authorized spec, so the id-range handling in between reads it).
func sanitizeConfig(cfg string, keepSecurity bool) (string, []string) {
	var out, dropped []string
	inBlock := ""
	for _, line := range strings.Split(strings.TrimRight(cfg, "\n"), "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == mountBlockBegin:
			inBlock = mountBlockEnd
			dropped = append(dropped, "host-access block")
			continue
		case strings.HasPrefix(t, secBlockBegin):
			inBlock = secBlockEnd
			if keepSecurity {
				out = append(out, line)
			}
			continue
		case inBlock != "" && t == inBlock:
			if inBlock == secBlockEnd && keepSecurity {
				out = append(out, line)
			}
			inBlock = ""
			continue
		case inBlock != "":
			if inBlock == secBlockEnd && keepSecurity {
				out = append(out, line)
			}
			continue
		case t == "" || strings.HasPrefix(t, "#"):
			out = append(out, line)
			continue
		}
		k, v := configKey(line)
		if k != "" && keepConfigLine(k, v) {
			out = append(out, line)
			continue
		}
		if k == "" {
			k = t
		}
		dropped = append(dropped, k)
	}
	return strings.Join(out, "\n") + "\n", dropped
}

// RebuildConfig makes a container's config litevirt's own again: every line an
// imported config may not keep is dropped, the security block is rendered from
// the authorized confinement and id range, and the host access from the
// authorized mounts and devices (SetHostAccess). Restore, import, revert and
// clone run it with what the caller was authorized to carry.
func (r *LxcRunner) RebuildConfig(name, confinement string, idmapBase int64, nics []NetworkAttach, mounts []Mount, devices []Device) ([]string, error) {
	dir := filepath.Join(r.lxcpath(), name)
	cfgPath := filepath.Join(dir, "config")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("read container config %s: %w", cfgPath, err)
	}
	idmapped := parseSecurity(string(b)).IDMappedMount
	clean, dropped := SanitizeImportedConfig(string(b))
	// The network too comes only from the authorized NICs: every lxc.net
	// line found is dropped, and the spec's rendered as create renders them
	// (none: create's default). One the spec would render identically is not
	// reported as dropped. nil nics — a revert to the container's own
	// snapshot, which no archive wrote — keeps the network as it is.
	if nics != nil {
		netCfg, err := NetworkConfig(nics)
		if err != nil {
			return nil, fmt.Errorf("render the authorized network: %w", err)
		}
		if netCfg == "" {
			netCfg = defaultNetConfig()
		}
		want := map[string]bool{}
		for _, l := range strings.Split(netCfg, "\n") {
			if k, v := configKey(l); k != "" {
				want[k+"="+v] = true
			}
		}
		var kept []string
		for _, line := range strings.Split(strings.TrimRight(clean, "\n"), "\n") {
			k, v := configKey(line)
			if strings.HasPrefix(k, "lxc.net.") {
				if !want[k+"="+v] {
					dropped = append(dropped, k+" = "+v)
				}
				continue
			}
			kept = append(kept, line)
		}
		clean = strings.Join(kept, "\n") + "\n" + strings.TrimLeft(netCfg, "\n")
	}
	var idmap *IDMap
	if idmapBase != 0 {
		idmap = &IDMap{Base: idmapBase, Size: IDMapSize}
	}
	if confinement == "" {
		confinement = ConfinementLegacy // as an earlier build wrote it, now explicit
	}
	clean = withSecurityBlock(clean, renderSecurityBlock(confinement, idmap, idmap != nil && idmapped))
	if err := writeFileAtomic(cfgPath, []byte(clean), 0o644); err != nil {
		return nil, err
	}
	return dropped, r.SetHostAccess(name, mounts, devices)
}

// hookPolicyPath is where the daemon leaves this host's host-access policy
// for the start hook, rewritten before every start it drives. A reboot from
// inside the container runs the hook without the daemon, so the hook judges
// against the last policy the daemon wrote — never against the config alone.
var hookPolicyDir = "/run/litevirt/lxc-hook-policy"

// hookPolicyFile is name's policy file.
func hookPolicyFile(name string) string { return filepath.Join(hookPolicyDir, name+".json") }

// hookPolicy is this host's host-access policy as the start hook sees it:
// the allowed prefixes and devices, and every protected tree (resolved).
type hookPolicy struct {
	MountPaths  []string `json:"mount_paths"`
	DevicePaths []string `json:"device_paths"`
	Deny        []string `json:"deny"`
	// Mounts and Devices are what the container's record authorizes,
	// resolved on this host as it is now.
	Mounts  []resolvedMount  `json:"mounts,omitempty"`
	Devices []resolvedDevice `json:"devices,omitempty"`
}

// coversMount reports whether the container's record authorizes m exactly:
// the same prefix, path beneath it, kind and mode.
func (p hookPolicy) coversMount(m hookMount) error {
	for _, a := range p.Mounts {
		if a.Prefix == m.prefix && a.Rel == m.rel && a.File == m.file && a.RW == !m.ro {
			return nil
		}
	}
	return fmt.Errorf("%s/%s is not a mount this container's record authorizes on this host", m.prefix, m.rel)
}

// coversDevice reports whether the container's record authorizes d exactly.
func (p hookPolicy) coversDevice(d hookDevice) error {
	for _, a := range p.Devices {
		if a.Source == d.source && a.Kind == d.kind && a.Major == d.major && a.Minor == d.minor {
			return nil
		}
	}
	return fmt.Errorf("device %s (%c %d:%d) is not one this container's record authorizes on this host", d.source, d.kind, d.major, d.minor)
}

// judgeOpened judges the path the kernel resolved an opened source to: still
// beneath its prefix, the prefix still allowed, and in no protected tree —
// by path, and by the identity of the filesystem the fd is on (mntID, its
// mount id), so a store reached through another mount of its filesystem is
// refused even where a later mount shadows that one. It is what lets a
// filesystem mounted beneath an allowed prefix (a NAS) be a source while a
// store or protected tree mounted or swapped there is not.
func (p hookPolicy) judgeOpened(prefix, opened string, mntID uint64) error {
	if err := p.judgeMount(prefix, opened); err != nil {
		return err
	}
	d, err := deniedTreeByIdentity(filepath.Clean(opened), mntID, append(append([]string(nil), hardDenyTrees...), p.Deny...))
	if err != nil {
		return fmt.Errorf("%s: the protected trees cannot be checked: %w", opened, err)
	}
	if d != "" {
		return fmt.Errorf("%s is, lies in or contains the protected tree %s", opened, d)
	}
	return nil
}

// RefreshHookPolicies rewrites every container's hook policy from its record
// and this host's policy as they are now (the daemon runs it at start and
// periodically, so a pool or repo created, or a prefix withdrawn, reaches the
// policy an in-container reboot judges against). A container whose record no
// longer resolves here gets a policy that authorizes nothing, and a policy
// whose container directory is gone is removed.
//
// Devices are judged on what they are, never on who holds them now: the
// container may be running, and its own processes may hold its granted block
// device open. The live checks — holders, mounts, swap, the exclusive-open
// probe — run in the start hook's pre-start judgment (judgeDevice), when no
// process of the container is alive, and at every daemon-driven start.
//
// Each container is refreshed under its host-access lock, so a refresh that
// read a record cannot write its policy over a newer one SetHostAccess wrote.
func (r *LxcRunner) RefreshHookPolicies() error {
	ents, err := os.ReadDir(r.lxcpath())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	var errs []error
	for _, e := range ents {
		if !e.IsDir() || e.Name() == stagingDirName {
			continue
		}
		if err := r.refreshHookPolicyBounded(e.Name()); err != nil {
			errs = append(errs, err)
		}
	}
	if err := r.sweepHookPolicies(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// refreshDeadline bounds how long the refresh loop waits for one container.
var refreshDeadline = 10 * time.Second

// refreshHookPolicyBounded is refreshHookPolicy that the loop stops waiting
// for after refreshDeadline (P5): a resolve that hangs inside a syscall — a
// hard-mounted NFS source that does not answer — while the refresh holds the
// container's lock would otherwise stall the refresh of every container
// after it. The abandoned refresh keeps running and still holds that lock,
// so it writes nothing stale (a SetHostAccess waits for it) and every later
// run skips the container (refreshHookPolicy's TryLock) rather than stacking
// another goroutine behind it; the container's start hook keeps the policy
// last written and judges again at pre-start.
func (r *LxcRunner) refreshHookPolicyBounded(name string) error {
	if since, stuck := r.refreshStuckSince(name); stuck {
		return fmt.Errorf("container %q: its host-access policy refresh has not returned since %s (a mount source that does not answer?); "+
			"its start hook keeps the policy last written, and its start and host-access changes are refused until it returns",
			name, since.Format(time.RFC3339))
	}
	var mu sync.Mutex
	finished, abandoned := false, false
	done := make(chan error, 1)
	go func() {
		err := r.refreshHookPolicy(name)
		mu.Lock()
		finished = true
		if abandoned {
			r.clearRefreshStuck(name)
		}
		mu.Unlock()
		done <- err
	}()
	t := time.NewTimer(refreshDeadline)
	defer t.Stop()
	select {
	case err := <-done:
		return err
	case <-t.C:
	}
	mu.Lock()
	if finished {
		mu.Unlock()
		return <-done
	}
	abandoned = true
	r.markRefreshStuck(name, time.Now())
	mu.Unlock()
	return fmt.Errorf("container %q: its host-access policy refresh has not finished in %s (a mount source that does not answer?); "+
		"its start hook keeps the policy last written, and the other containers are refreshed", name, refreshDeadline)
}

// markRefreshStuck records that name's refresh was abandoned at since, still
// holding its lock; clearRefreshStuck forgets it once that refresh returns.
func (r *LxcRunner) markRefreshStuck(name string, since time.Time) {
	r.hostAccessMu.Lock()
	defer r.hostAccessMu.Unlock()
	if r.refreshStuck == nil {
		r.refreshStuck = map[string]time.Time{}
	}
	r.refreshStuck[name] = since
}

func (r *LxcRunner) clearRefreshStuck(name string) {
	r.hostAccessMu.Lock()
	defer r.hostAccessMu.Unlock()
	delete(r.refreshStuck, name)
}

// refreshStuckSince reports whether name's refresh was abandoned and has not
// returned, and since when.
func (r *LxcRunner) refreshStuckSince(name string) (time.Time, bool) {
	r.hostAccessMu.Lock()
	defer r.hostAccessMu.Unlock()
	since, ok := r.refreshStuck[name]
	return since, ok
}

// refreshHookPolicy rewrites one container's policy under its lock. A
// container whose lock is held — a start or a grant judging it now, which
// may wait on a device that does not answer — is skipped, so one container
// never stalls the refresh of every other (m-5); the next run refreshes it.
func (r *LxcRunner) refreshHookPolicy(name string) error {
	unlock, ok := r.tryLockHostAccess(name)
	if !ok {
		slog.Debug("container: host-access policy refresh skipped; the container is being judged now", "container", name)
		return nil
	}
	defer unlock()
	auth, err := readAuthorizedHostAccess(filepath.Join(r.lxcpath(), name))
	if err != nil {
		// Unreadable: authorize nothing until it reads.
		return errors.Join(fmt.Errorf("container %q: %w", name, err), r.writeHookPolicy(name, nil, nil))
	}
	if len(auth.Mounts) == 0 && len(auth.Devices) == 0 {
		return r.syncHookPolicy(name, nil, nil)
	}
	// A record that no longer resolves here yields nothing (rm, rd nil):
	// its policy then authorizes nothing. One that could not be judged now
	// (a read or lookup failed) keeps the policy last written (m-2): the
	// refresh only tightens for a store or prefix that changed, the config
	// still bounds the container, and the hook judges again at pre-start.
	rm, rd, rerr := resolveHostAccess(auth.Mounts, auth.Devices, r.hostAccess(), false)
	if rerr != nil {
		if isTransient(rerr) {
			slog.Warn("container: its host access could not be judged now; its start hook keeps the policy last written", "container", name, "error", rerr)
			return nil
		}
		slog.Warn("container: its host access no longer resolves on this host; its start hook will refuse it", "container", name, "error", rerr)
	}
	if refreshPauseHook != nil {
		refreshPauseHook(name)
	}
	return r.writeHookPolicy(name, rm, rd)
}

// sweepHookPolicies removes the policy of every container whose directory is
// gone (deleted, or migrated to another host). Each is checked again under
// the container's lock, so a container created meanwhile keeps its policy.
func (r *LxcRunner) sweepHookPolicies() error {
	ents, err := os.ReadDir(hookPolicyDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	var errs []error
	for _, e := range ents {
		name, ok := strings.CutSuffix(e.Name(), ".json")
		if !ok || e.IsDir() || name == "" {
			continue
		}
		func() {
			unlock, ok := r.tryLockHostAccess(name)
			if !ok {
				return // being judged now: the next sweep removes it if it is gone
			}
			defer unlock()
			if _, err := os.Stat(filepath.Join(r.lxcpath(), name)); !errors.Is(err, fs.ErrNotExist) {
				return
			}
			if err := os.Remove(hookPolicyFile(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, err)
			}
		}()
	}
	return errors.Join(errs...)
}

// ErrHostAccessBusy is what a host-access change or a start's judgment
// returns when the container's host-access lock stays held past
// hostAccessLockWait — most often by a policy refresh stuck in a lookup that
// does not return. Retryable: the caller maps it to Unavailable.
var ErrHostAccessBusy = errors.New("its host access is held by another operation")

// hostAccessLockWait bounds how long lockHostAccess waits, so a refresh stuck
// in a syscall never holds a start, a convert or a restore — or, through
// their own per-container locks, its stop and delete — forever.
var hostAccessLockWait = 15 * time.Second

// lockHostAccess takes name's host-access lock (its record, config block and
// hook policy change together under it) and returns its release. It waits at
// most hostAccessLockWait, then fails with ErrHostAccessBusy, naming the
// stuck refresh when that is what holds it.
func (r *LxcRunner) lockHostAccess(name string) (func(), error) {
	deadline := time.Now().Add(hostAccessLockWait)
	for {
		if unlock, ok := r.tryLockHostAccess(name); ok {
			return unlock, nil
		}
		if !time.Now().Before(deadline) {
			if since, stuck := r.refreshStuckSince(name); stuck {
				return nil, fmt.Errorf("container %q: %w: a host-access policy refresh has not returned since %s "+
					"(a mount source that does not answer?); retry once it returns", name, ErrHostAccessBusy, since.Format(time.RFC3339))
			}
			return nil, fmt.Errorf("container %q: %w (a start or a host-access change judging it, for over %s); retry",
				name, ErrHostAccessBusy, hostAccessLockWait)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// tryLockHostAccess is lockHostAccess that does not wait: ok is false, and
// nothing is held, when name's lock is taken.
func (r *LxcRunner) tryLockHostAccess(name string) (func(), bool) {
	r.hostAccessMu.Lock()
	if r.hostAccessLocks == nil {
		r.hostAccessLocks = map[string]*sync.Mutex{}
	}
	l := r.hostAccessLocks[name]
	if l == nil {
		l = &sync.Mutex{}
		r.hostAccessLocks[name] = l
	}
	r.hostAccessMu.Unlock()
	if !l.TryLock() {
		return nil, false
	}
	return l.Unlock, true
}

// refreshPauseHook, when set (tests), runs in RefreshHookPolicies between a
// container's resolve and its policy write.
var refreshPauseHook func(name string)

// writeHookPolicy records this host's policy, as it is now, for the hook.
func (r *LxcRunner) writeHookPolicy(name string, rm []resolvedMount, rd []resolvedDevice) error {
	a := r.hostAccess()
	p := hookPolicy{DevicePaths: append([]string(nil), a.DevicePaths...), Mounts: rm, Devices: rd}
	deny, err := effectiveDeny(a, len(rm) > 0)
	if err != nil {
		return fmt.Errorf("this host's stores cannot be read for the start hook's policy: %w", err)
	}
	for _, d := range deny {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		p.Deny = append(p.Deny, filepath.Clean(d))
		if rd := resolveIfExists(d); rd != filepath.Clean(d) {
			p.Deny = append(p.Deny, rd)
		}
	}
	for _, m := range a.MountPaths {
		if !filepath.IsAbs(m) {
			continue
		}
		if rm, err := filepath.EvalSymlinks(filepath.Clean(m)); err == nil {
			p.MountPaths = append(p.MountPaths, rm)
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	// The parent (/run/litevirt) is shared: the daemon's endpoint file, which
	// every user on the node reads, is in it. Made here first, it is made
	// 0755, not the 0700 MkdirAll would give it along with the policy dir.
	if parent := filepath.Dir(hookPolicyDir); parent != hookPolicyDir {
		if err := os.Mkdir(parent, 0o755); err == nil {
			if err := os.Chmod(parent, 0o755); err != nil {
				return err
			}
		} else if !errors.Is(err, fs.ErrExist) && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	if err := os.MkdirAll(hookPolicyDir, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(hookPolicyFile(name), b, 0o600)
}

// readHookPolicy reads the policy the daemon left. A missing or unreadable
// one is an error: the hook then stages nothing.
func readHookPolicy(name string) (hookPolicy, error) {
	var p hookPolicy
	b, err := os.ReadFile(hookPolicyFile(name))
	if err != nil {
		return p, fmt.Errorf("read this host's host-access policy: %w", err)
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return p, fmt.Errorf("parse this host's host-access policy %s: %w", hookPolicyFile(name), err)
	}
	return p, nil
}

// judgeMount re-judges one staged mount: its prefix must still be allowed
// (an allowed prefix or beneath one), the source must lie beneath it, and
// neither may touch a protected tree.
func (p hookPolicy) judgeMount(prefix, src string) error {
	prefix, src = filepath.Clean(prefix), filepath.Clean(src)
	if !within(src, prefix) {
		return fmt.Errorf("%s is not beneath %s", src, prefix)
	}
	allowed := false
	for _, m := range p.MountPaths {
		if m != "/" && within(prefix, filepath.Clean(m)) {
			allowed = true
		}
	}
	if !allowed {
		return fmt.Errorf("%s is no longer under any containers.bind_mount_paths prefix on this host", prefix)
	}
	d, err := deniedTree(src, p.Deny)
	if err != nil {
		return fmt.Errorf("%s: the protected trees cannot be checked: %w", src, err)
	}
	if d != "" {
		return fmt.Errorf("%s is, lies in or contains the protected tree %s", src, d)
	}
	return nil
}

// judgeDevice re-judges one device: still listed exactly, not a host-trust
// node by name or number, the node still the number that was authorized,
// and (a block device) not the host's.
func (p hookPolicy) judgeDevice(src string, kind byte, major, minor uint32) error {
	listed := false
	for _, d := range p.DevicePaths {
		if filepath.Clean(d) == src {
			listed = true
		}
	}
	if !listed {
		return fmt.Errorf("device %s is no longer listed in containers.device_paths on this host", src)
	}
	if deniedDeviceName(src) || deniedDeviceNumber(kind, major, minor) {
		return fmt.Errorf("device %s is never passed through", src)
	}
	fi, err := lstatDevice(src)
	if err != nil {
		return fmt.Errorf("device %s: %w", src, err)
	}
	k, ma, mi, ok := deviceNumbers(fi)
	if !ok || fi.Mode()&fs.ModeSymlink != 0 || k != kind || ma != major || mi != minor {
		return fmt.Errorf("device %s is no longer the node (%c %d:%d) that was authorized", src, kind, major, minor)
	}
	if kind == 'b' {
		if why := blockDeviceInUse(major, minor); why != "" {
			return fmt.Errorf("block device %s is the host's: %s", src, why)
		}
	}
	return nil
}

// hookMount is one mount the hook stages, read from the config's markers.
type hookMount struct {
	ro, file    bool
	prefix, rel string
	staging     string
}

// hookDevice is one device of the managed block, as the hook re-judges it.
type hookDevice struct {
	kind         byte
	major, minor uint32
	source       string
}

// hookDevices reads the managed block's device markers and the source each
// one's mount entry names.
func hookDevices(cfg string) ([]hookDevice, error) {
	block, ok := hostAccessBlockOf(cfg)
	if !ok {
		return nil, fmt.Errorf("host-access block is not closed")
	}
	var out []hookDevice
	var pending *hookDevice
	for _, line := range strings.Split(block, "\n") {
		if rest, ok := strings.CutPrefix(line, deviceMarker+" "); ok {
			var k string
			var ma, mi uint32
			if n, err := fmt.Sscanf(rest, "%s %d:%d", &k, &ma, &mi); n != 3 || err != nil || (k != "c" && k != "b") {
				return nil, fmt.Errorf("bad device marker %q", line)
			}
			pending = &hookDevice{kind: k[0], major: ma, minor: mi}
			continue
		}
		if k, v := configKey(line); k == "lxc.mount.entry" && pending != nil {
			f := strings.Fields(v)
			if len(f) < 2 {
				return nil, fmt.Errorf("bad device entry %q", line)
			}
			pending.source = filepath.Clean(f[0])
			out = append(out, *pending)
			pending = nil
		}
	}
	return out, nil
}

// BlockDeviceNumber is the major:minor of the block device node at p, when p
// is one (symlinks followed): how the daemon compares a VM's disk path with
// a device asked for by a container.
func BlockDeviceNumber(p string) (major, minor uint32, ok bool) {
	fi, err := os.Stat(p)
	if err != nil {
		return 0, 0, false
	}
	kind, ma, mi, ok := deviceNumbers(fi)
	return ma, mi, ok && kind == 'b'
}

// litevirtBlockUse reports why a block device, one of its partitions or the
// disk it belongs to is litevirt's own (a.BlockInUse: a VM disk on this host),
// or "".
func litevirtBlockUse(a HostAccess, major, minor uint32) (string, error) {
	if a.BlockInUse == nil {
		return "", nil
	}
	for _, f := range blockFamily(major, minor) {
		var ma, mi uint32
		if _, err := fmt.Sscanf(f.dev, "%d:%d", &ma, &mi); err != nil {
			continue
		}
		why, err := a.BlockInUse(ma, mi)
		if err != nil {
			return "", err
		}
		if why != "" {
			return f.what + why, nil
		}
	}
	return "", nil
}
