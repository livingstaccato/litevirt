package lxc

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// Host bind mounts and device nodes (Proxmox mpN / devN).
//
// Mounting a host path into a container is a host privilege escalation: on
// Proxmox only root@pam may do it. Here the gRPC layer requires the admin role,
// and this layer — which runs ON the host — decides what the host allows:
//
//   - every host path must resolve, symlinks followed, under a prefix in this
//     host's containers.bind_mount_paths (mounts) or containers.device_paths
//     (devices). Empty lists allow nothing;
//   - the RESOLVED path is what the config names, so a symlink that points out
//     of the allowed tree is refused rather than followed;
//   - the check runs again at every start (prepareStart): a path that has since
//     become a symlink, left the allowed tree, changed kind, or a device whose
//     major:minor changed, refuses the start. A container migrated or restored
//     here is judged by THIS host's lists, not the ones it was created under;
//   - mounts are read-only unless asked otherwise, and always nosuid,nodev;
//   - nothing about the user namespace changes: an unprivileged container
//     keeps its id map, so a mounted tree's files appear owned by the ids they
//     map to (unmapped ones as nobody), and a device node is only as usable as
//     its mode lets the mapped ids use it.
//
// What remains is a race between the start check and lxc-start's own mount:
// whoever can rename inside an allowed tree in that window can swap a symlink
// in. Allow only trees that untrusted users cannot write.

// Mount is one host path bind-mounted into a container.
type Mount struct {
	HostPath      string
	ContainerPath string
	ReadWrite     bool
}

// Device is one host device node passed into a container. ContainerPath ""
// means the host path.
type Device struct {
	HostPath      string
	ContainerPath string
}

// HostAccess is what this host lets containers reach: path prefixes for bind
// mounts and for device nodes.
type HostAccess struct {
	MountPaths  []string
	DevicePaths []string
}

// resolvedMount / resolvedDevice are a mount and a device after the host
// resolved and judged them: the paths the config will name.
type resolvedMount struct {
	Source string // resolved host path
	Target string // container path, relative to the rootfs
	RW     bool
	File   bool // a file rather than a directory (create=file)
}

type resolvedDevice struct {
	Source string // resolved host device node
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
// cleaned. A ".." element is refused outright rather than cleaned away, so a
// path never means something other than what it says.
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
// the rootfs, as lxc.mount.entry names it. LXC itself confines the target to
// the container's rootfs.
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

// forbiddenMountSource reports a host tree no bind mount may come from, even
// when an allowed prefix covers it: the whole filesystem, and the kernel and
// device trees (a device is passed as a Device, which checks its kind).
func forbiddenMountSource(p string) bool {
	if p == "/" {
		return true
	}
	for _, t := range []string{"/proc", "/sys", "/dev"} {
		if p == t || strings.HasPrefix(p, t+"/") {
			return true
		}
	}
	return false
}

// underAllowed resolves each allowed prefix as the host sees it now and reports
// whether resolved lies inside one. A prefix that does not exist allows
// nothing; one that is not absolute is ignored.
func underAllowed(resolved string, allowed []string) bool {
	for _, a := range allowed {
		if !filepath.IsAbs(a) {
			continue
		}
		ra, err := filepath.EvalSymlinks(filepath.Clean(a))
		if err != nil {
			continue
		}
		if ra == "/" || resolved == ra || strings.HasPrefix(resolved, ra+"/") {
			return true
		}
	}
	return false
}

// resolveMount judges one mount on this host.
func resolveMount(m Mount, allowed []string) (resolvedMount, error) {
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
		return resolvedMount{}, fmt.Errorf("host path %q: %w", m.HostPath, err)
	}
	if !safePathRe.MatchString(resolved) {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, which holds characters a mount entry cannot carry", m.HostPath, resolved)
	}
	if forbiddenMountSource(resolved) {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, which is never bind-mounted (the root, /proc, /sys or /dev; pass a device node as a device)", m.HostPath, resolved)
	}
	if !underAllowed(resolved, allowed) {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, outside every containers.bind_mount_paths prefix on this host", m.HostPath, resolved)
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return resolvedMount{}, fmt.Errorf("host path %q: %w", resolved, err)
	}
	switch {
	case fi.IsDir():
		return resolvedMount{Source: resolved, Target: target, RW: m.ReadWrite}, nil
	case fi.Mode().IsRegular():
		return resolvedMount{Source: resolved, Target: target, RW: m.ReadWrite, File: true}, nil
	}
	return resolvedMount{}, fmt.Errorf("host path %q is neither a directory nor a regular file", resolved)
}

// deviceNumbers reads a device node's kind and major:minor.
func deviceNumbers(fi fs.FileInfo) (kind byte, major, minor uint32, ok bool) {
	switch {
	case fi.Mode()&fs.ModeCharDevice != 0:
		kind = 'c'
	case fi.Mode()&fs.ModeDevice != 0:
		kind = 'b'
	default:
		return 0, 0, 0, false
	}
	st, sok := fi.Sys().(*syscall.Stat_t)
	if !sok {
		return 0, 0, 0, false
	}
	rdev := uint64(st.Rdev) // uint64 on linux, int32 on darwin
	major = uint32(((rdev >> 8) & 0xfff) | ((rdev >> 32) & 0xfffff000))
	minor = uint32((rdev & 0xff) | ((rdev >> 12) & 0xffffff00))
	return kind, major, minor, true
}

// resolveDevice judges one device on this host.
func resolveDevice(d Device, allowed []string) (resolvedDevice, error) {
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
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		return resolvedDevice{}, fmt.Errorf("device %q: %w", d.HostPath, err)
	}
	if !safePathRe.MatchString(resolved) {
		return resolvedDevice{}, fmt.Errorf("device %q resolves to %q, which holds characters a mount entry cannot carry", d.HostPath, resolved)
	}
	if !underAllowed(resolved, allowed) {
		return resolvedDevice{}, fmt.Errorf("device %q resolves to %q, outside every containers.device_paths prefix on this host", d.HostPath, resolved)
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return resolvedDevice{}, fmt.Errorf("device %q: %w", resolved, err)
	}
	kind, major, minor, ok := deviceNumbers(fi)
	if !ok {
		return resolvedDevice{}, fmt.Errorf("device %q is not a character or block device node", resolved)
	}
	return resolvedDevice{Source: resolved, Target: target, Kind: kind, Major: major, Minor: minor}, nil
}

// ResolveHostAccess judges a container's mounts and devices on this host,
// returning the resolved forms its config names, or the first refusal.
func ResolveHostAccess(mounts []Mount, devices []Device, access HostAccess) ([]resolvedMount, []resolvedDevice, error) {
	var rm []resolvedMount
	for _, m := range mounts {
		r, err := resolveMount(m, access.MountPaths)
		if err != nil {
			return nil, nil, err
		}
		rm = append(rm, r)
	}
	var rd []resolvedDevice
	for _, d := range devices {
		r, err := resolveDevice(d, access.DevicePaths)
		if err != nil {
			return nil, nil, err
		}
		rd = append(rd, r)
	}
	return rm, rd, nil
}

const (
	mountBlockBegin = "# litevirt:host-access-begin"
	mountBlockEnd   = "# litevirt:host-access-end"
	// Each entry is preceded by a marker naming its kind, which the start
	// check reads: "mount ro|rw dir|file" or "device c|b <major>:<minor>".
	mountMarker  = "# litevirt:mount"
	deviceMarker = "# litevirt:device"
)

// renderHostAccessBlock is the litevirt-owned config block for resolved mounts
// and devices; "" when there are none.
func renderHostAccessBlock(mounts []resolvedMount, devices []resolvedDevice) string {
	if len(mounts) == 0 && len(devices) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(mountBlockBegin + "\n")
	for _, m := range mounts {
		mode, kind, create := "ro", "dir", "create=dir"
		opts := "bind,ro,nosuid,nodev"
		if m.RW {
			mode, opts = "rw", "bind,nosuid,nodev"
		}
		if m.File {
			kind, create = "file", "create=file"
		}
		fmt.Fprintf(&b, "%s %s %s\n", mountMarker, mode, kind)
		fmt.Fprintf(&b, "lxc.mount.entry = %s %s none %s,%s 0 0\n", m.Source, m.Target, opts, create)
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

// HostAccessEntry is one entry of a container's managed block, as the start
// check reads it back.
type HostAccessEntry struct {
	Device bool   // a device node rather than a bind mount
	Source string // the host path the config names
	Target string
	RW     bool   // mounts: read-write
	File   bool   // mounts: a regular file
	Kind   byte   // devices: 'c' or 'b'
	Major  uint32 // devices
	Minor  uint32 // devices
}

// ParseHostAccess reads the managed block's entries from a config rendering.
// A block that does not parse is an error: the start check must not pass a
// container whose mounts it cannot read.
func ParseHostAccess(cfg string) ([]HostAccessEntry, error) {
	var out []HostAccessEntry
	in := false
	var pending *HostAccessEntry
	for _, line := range strings.Split(cfg, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == mountBlockBegin:
			in = true
			continue
		case t == mountBlockEnd:
			if pending != nil {
				return nil, fmt.Errorf("host-access block: a marker has no mount entry")
			}
			in = false
			continue
		case !in || t == "":
			continue
		}
		if rest, ok := strings.CutPrefix(t, mountMarker+" "); ok {
			f := strings.Fields(rest)
			if len(f) != 2 || (f[0] != "ro" && f[0] != "rw") || (f[1] != "dir" && f[1] != "file") {
				return nil, fmt.Errorf("host-access block: bad mount marker %q", t)
			}
			pending = &HostAccessEntry{RW: f[0] == "rw", File: f[1] == "file"}
			continue
		}
		if rest, ok := strings.CutPrefix(t, deviceMarker+" "); ok {
			f := strings.Fields(rest)
			mm := strings.SplitN(safeIndex(f, 1), ":", 2)
			if len(f) != 2 || (f[0] != "c" && f[0] != "b") || len(mm) != 2 {
				return nil, fmt.Errorf("host-access block: bad device marker %q", t)
			}
			maj, e1 := strconv.ParseUint(mm[0], 10, 32)
			mnr, e2 := strconv.ParseUint(mm[1], 10, 32)
			if e1 != nil || e2 != nil {
				return nil, fmt.Errorf("host-access block: bad device numbers %q", t)
			}
			pending = &HostAccessEntry{Device: true, Kind: f[0][0], Major: uint32(maj), Minor: uint32(mnr)}
			continue
		}
		k, v := configKey(line)
		switch k {
		case "lxc.cgroup2.devices.allow":
			continue
		case "lxc.mount.entry":
			if pending == nil {
				return nil, fmt.Errorf("host-access block: mount entry %q has no marker", t)
			}
			f := strings.Fields(v)
			if len(f) < 2 {
				return nil, fmt.Errorf("host-access block: bad mount entry %q", t)
			}
			pending.Source, pending.Target = f[0], f[1]
			out = append(out, *pending)
			pending = nil
		default:
			return nil, fmt.Errorf("host-access block: unexpected line %q", t)
		}
	}
	if in {
		return nil, fmt.Errorf("host-access block is not closed")
	}
	return out, nil
}

func safeIndex(f []string, i int) string {
	if i < len(f) {
		return f[i]
	}
	return ""
}

// VerifyHostAccess re-judges a container's managed mounts and devices on this
// host as they are NOW: each source must still be exactly the path the config
// names (no symlink has appeared anywhere along it), still under this host's
// allowed prefixes, still the same kind — and a device still the same
// major:minor. Run before every start.
func VerifyHostAccess(cfg string, access HostAccess) error {
	entries, err := ParseHostAccess(cfg)
	if err != nil {
		return err
	}
	for _, e := range entries {
		resolved, err := filepath.EvalSymlinks(e.Source)
		if err != nil {
			return fmt.Errorf("host path %q: %w", e.Source, err)
		}
		if resolved != e.Source {
			return fmt.Errorf("host path %q now resolves to %q (a symlink appeared); refusing to mount it", e.Source, resolved)
		}
		fi, err := os.Lstat(e.Source)
		if err != nil {
			return fmt.Errorf("host path %q: %w", e.Source, err)
		}
		if e.Device {
			if !underAllowed(e.Source, access.DevicePaths) {
				return fmt.Errorf("device %q is outside every containers.device_paths prefix on this host", e.Source)
			}
			kind, major, minor, ok := deviceNumbers(fi)
			if !ok || kind != e.Kind || major != e.Major || minor != e.Minor {
				return fmt.Errorf("device %q is no longer the %c %d:%d node it was passed through as", e.Source, e.Kind, e.Major, e.Minor)
			}
			continue
		}
		if forbiddenMountSource(e.Source) || !underAllowed(e.Source, access.MountPaths) {
			return fmt.Errorf("host path %q is outside every containers.bind_mount_paths prefix on this host", e.Source)
		}
		if (e.File && !fi.Mode().IsRegular()) || (!e.File && !fi.IsDir()) {
			return fmt.Errorf("host path %q changed kind since it was mounted", e.Source)
		}
	}
	return nil
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
