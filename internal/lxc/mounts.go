package lxc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
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
//     path under /run/litevirt (root-only). The LXC pre-start hook — which LXC
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
	// Deny are further trees no mount may come from or be an ancestor of:
	// litevirt's data, PKI and database directories, the image store, storage
	// pool targets and backup repos (the daemon fills them in).
	Deny []string
	// HookBinary is the executable LXC runs as the container's start hook
	// (the litevirt binary, `<HookBinary> __lxc-hook`).
	HookBinary string
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

// deniedTree reports the protected tree p touches — p inside it, or p an
// ancestor of it — or "" when it touches none.
func deniedTree(p string, extra []string) string {
	if p == "/" {
		return "/"
	}
	for _, d := range append(append([]string(nil), hardDenyTrees...), extra...) {
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

// deniedDeviceName reports device nodes never passed through by name.
func deniedDeviceName(p string) bool {
	switch p {
	case "/dev/mem", "/dev/kmem", "/dev/port", "/dev/kvm":
		return true
	}
	return strings.HasPrefix(p, "/dev/vhost-")
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
	}
	return false
}

// ValidateHostAccess refuses an allowed-prefix list a host must not run with:
// a mount prefix that is, lies in, or is an ancestor of a protected tree (so
// never "/"), and a device entry that is not an exact node under /dev or is a
// denied one. The daemon runs it on its config at load.
func ValidateHostAccess(a HostAccess) error {
	for _, p := range a.MountPaths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("containers.bind_mount_paths: %q is not an absolute path", p)
		}
		r := resolveIfExists(p)
		if d := deniedTree(r, a.Deny); d != "" {
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
		return resolvedMount{}, fmt.Errorf("host path %q: %w", m.HostPath, err)
	}
	if !safePathRe.MatchString(resolved) {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, which holds characters a mount entry cannot carry", m.HostPath, resolved)
	}
	if d := deniedTree(resolved, a.Deny); d != "" {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, which is, lies in or contains the protected tree %s", m.HostPath, resolved, d)
	}
	var prefix string
	for _, p := range a.MountPaths {
		if !filepath.IsAbs(p) {
			continue
		}
		rp, perr := filepath.EvalSymlinks(filepath.Clean(p))
		if perr != nil || rp == "/" || deniedTree(rp, a.Deny) != "" || !safePathRe.MatchString(rp) {
			continue
		}
		if within(resolved, rp) && len(rp) > len(prefix) {
			prefix = rp
		}
	}
	if prefix == "" {
		return resolvedMount{}, fmt.Errorf("host path %q resolves to %q, outside every containers.bind_mount_paths prefix on this host", m.HostPath, resolved)
	}
	rel, err := filepath.Rel(prefix, resolved)
	if err != nil || strings.HasPrefix(rel, "..") {
		return resolvedMount{}, fmt.Errorf("host path %q is not beneath %s", resolved, prefix)
	}
	fi, err := os.Lstat(resolved)
	if err != nil {
		return resolvedMount{}, fmt.Errorf("host path %q: %w", resolved, err)
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

// mountinfoPath and sysDevBlock are where block-device use is read; tests
// point them at fixtures.
var (
	mountinfoPath = "/proc/self/mountinfo"
	sysDevBlock   = "/sys/dev/block"
)

// blockDeviceInUse reports why a block device must not be passed through: it
// (or one of its partitions) holds a mounted filesystem, or something — a
// device-mapper or md device, a VM disk's LVM volume — is built on it.
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
	check := func(dev string) string {
		if mounted[dev] {
			return "it holds a mounted filesystem"
		}
		if ents, err := os.ReadDir(filepath.Join(sysDevBlock, dev, "holders")); err == nil && len(ents) > 0 {
			return "another block device (" + ents[0].Name() + ") is built on it"
		}
		return ""
	}
	self := fmt.Sprintf("%d:%d", major, minor)
	if why := check(self); why != "" {
		return why
	}
	// Its partitions: subdirectories of its sysfs node carrying a "partition" file.
	ents, _ := os.ReadDir(filepath.Join(sysDevBlock, self))
	for _, e := range ents {
		if _, err := os.Stat(filepath.Join(sysDevBlock, self, e.Name(), "partition")); err != nil {
			continue
		}
		dev, err := os.ReadFile(filepath.Join(sysDevBlock, self, e.Name(), "dev"))
		if err != nil {
			continue
		}
		if why := check(strings.TrimSpace(string(dev))); why != "" {
			return "its partition " + e.Name() + ": " + why
		}
	}
	return ""
}

// resolveDevice judges one device on this host.
func resolveDevice(d Device, a HostAccess) (resolvedDevice, error) {
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
	fi, err := os.Lstat(src)
	if err != nil {
		return resolvedDevice{}, fmt.Errorf("device %q: %w", src, err)
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
		if why := blockDeviceInUse(major, minor); why != "" {
			return resolvedDevice{}, fmt.Errorf("block device %q is the host's: %s", src, why)
		}
	}
	return resolvedDevice{Source: src, Target: target, Kind: kind, Major: major, Minor: minor}, nil
}

// ResolveHostAccess judges a container's mounts and devices on this host,
// returning the resolved forms its config names, or the first refusal.
func ResolveHostAccess(mounts []Mount, devices []Device, access HostAccess) ([]resolvedMount, []resolvedDevice, error) {
	if len(mounts) > 0 {
		if err := hostAccessSupported(); err != nil {
			return nil, nil, fmt.Errorf("host bind mounts need the kernel's openat2 and new mount API (Linux 5.12+): %w", err)
		}
	}
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
		r, err := resolveDevice(d, access)
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
// the container: root-only, so nothing unprivileged can rename in it.
var stagingRoot = "/run/litevirt/ct"

// stagingPath is the staging mount point of a container's i-th mount.
func stagingPath(name string, i int) string {
	return filepath.Join(stagingRoot, name, fmt.Sprintf("m%d", i))
}

// renderHostAccessBlock is the litevirt-owned config block for a container's
// resolved mounts and devices; "" when there are none.
func renderHostAccessBlock(name, hookBinary string, mounts []resolvedMount, devices []resolvedDevice) string {
	if len(mounts) == 0 && len(devices) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString(mountBlockBegin + "\n")
	if len(mounts) > 0 {
		fmt.Fprintf(&b, "lxc.hook.pre-start = %s %s\n", hookBinary, HookArg)
		fmt.Fprintf(&b, "lxc.hook.post-stop = %s %s\n", hookBinary, HookArg)
	}
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
	cfg := withHostAccessBlock(string(b), renderHostAccessBlock(name, r.hostAccess().HookBinary, rm, rd))
	return writeFileAtomic(cfgPath, []byte(cfg), 0o644)
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
// and rendered, and the config's managed block must be exactly that (its
// hook lines are refreshed to this binary). Any other block — mount options,
// devices.allow lines, entries nobody authorized — refuses the start, as
// does a record that cannot be read.
func (r *LxcRunner) checkHostAccessForStart(name string) error {
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
	if withoutHookLines(have) != withoutHookLines(want) {
		return fmt.Errorf("its host-access block is not what was authorized for it (an admin re-applies the mounts with lv ct convert)")
	}
	if have != want {
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
		c := filepath.Clean(val)
		return strings.HasPrefix(c, lxcSystemConfigDir) && !strings.Contains(val, "..")
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
func (r *LxcRunner) RebuildConfig(name, confinement string, idmapBase int64, mounts []Mount, devices []Device) error {
	dir := filepath.Join(r.lxcpath(), name)
	cfgPath := filepath.Join(dir, "config")
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		return fmt.Errorf("read container config %s: %w", cfgPath, err)
	}
	idmapped := parseSecurity(string(b)).IDMappedMount
	clean, _ := SanitizeImportedConfig(string(b))
	var idmap *IDMap
	if idmapBase != 0 {
		idmap = &IDMap{Base: idmapBase, Size: IDMapSize}
	}
	if confinement == "" {
		confinement = ConfinementLegacy // as an earlier build wrote it, now explicit
	}
	clean = withSecurityBlock(clean, renderSecurityBlock(confinement, idmap, idmap != nil && idmapped))
	if err := writeFileAtomic(cfgPath, []byte(clean), 0o644); err != nil {
		return err
	}
	return r.SetHostAccess(name, mounts, devices)
}
