package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/qcow2"
)

const (
	defaultNFSCommandTimeout = 30 * time.Second
	maxNFSCommandOutput      = 4 << 10
)

// nfsDriver mounts an NFS export and stores qcow2/raw files inside the
// mountpoint. The export is mounted lazily by Prepare() and survives
// across daemon restarts (we re-bind-mount on start; no umount on shutdown
// to avoid disturbing co-tenants).
type nfsDriver struct {
	source         string            // "server:/export"
	mountBase      string            // local base directory for mounts (empty if targetOverride set)
	targetOverride string            // explicit mount point from pool config
	opts           map[string]string // mount options et al.
	mountDir       string            // resolved by Prepare()
	run            cmdRunner         // mountpoint, mount, and umount seam; tests inject a fake
}

func (d *nfsDriver) String() string { return "nfs" }

// Teardown unmounts a litevirt-OWNED NFS mount on pool delete. It does NOT touch a
// mount the operator manages (targetOverride set) — that's a shared path we didn't
// create. Idempotent: a no-op when the path isn't mounted. Derives the mountpoint
// the same way Prepare does, so it's safe to call without a prior Prepare. The
// caller is responsible for the cross-pool refcount (don't tear down an export
// another pool still uses).
func (d *nfsDriver) Teardown(ctx context.Context) error {
	if d.targetOverride != "" {
		slog.Info("NFS teardown skipped: operator-managed mount", "source", d.source, "target", d.targetOverride)
		return nil
	}
	commandCtx, cancel, err := d.commandContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	run := d.run
	if run == nil {
		run = realCmd
	}
	safe := strings.NewReplacer("/", "_", ":", "_").Replace(d.source)
	mountDir := filepath.Join(d.mountBase, safe)
	if out, err := run(commandCtx, "mountpoint", "-q", "--", mountDir); err != nil {
		if commandCtx.Err() != nil {
			return nfsCommandError("check nfs mountpoint", d.source, commandCtx.Err(), out)
		}
		if mountpointNotMounted(err) {
			return nil
		}
		return nfsCommandError("check nfs mountpoint", mountDir, err, out)
	}
	if out, err := run(commandCtx, "umount", "--", mountDir); err != nil {
		if commandCtx.Err() != nil {
			return nfsCommandError("umount nfs", mountDir, commandCtx.Err(), out)
		}
		return nfsCommandError("umount nfs", mountDir, err, out)
	}
	slog.Info("NFS unmounted", "source", d.source, "mountpoint", mountDir)
	return nil
}

func (d *nfsDriver) Prepare(ctx context.Context) error {
	commandCtx, cancel, err := d.commandContext(ctx)
	if err != nil {
		return err
	}
	defer cancel()

	if d.targetOverride != "" {
		d.mountDir = d.targetOverride
	} else {
		safe := strings.NewReplacer("/", "_", ":", "_").Replace(d.source)
		d.mountDir = filepath.Join(d.mountBase, safe)
	}

	if err := os.MkdirAll(d.mountDir, 0755); err != nil {
		return fmt.Errorf("create mount dir: %w", err)
	}

	run := d.run
	if run == nil {
		run = realCmd
	}

	// `mountpoint -q` reports the result ONLY via exit code (0 = already a
	// mountpoint) — it prints nothing — so the old `string(out) == ""` test was
	// always true and re-ran `mount` on every Prepare (every CreateVM / restart),
	// which fails on already-mounted configs or stacks mounts (bug-sweep #8).
	// Skip the mount when it's already mounted, keyed on the exit code.
	mountpointOut, err := run(commandCtx, "mountpoint", "-q", "--", d.mountDir)
	if err != nil && commandCtx.Err() != nil {
		return nfsCommandError("check nfs mountpoint", d.mountDir, commandCtx.Err(), mountpointOut)
	}
	alreadyMounted := err == nil
	if alreadyMounted {
		// Mounted before this build, or by hand: it may lack the hardening.
		return d.ensureHardened()
	}
	mountOpts := "vers=4,hard,intr"
	if extra, ok := d.opts["options"]; ok {
		mountOpts = extra
	}
	// nosymfollow is required, not best-effort: without it a symlink the
	// server plants is followed as root in the host's namespace by anything
	// that opens a pool file by name (qemu-img, qemu). A kernel or mount.nfs
	// that cannot do it gets no NFS pool.
	mountOpts = hardenNFSOptions(mountOpts) + ",nosymfollow"
	out, err := run(commandCtx, "mount", "-t", "nfs", "-o", mountOpts, "--", d.source, d.mountDir)
	if err != nil {
		if commandCtx.Err() != nil {
			return nfsCommandError("mount nfs", d.source, commandCtx.Err(), out)
		}
		return fmt.Errorf("%w (an NFS pool is mounted nosuid,nodev,noexec,nosymfollow; nosymfollow needs Linux 5.10+ and a mount.nfs that passes it on)",
			nfsCommandError("mount nfs", d.source, err, out))
	}
	slog.Info("NFS mounted", "source", d.source, "mountpoint", d.mountDir, "options", mountOpts)
	return nil
}

// nfsRequiredFlags are the per-mount flags every NFS pool's mount must carry.
var nfsRequiredFlags = []string{"nosuid", "nodev", "noexec", "nosymfollow"}

// readMountInfo returns /proc/self/mountinfo; tests replace it.
var readMountInfo = func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") }

// mountEntry is one line of mountinfo: where, the per-mount options, and what
// is mounted there (filesystem type and source).
type mountEntry struct {
	dir    string
	flags  []string
	fstype string
	source string
}

// mounts parses mountinfo, in order (a later mount on the same point is on top).
func mounts() ([]mountEntry, error) {
	data, err := readMountInfo()
	if err != nil {
		return nil, err
	}
	var out []mountEntry
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 {
			continue
		}
		e := mountEntry{dir: filepath.Clean(unescapeMountInfo(f[4])), flags: strings.Split(f[5], ",")}
		// Optional fields end at "-"; filesystem type and source follow it.
		if i := slices.Index(f[6:], "-"); i >= 0 && len(f) > 6+i+2 {
			e.fstype, e.source = f[6+i+1], unescapeMountInfo(f[6+i+2])
		}
		out = append(out, e)
	}
	return out, nil
}

// mountAt returns the mount at dir (the top one, when mounts are stacked), and
// whether dir is a mount point at all.
func mountAt(dir string) (mountEntry, bool, error) {
	all, err := mounts()
	if err != nil {
		return mountEntry{}, false, err
	}
	want := filepath.Clean(dir)
	var top mountEntry
	found := false
	for _, e := range all {
		if e.dir == want {
			top, found = e, true
		}
	}
	return top, found, nil
}

// mountFlags returns the per-mount options of the mount at dir (the last one,
// when mounts are stacked), and whether dir is a mount point at all.
func mountFlags(dir string) ([]string, bool, error) {
	e, found, err := mountAt(dir)
	return e.flags, found, err
}

// unescapeMountInfo undoes mountinfo's octal escapes (\040 for a space …).
func unescapeMountInfo(s string) string {
	if !strings.Contains(s, "\\") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func missingNFSFlags(flags []string) []string {
	var miss []string
	for _, f := range nfsRequiredFlags {
		if !slices.Contains(flags, f) {
			miss = append(miss, f)
		}
	}
	return miss
}

// ensureHardened refuses an existing mount at d.mountDir that is not this
// pool's export, or that lacks any of nfsRequiredFlags. It does not remount:
// litevirt uses only a mount it made itself, of the pool's own export with
// those flags, so anything else there (another export left by a deleted pool,
// a mount made by hand, or by an earlier build) must be unmounted and is then
// mounted again by Prepare.
func (d *nfsDriver) ensureHardened() error {
	m, mounted, err := mountAt(d.mountDir)
	if err != nil {
		return fmt.Errorf("read mount options of %s: %w", d.mountDir, err)
	}
	if !mounted {
		return fmt.Errorf("%s reports as a mount point but is not in mountinfo; refusing to use it", d.mountDir)
	}
	// The export mounted there is compared in the same canonical form as the
	// pool's source: another export (or the same server's parent export) at
	// the pool's mount point would hand the pool someone else's files.
	want, werr := ParseNFSExport(d.source)
	got, gerr := ParseNFSExport(m.source)
	if werr != nil || gerr != nil || got != want || !isNFSFstype(m.fstype) {
		slog.Error("NFS pool's mount point holds a mount that is not its export; the pool is refused until it is unmounted",
			"mountpoint", d.mountDir, "mounted", m.source, "fstype", m.fstype, "source", d.source)
		return fmt.Errorf("%s has %s mounted, not this pool's export %s; unmount it (umount %s) and litevirt mounts the pool's export there",
			d.mountDir, mountedWhat(m), d.source, d.mountDir)
	}
	flags := m.flags
	if miss := missingNFSFlags(flags); len(miss) > 0 {
		slog.Error("NFS pool is mounted without the required options; the pool is refused until it is unmounted and mounted again by litevirt",
			"mountpoint", d.mountDir, "missing", miss)
		return fmt.Errorf("NFS mount at %s lacks %s; unmount it (umount %s) and litevirt mounts it again with them",
			d.mountDir, strings.Join(miss, ","), d.mountDir)
	}
	return nil
}

func isNFSFstype(t string) bool { return t == "nfs" || t == "nfs4" }

func mountedWhat(m mountEntry) string {
	if m.source == "" {
		return "a mount"
	}
	return fmt.Sprintf("%q (%s)", m.source, m.fstype)
}

// CheckNFSMountHardened refuses an NFS pool whose mount point holds anything
// but its own export (ensureHardened), or holds it mounted without
// nosuid,nodev,noexec,nosymfollow. A pool that is not mounted passes (Prepare
// mounts it with them). Not an NFS config: nil.
func CheckNFSMountHardened(dataDir string, cfg Config) error {
	if !strings.EqualFold(cfg.Driver, "nfs") {
		return nil
	}
	dir := cfg.Target
	if dir == "" {
		dir = filepath.Join(dataDir, "mounts", NFSMountName(cfg.Source))
	}
	d := &nfsDriver{source: cfg.Source, mountDir: dir}
	if _, mounted, err := mountFlags(dir); err != nil {
		return fmt.Errorf("read mount options of %s: %w", dir, err)
	} else if !mounted {
		return nil
	}
	return d.ensureHardened()
}

// MountTable is a snapshot of this host's mount table, read once and judged
// many times (one per pool row).
type MountTable struct{ all []mountEntry }

// ReadMountTable reads the mount table.
func ReadMountTable() (MountTable, error) {
	all, err := mounts()
	if err != nil {
		return MountTable{}, fmt.Errorf("read the mount table: %w", err)
	}
	return MountTable{all: all}, nil
}

// NFSBacking is the NFS export a directory is stored on, and what its mount
// lacks of nosuid,nodev,noexec,nosymfollow.
type NFSBacking struct {
	// Export is the export of the mount the directory is on plus the path of
	// the directory below that mount point: the directory's identity as NFS
	// storage, comparable with an nfs pool's Source and with any other
	// directory on the same export, on any host.
	Export NFSExport
	// MountPoint is where that export is mounted on this host.
	MountPoint string
	// Missing lists the required per-mount options the mount lacks.
	Missing []string
}

// NFSBackingOf reports whether dir is on an NFS mount — the mount point
// itself or anything below it, judged as written and after resolving
// symlinks (the resolved form wins) — and if so which export it is and what
// its mount lacks. nil: on no NFS mount. An error: the mount's source is not
// an NFS export litevirt can identify.
func (t MountTable) NFSBackingOf(dir string) (*NFSBacking, error) {
	var out *NFSBacking
	for _, p := range pathForms(dir) {
		var under mountEntry
		for _, e := range t.all {
			// The deepest mount containing p is the one p is on; the last of
			// equal depth is on top.
			if within(e.dir, p) && len(e.dir) >= len(under.dir) {
				under = e
			}
		}
		if !isNFSFstype(under.fstype) {
			continue
		}
		exp, err := ParseNFSExport(under.source)
		if err != nil {
			return nil, fmt.Errorf("%s is on an NFS mount at %s whose source is not server:/export", dir, under.dir)
		}
		rel, err := filepath.Rel(under.dir, p)
		if err != nil {
			return nil, err
		}
		exp.Path = filepath.Clean(filepath.Join(exp.Path, rel))
		out = &NFSBacking{Export: exp, MountPoint: under.dir, Missing: missingNFSFlags(under.flags)}
	}
	return out, nil
}

// CheckNFSBackingHardened refuses a directory pool (local, dir, btrfs) whose
// directory is on an NFS mount without nosuid,nodev,noexec,nosymfollow: the
// export's server decides what is on it, so nothing there may be a setuid
// binary, a device node, an executable or a symlink followed as root. The
// refusal names the mount point and the options it lacks, never the export.
func CheckNFSBackingHardened(dir string) error {
	t, err := ReadMountTable()
	if err != nil {
		return err
	}
	b, err := t.NFSBackingOf(dir)
	if err != nil || b == nil {
		return err
	}
	if len(b.Missing) > 0 {
		return fmt.Errorf("%s is on an NFS mount at %s without %s; mount it with nosuid,nodev,noexec,nosymfollow (in fstab, for a mount litevirt does not make)",
			dir, b.MountPoint, strings.Join(b.Missing, ","))
	}
	return nil
}

// OverrideMountInfoForTest replaces how mounts are inspected, for tests in
// other packages. It returns the restore function.
func OverrideMountInfoForTest(mountinfo func() ([]byte, error)) func() {
	prev := readMountInfo
	readMountInfo = mountinfo
	return func() { readMountInfo = prev }
}

func (d *nfsDriver) commandContext(ctx context.Context) (context.Context, context.CancelFunc, error) {
	timeout := defaultNFSCommandTimeout
	if configured, ok := d.opts["command_timeout"]; ok {
		configured = strings.TrimSpace(configured)
		if configured != "" {
			parsed, err := time.ParseDuration(configured)
			if err != nil || parsed <= 0 {
				return nil, nil, fmt.Errorf("invalid NFS command_timeout %q: must be a positive duration", configured)
			}
			timeout = parsed
		}
	}
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	return commandCtx, cancel, nil
}

// mountpoint -q exits 32 when its target is not a mountpoint. Other failures
// (including a missing binary or permission error) are probe failures and must
// not be treated as an idempotent teardown success.
func mountpointNotMounted(err error) bool {
	var exitCode interface{ ExitCode() int }
	return errors.As(err, &exitCode) && exitCode.ExitCode() == 32
}

func nfsCommandError(operation, target string, err error, out []byte) error {
	if output := trimmedNFSCommandOutput(out); output != "" {
		return fmt.Errorf("%s %s: %w: %s", operation, target, err, output)
	}
	return fmt.Errorf("%s %s: %w", operation, target, err)
}

func trimmedNFSCommandOutput(out []byte) string {
	output := strings.TrimSpace(string(out))
	if len(output) > maxNFSCommandOutput {
		return output[:maxNFSCommandOutput] + "…"
	}
	return output
}

func (d *nfsDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	if d.mountDir == "" {
		return "", fmt.Errorf("NFS not prepared; call Prepare first")
	}
	path := filepath.Join(d.mountDir, fmt.Sprintf("%s-%s.qcow2", opts.VMName, opts.DiskName))
	format := opts.Format
	if format == "" {
		format = "qcow2"
	}

	if format == "qcow2" {
		qOpts := qcow2Opts(opts)
		if opts.SourceImage != "" {
			if err := qcow2.CreateWithBacking(path, opts.SourceImage, uint64(opts.SizeBytes), qOpts); err != nil {
				return "", fmt.Errorf("create overlay disk on NFS: %w", err)
			}
		} else {
			if err := qcow2.Create(path, uint64(opts.SizeBytes), qOpts); err != nil {
				return "", fmt.Errorf("create disk on NFS: %w", err)
			}
		}
	} else {
		f, err := CreateExclusive(path)
		if err != nil {
			return "", fmt.Errorf("create raw disk on NFS: %w", err)
		}
		if err := f.Truncate(opts.SizeBytes); err != nil {
			f.Close()
			return "", fmt.Errorf("truncate raw disk on NFS: %w", err)
		}
		// fsync to flush the new file to the NFS server before reporting
		// success — a crash mid-write must not leave a partial disk (F7).
		if err := f.Sync(); err != nil {
			f.Close()
			return "", fmt.Errorf("sync raw disk on NFS: %w", err)
		}
		f.Close()
	}

	slog.Info("NFS disk created", "path", path)
	return path, nil
}

func (d *nfsDriver) DeleteDisk(_ context.Context, path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove NFS disk %s: %w", path, err)
	}
	return nil
}

// nfsHardening is what every NFS pool is mounted with: the export's server
// decides its contents, so nothing on it may be a setuid binary, a device
// node or an executable as far as this host is concerned. Pool content is
// disk images; qemu reads them, nothing executes them.
//
// nosharecache gives each mount its own superblock. Without it two mounts of
// one server share the first mount's, and the kernel reports that mount's
// spelling of the server as the source of both: a pool mounted by address
// beside one mounted by name would then fail the source check at every use.
var nfsHardening = []string{"nosuid", "nodev", "noexec", "nosharecache"}

// hardenNFSOptions appends nfsHardening to opts, and drops any option that
// would undo it (suid, dev, exec, sharecache).
func hardenNFSOptions(opts string) string {
	var out []string
	for _, o := range strings.Split(opts, ",") {
		o = strings.TrimSpace(o)
		switch o {
		case "", "suid", "dev", "exec", "symfollow", "nosymfollow", "sharecache":
			continue
		}
		out = append(out, o)
	}
	for _, h := range nfsHardening {
		if !slices.Contains(out, h) {
			out = append(out, h)
		}
	}
	return strings.Join(out, ",")
}

// Empty reports whether the table was never read.
func (t MountTable) Empty() bool { return t.all == nil }
