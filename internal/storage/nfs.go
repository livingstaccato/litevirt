package storage

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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
	if !alreadyMounted {
		mountOpts := "vers=4,hard,intr"
		if extra, ok := d.opts["options"]; ok {
			mountOpts = extra
		}
		mountOpts = hardenNFSOptions(mountOpts)
		mount := func(opts string) ([]byte, error) {
			return run(commandCtx, "mount", "-t", "nfs", "-o", opts, "--", d.source, d.mountDir)
		}
		out, err := mount(mountOpts + ",nosymfollow")
		if err != nil && commandCtx.Err() == nil && nosymfollowUnsupported(out) {
			// nosymfollow needs Linux 5.10+ and a mount.nfs that passes it on.
			// Without it a symlink the server plants is followed in the host's
			// namespace; nosuid,nodev,noexec still hold.
			slog.Warn("NFS mount without nosymfollow (unsupported here): symlinks on the export will be followed",
				"source", d.source, "mountpoint", d.mountDir)
			out, err = mount(mountOpts)
		}
		if err != nil {
			if commandCtx.Err() != nil {
				return nfsCommandError("mount nfs", d.source, commandCtx.Err(), out)
			}
			return nfsCommandError("mount nfs", d.source, err, out)
		}
		slog.Info("NFS mounted", "source", d.source, "mountpoint", d.mountDir)
	}
	return nil
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
var nfsHardening = []string{"nosuid", "nodev", "noexec"}

// hardenNFSOptions appends nfsHardening to opts, and drops any option that
// would undo it (suid, dev, exec).
func hardenNFSOptions(opts string) string {
	var out []string
	for _, o := range strings.Split(opts, ",") {
		o = strings.TrimSpace(o)
		switch o {
		case "", "suid", "dev", "exec", "symfollow", "nosymfollow":
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

// nosymfollowUnsupported reports whether a mount failure is the kernel or
// mount.nfs refusing the nosymfollow option, rather than any other failure.
func nosymfollowUnsupported(out []byte) bool {
	s := strings.ToLower(string(out))
	return strings.Contains(s, "nosymfollow") || strings.Contains(s, "incorrect mount option") ||
		strings.Contains(s, "invalid argument") || strings.Contains(s, "unknown option")
}
