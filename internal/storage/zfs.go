package storage

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"
)

// zfsDriver provisions ZFS zvols (block devices) under a parent dataset.
// We use zvols rather than file-on-zfs so backups via `zfs send` are
// streamable byte-for-byte and snapshot semantics are atomic.
//
// Pool config:
//
//	driver:  zfs
//	source:  <parent dataset>          # e.g. "tank/litevirt"
//	options:
//	  volblocksize: 16k                 # default 16k; 4k-128k valid
//	  compression:  lz4                 # passed through to zfs create
//	  encryption:   off                 # native ZFS encryption opt
//
// Each disk lands at "<parent>/<vm>-<disk>" as a zvol; the libvirt
// source path is "/dev/zvol/<parent>/<vm>-<disk>".
type zfsDriver struct {
	dataset string
	opts    map[string]string
	run     cmdRunner // nil → realCmd; overridable in tests
}

func (d *zfsDriver) String() string { return "zfs" }

// zfsPipe runs the send | recv pipeline; tests replace it.
var zfsPipe = pipeCmds

// zfs runs a zfs subcommand through the driver's runner (real exec by default).
func (d *zfsDriver) zfs(ctx context.Context, args ...string) ([]byte, error) {
	run := d.run
	if run == nil {
		run = realCmd
	}
	return run(ctx, "zfs", args...)
}

func (d *zfsDriver) Prepare(ctx context.Context) error {
	if d.dataset == "" {
		return fmt.Errorf("zfs: dataset (Source) required")
	}
	out, err := exec.CommandContext(ctx, "zfs", "list", "-H", "-o", "name", "--", d.dataset).CombinedOutput()
	if err != nil {
		return fmt.Errorf("zfs list %s: %w: %s", d.dataset, err, out)
	}
	return nil
}

func (d *zfsDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	// Fail fast on source-image clone (not yet implemented). Returning a blank
	// zvol as "success" would silently boot the wrong (empty) disk, so reject up
	// front rather than creating an orphan zvol we'd then disown.
	if opts.SourceImage != "" {
		return "", fmt.Errorf("%w: zfs source-image clone (source=%q) — would boot a blank disk",
			ErrUnimplemented, opts.SourceImage)
	}

	zvol := fmt.Sprintf("%s/%s-%s", d.dataset, opts.VMName, opts.DiskName)
	args := []string{"create", "-V", fmt.Sprintf("%d", opts.SizeBytes)}
	if vbs := d.opts["volblocksize"]; vbs != "" {
		args = append(args, "-o", "volblocksize="+vbs)
	}
	if comp := d.opts["compression"]; comp != "" {
		args = append(args, "-o", "compression="+comp)
	}
	args = append(args, "--", zvol)

	if out, err := exec.CommandContext(ctx, "zfs", args...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("zfs create %s: %w: %s", zvol, err, out)
	}

	path := "/dev/zvol/" + zvol
	slog.Info("zvol created", "zvol", zvol, "path", path, "size", opts.SizeBytes)
	return path, nil
}

// Replicate implements native ZFS send/recv. The src/dst
// refs are zvol names ("tank/litevirt/vm-data"); for a same-host
// pipe we use `zfs send | zfs recv`, for cross-host we add an SSH
// hop. Incremental sends use `-I` against the prior snapshot
// recorded under <dataset>@litevirt-replicate-prev so subsequent
// replications send only the diff.
func (d *zfsDriver) Replicate(ctx context.Context, opts ReplicateOptions) (err error) {
	if opts.SrcRef == "" || opts.DstRef == "" {
		return fmt.Errorf("zfs replicate: src and dst refs required")
	}
	// The destination must not exist: the receive below has no -F, and a
	// dataset of that name is refused here first, before anything is sent.
	if _, lerr := d.zfs(ctx, "list", "-H", "-o", "name", "--", opts.DstRef); lerr == nil {
		return fmt.Errorf("zfs replicate → %s: %w", opts.DstRef, ErrDestinationExists)
	}
	snap := opts.SnapshotName
	if snap == "" {
		snap = "litevirt-" + nowSnapTag()
	}
	srcSnap := fmt.Sprintf("%s@%s", opts.SrcRef, snap)
	if out, serr := d.zfs(ctx, "snapshot", "--", srcSnap); serr != nil {
		return fmt.Errorf("zfs snapshot %s: %w: %s", srcSnap, serr, out)
	}
	// The per-call snapshot is the copy's point in time only: always
	// destroyed (the incremental base is the separate "prev" snapshot).
	defer func() {
		if out, derr := d.zfs(ctx, "destroy", "--", srcSnap); derr != nil && err == nil {
			err = fmt.Errorf("zfs destroy %s: %w: %s", srcSnap, derr, out)
		}
	}()
	// Anything after the receive fails: the dataset this copy created is
	// destroyed, never left unrecorded.
	received := false
	defer func() {
		if err != nil && received {
			_, _ = d.zfs(ctx, "destroy", "-r", "--", opts.DstRef)
		}
	}()

	sendArgs := []string{"send"}
	prev := fmt.Sprintf("%s@litevirt-replicate-prev", opts.SrcRef)
	if opts.Incremental && snapshotExists(ctx, prev) {
		sendArgs = append(sendArgs, "-I", prev, "--", srcSnap)
	} else {
		sendArgs = append(sendArgs, "--", srcSnap)
	}

	// Never -F: a forced receive rolls back or replaces whatever dataset has
	// the name. Without it, zfs refuses an existing destination itself.
	recvArgs := []string{"recv", "--", opts.DstRef}
	if _, perr := zfsPipe(ctx, opts.SSHTarget, "zfs", sendArgs, "zfs", recvArgs); perr != nil {
		return fmt.Errorf("zfs replicate %s → %s: %w", opts.SrcRef, opts.DstRef, perr)
	}
	received = true
	// Record first: a recorded copy is what a failure below may leave. `zfs
	// set` takes no "--": OpenZFS up to 2.1 parses its arguments without
	// getopt and refuses any argument starting with "-" (GrowBlockVolume says
	// the same). Neither the property ("litevirt:…") nor DstRef (a dataset
	// under the pool's, never starting with "-") can be taken for an option.
	// A property that cannot be written is warned about and the copy is
	// kept: it is the data the operator asked for, and the deferred cleanup
	// must never destroy it for a missing label.
	for _, k := range sortedKeys(opts.Record) {
		if out, serr := d.zfs(ctx, "set", "litevirt:"+k+"="+opts.Record[k], opts.DstRef); serr != nil {
			slog.Warn("zfs replicate: the received copy is kept, but its owner property was not written",
				"dataset", opts.DstRef, "property", "litevirt:"+k, "error", serr, "output", strings.TrimSpace(string(out)))
		}
	}
	// Roll the "prev" pointer for the next incremental. A silent failure here
	// would make the NEXT `-I` send diff against a stale base → incomplete /
	// corrupt replica with no signal, so surface any error.
	if rerr := d.rollPrevSnapshot(ctx, prev); rerr != nil {
		return fmt.Errorf("zfs replicate %s → %s: roll prev snapshot: %w", opts.SrcRef, opts.DstRef, rerr)
	}
	return nil
}

// rollPrevSnapshot advances the "@litevirt-replicate-prev" pointer to the
// current state so the next incremental diffs against it. Each step's error is
// checked; a missing prev on the first run (nothing to destroy) is tolerated,
// but any real failure aborts the roll rather than leaving a stale base.
func (d *zfsDriver) rollPrevSnapshot(ctx context.Context, prev string) error {
	prevNew := prev + "-new"
	if out, err := d.zfs(ctx, "snapshot", "--", prevNew); err != nil {
		return fmt.Errorf("snapshot %s: %w: %s", prevNew, err, out)
	}
	if out, err := d.zfs(ctx, "destroy", "--", prev); err != nil && !strings.Contains(string(out), "does not exist") {
		return fmt.Errorf("destroy %s: %w: %s", prev, err, out)
	}
	if out, err := d.zfs(ctx, "rename", "--", prevNew, prev); err != nil {
		return fmt.Errorf("rename %s -> %s: %w: %s", prevNew, prev, err, out)
	}
	return nil
}

func (d *zfsDriver) DeleteDisk(ctx context.Context, path string) error {
	zvol := strings.TrimPrefix(path, "/dev/zvol/")
	if zvol == path {
		return fmt.Errorf("zfs: cannot derive zvol name from %q", path)
	}
	if out, err := exec.CommandContext(ctx, "zfs", "destroy", "-r", "--", zvol).CombinedOutput(); err != nil {
		return fmt.Errorf("zfs destroy %s: %w: %s", zvol, err, out)
	}
	slog.Info("zvol destroyed", "zvol", zvol)
	return nil
}
