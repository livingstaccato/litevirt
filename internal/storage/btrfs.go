package storage

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/randid"
)

// btrfsDriver creates a subvolume per VM disk under a parent path on a
// BTRFS filesystem, then stores a qcow2 file inside the subvolume. The
// subvolume gives us atomic snapshots via `btrfs subvolume snapshot` and
// efficient send/receive replication.
//
// Pool config:
//
//	driver:  btrfs
//	source:  /mnt/btrfs/litevirt        # absolute path; must be on btrfs
type btrfsDriver struct {
	subvolRoot string
	opts       map[string]string
	run        cmdRunner // nil → realCmd; overridable in tests
}

func (d *btrfsDriver) String() string { return "btrfs" }

func (d *btrfsDriver) Prepare(ctx context.Context) error {
	if d.subvolRoot == "" {
		return fmt.Errorf("btrfs: subvolume root (Source) required")
	}
	if err := os.MkdirAll(d.subvolRoot, 0755); err != nil {
		return fmt.Errorf("btrfs: create subvol root: %w", err)
	}
	// `btrfs filesystem show <path>` confirms the path lives on btrfs.
	out, err := exec.CommandContext(ctx, "btrfs", "filesystem", "show", "--", d.subvolRoot).CombinedOutput()
	if err != nil {
		return fmt.Errorf("btrfs filesystem show %s: %w: %s", d.subvolRoot, err, out)
	}
	return nil
}

func (d *btrfsDriver) CreateDisk(ctx context.Context, opts DiskOptions) (string, error) {
	subvol := filepath.Join(d.subvolRoot, fmt.Sprintf("%s-%s", opts.VMName, opts.DiskName))
	if out, err := exec.CommandContext(ctx, "btrfs", "subvolume", "create", "--", subvol).CombinedOutput(); err != nil {
		return "", fmt.Errorf("btrfs subvolume create %s: %w: %s", subvol, err, out)
	}
	// Reuse the local qcow2 path inside the subvolume. CoW conflicts
	// with qcow2 random writes on some workloads — operators who need
	// raw can override Format=raw.
	inner := &localDriver{dataDir: subvol}
	if err := inner.Prepare(ctx); err != nil {
		return "", err
	}
	return inner.CreateDisk(ctx, opts)
}

// btrfs runs a btrfs subcommand through the driver's runner (real exec by
// default).
func (d *btrfsDriver) btrfs(ctx context.Context, args ...string) ([]byte, error) {
	run := d.run
	if run == nil {
		run = realCmd
	}
	return run(ctx, "btrfs", args...)
}

// IsBtrfsSubvolume reports whether path is the root of a btrfs subvolume
// (`btrfs subvolume show` succeeds on it).
func IsBtrfsSubvolume(ctx context.Context, path string) bool {
	_, err := realCmd(ctx, "btrfs", "subvolume", "show", "--", path)
	return err == nil
}

// btrfsStageMarker begins the name of the private directories a replicate
// stages its snapshots in. A disk subvolume is named "<vm>-<disk>", never
// with a leading ".".
const btrfsStageMarker = ".litevirt-"

// Replicate copies the subvolume SrcRef into a NEW subvolume DstRef with
// `btrfs send | btrfs receive`. DstRef is "<this pool's root>/<leaf>" and must
// not exist: it is refused before anything is snapshotted or sent, and the
// copy is placed there with a rename that refuses an existing name, so a
// subvolume or directory created in between is never replaced.
//
//  1. SrcRef is snapshotted read-only (send needs one) into a private
//     directory beside it, the snapshot named after DstRef's leaf (receive
//     names what it creates after what was sent).
//  2. It is received into a private directory in this pool, where nothing
//     but this run's subvolume can be.
//  3. A received subvolume is read-only; a writable snapshot of it is what is
//     placed at DstRef, so the copy is a disk that can be promoted.
//
// Every run's staging names are new, and everything staged — the send
// snapshot, the received subvolume, a writable snapshot not placed, the
// private directories — is removed when the run ends, by what exists (never
// by an error's text). A copy is always a full send: no "previous" snapshot
// is kept between runs, so none can be missing or stale.
//
// opts.Record is not written here: the caller records the copy's disk file
// in its pool records, as for a file copy. SSHTarget is refused: the copy is
// placed by a local no-replace rename.
func (d *btrfsDriver) Replicate(ctx context.Context, opts ReplicateOptions) error {
	if opts.SrcRef == "" || opts.DstRef == "" {
		return fmt.Errorf("btrfs replicate: src and dst refs required")
	}
	if opts.SSHTarget != "" {
		return fmt.Errorf("btrfs replicate: a cross-host copy is not supported (the copy is placed by a local rename)")
	}
	root := filepath.Clean(d.subvolRoot)
	src, dst := filepath.Clean(opts.SrcRef), filepath.Clean(opts.DstRef)
	leaf := filepath.Base(dst)
	if !filepath.IsAbs(src) || !filepath.IsAbs(dst) || root == "." || filepath.Dir(dst) != root ||
		strings.HasPrefix(leaf, ".") || strings.HasPrefix(leaf, "-") || strings.HasPrefix(filepath.Base(src), "-") {
		return fmt.Errorf("btrfs replicate %s → %s: the destination must be a new subvolume directly under the pool %s", src, dst, root)
	}
	if _, lerr := os.Lstat(dst); lerr == nil {
		return fmt.Errorf("btrfs replicate → %s: %w", dst, ErrDestinationExists)
	} else if !os.IsNotExist(lerr) {
		return fmt.Errorf("btrfs replicate → %s: %w", dst, lerr)
	}

	tag := fmt.Sprintf("%d-%s", time.Now().Unix(), randid.New()[:12])
	srcStage := filepath.Join(filepath.Dir(src), btrfsStageMarker+"send-"+tag)
	if merr := os.Mkdir(srcStage, 0o700); merr != nil {
		return fmt.Errorf("btrfs replicate: stage the snapshot: %w", merr)
	}
	snap := filepath.Join(srcStage, leaf)
	defer d.removeStaged(ctx, srcStage, snap)
	if out, serr := d.btrfs(ctx, "subvolume", "snapshot", "-r", "--", src, snap); serr != nil {
		return fmt.Errorf("btrfs snapshot %s: %w: %s", snap, serr, out)
	}

	dstStage := filepath.Join(root, btrfsStageMarker+"recv-"+tag)
	if merr := os.Mkdir(dstStage, 0o700); merr != nil {
		return fmt.Errorf("btrfs replicate: stage the receive: %w", merr)
	}
	received, writable := filepath.Join(dstStage, leaf), filepath.Join(dstStage, "rw")
	defer d.removeStaged(ctx, dstStage, received, writable)

	if _, perr := btrfsPipe(ctx, "", "btrfs", []string{"send", "--", snap}, "btrfs", []string{"receive", "--", dstStage}); perr != nil {
		return fmt.Errorf("btrfs replicate %s → %s: %w", src, dst, perr)
	}
	if out, serr := d.btrfs(ctx, "subvolume", "snapshot", "--", received, writable); serr != nil {
		return fmt.Errorf("btrfs snapshot %s: %w: %s", writable, serr, out)
	}
	if rerr := renameNoReplace(writable, dst); rerr != nil {
		if errors.Is(rerr, fs.ErrExist) {
			return fmt.Errorf("btrfs replicate → %s: %w", dst, ErrDestinationExists)
		}
		return fmt.Errorf("btrfs replicate → %s: place the copy: %w", dst, rerr)
	}
	return nil
}

// btrfsPipe runs the send | receive pipeline; tests may replace it.
var btrfsPipe = pipeCmds

// removeStaged deletes the subvolumes among subs that exist, then the
// private directory dir. Only paths inside dir — this run's — are touched; a
// failure is logged (the names are this run's alone, so a leftover never
// gets in a later run's way). It runs even when the copy's context was
// cancelled (a client that went away), within a bound of its own.
func (d *btrfsDriver) removeStaged(ctx context.Context, dir string, subs ...string) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Minute)
	defer cancel()
	for _, p := range subs {
		if filepath.Dir(p) != dir {
			continue
		}
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		if out, err := d.btrfs(ctx, "subvolume", "delete", "--", p); err != nil {
			slog.Warn("btrfs replicate: a staged subvolume was not removed", "subvol", p, "error", err, "output", strings.TrimSpace(string(out)))
		}
	}
	if err := os.Remove(dir); err != nil && !os.IsNotExist(err) {
		slog.Warn("btrfs replicate: a staging directory was not removed", "dir", dir, "error", err)
	}
}

func (d *btrfsDriver) DeleteDisk(ctx context.Context, path string) error {
	// Always remove the qcow2 file. Whether to also reap a wrapping
	// subvolume depends on how the file was created: only CreateDisk
	// puts each disk in its own subvolume; storage-motion / replication
	// drop files directly under subvolRoot.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove btrfs qcow2 %s: %w", path, err)
	}
	subvol := filepath.Dir(path)
	// Refuse to delete if the parent is the pool root, the filesystem
	// root, or anything outside subvolRoot — otherwise a misconfigured
	// path could nuke the pool. A bug here in earlier versions would
	// have called `btrfs subvolume delete <subvolRoot>`.
	cleanRoot := filepath.Clean(d.subvolRoot)
	cleanParent := filepath.Clean(subvol)
	if cleanParent == cleanRoot || cleanParent == "/" || cleanParent == "." {
		return nil
	}
	rel, err := filepath.Rel(cleanRoot, cleanParent)
	if err != nil || strings.HasPrefix(rel, "..") {
		return nil
	}
	if out, err := exec.CommandContext(ctx, "btrfs", "subvolume", "delete", "--", cleanParent).CombinedOutput(); err != nil {
		// Non-fatal: caller may have created the file directly without
		// a wrapping subvolume.
		slog.Warn("btrfs subvolume delete failed", "subvol", cleanParent, "error", err, "output", string(out))
		return nil
	}
	slog.Info("btrfs subvolume deleted", "subvol", cleanParent)
	return nil
}
