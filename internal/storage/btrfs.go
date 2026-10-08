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
	"regexp"
	"strconv"
	"strings"
	"syscall"
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

// btrfsStageMarker begins the name of everything a replicate stages: the
// private directories its snapshots are taken and received in
// (".litevirt-send-<unix>-<id>", ".litevirt-recv-<unix>-<id>") and the file
// the copy is written to before it is placed (".litevirt-place-<unix>-<id>").
// A disk subvolume is "<vm>-<disk>" and a copy a name the caller chose, never
// with a leading ".".
const btrfsStageMarker = ".litevirt-"

// btrfsStagingName matches a staging name this driver mints.
var btrfsStagingName = regexp.MustCompile(`^\.litevirt-(send|recv|place)-([0-9]+)-[0-9a-f]{12}$`)

// btrfsStagingMaxAge is how old staging is, by the time in its name, before a
// later copy removes it as the leftover of a daemon that died mid-copy. No
// copy runs that long.
const btrfsStagingMaxAge = 24 * time.Hour

// btrfsSnapName is the name of the snapshot in a send or receive directory.
const btrfsSnapName = "snap"

// Replicate copies the disk file SrcRef — alone in its own subvolume directly
// under its pool's root SrcRoot (checkDiskSubvolume) — to the
// NEW file DstRef, directly under this pool's root, with `btrfs send | btrfs
// receive`. DstRef must not exist: it is refused before anything is
// snapshotted or sent, and the copy is placed there with a rename that refuses
// an existing name, so a file created in between is never replaced.
//
//  1. SrcRef's subvolume is snapshotted read-only (send needs one) into a
//     private directory beside it.
//  2. That is received into a private directory in this pool.
//  3. opts.Verify, when set, judges the received disk file; a refusal places
//     nothing.
//  4. The received file is cloned (a reflink: no data is copied; a plain
//     copy where the filesystem cannot) into a new file in this pool's
//     directory, which is renamed to DstRef. The copy is an ordinary file in
//     the pool — where every other copy is — not a subvolume.
//
// Every run's staging names are new, and everything staged is removed when
// the run ends, whether it succeeded, failed or was cancelled, by what exists
// (never by an error's text). A copy is always a full send: no "previous"
// snapshot is kept between runs, so none can be missing or stale. Staging a
// daemon that died mid-copy left is swept by a later copy (sweepStaging) when
// opts.InUse is set. opts.Record is not written here: the caller records the
// copy as for a file copy. SSHTarget is refused: the copy is placed by a
// local rename.
func (d *btrfsDriver) Replicate(ctx context.Context, opts ReplicateOptions) error {
	if opts.SrcRef == "" || opts.DstRef == "" {
		return fmt.Errorf("btrfs replicate: src and dst refs required")
	}
	if opts.SSHTarget != "" {
		return fmt.Errorf("btrfs replicate: a cross-host copy is not supported (the copy is placed by a local rename)")
	}
	root := filepath.Clean(d.subvolRoot)
	srcFile, dst := filepath.Clean(opts.SrcRef), filepath.Clean(opts.DstRef)
	sub := filepath.Dir(srcFile)
	leaf := filepath.Base(dst)
	if !filepath.IsAbs(srcFile) || !filepath.IsAbs(dst) || root == "." || filepath.Dir(dst) != root || strings.HasPrefix(leaf, ".") {
		return fmt.Errorf("btrfs replicate %s → %s: the copy must be a new file directly under the pool %s", srcFile, dst, root)
	}
	if _, lerr := os.Lstat(dst); lerr == nil {
		return fmt.Errorf("btrfs replicate → %s: %w", dst, ErrDestinationExists)
	} else if !os.IsNotExist(lerr) {
		return fmt.Errorf("btrfs replicate → %s: %w", dst, lerr)
	}
	if err := d.checkDiskSubvolume(ctx, opts.SrcRoot, srcFile); err != nil {
		return fmt.Errorf("btrfs replicate %s: %w", srcFile, err)
	}
	if opts.InUse != nil {
		d.sweepStaging(ctx, time.Now(), opts.InUse, filepath.Dir(sub), root)
	}

	tag := fmt.Sprintf("%d-%s", time.Now().Unix(), randid.New()[:12])
	srcStage := filepath.Join(filepath.Dir(sub), btrfsStageMarker+"send-"+tag)
	if merr := os.Mkdir(srcStage, 0o700); merr != nil {
		return fmt.Errorf("btrfs replicate: stage the snapshot: %w", merr)
	}
	snap := filepath.Join(srcStage, btrfsSnapName)
	defer d.removeStaged(ctx, srcStage, snap)
	if out, serr := d.btrfs(ctx, "subvolume", "snapshot", "-r", "--", sub, snap); serr != nil {
		return fmt.Errorf("btrfs snapshot %s: %w: %s", snap, serr, out)
	}

	dstStage := filepath.Join(root, btrfsStageMarker+"recv-"+tag)
	if merr := os.Mkdir(dstStage, 0o700); merr != nil {
		return fmt.Errorf("btrfs replicate: stage the receive: %w", merr)
	}
	received := filepath.Join(dstStage, btrfsSnapName)
	defer d.removeStaged(ctx, dstStage, received)
	if _, perr := btrfsPipe(ctx, "", "btrfs", []string{"send", "--", snap}, "btrfs", []string{"receive", "--", dstStage}); perr != nil {
		return fmt.Errorf("btrfs replicate %s → %s: %w", srcFile, dst, perr)
	}
	file := filepath.Join(received, filepath.Base(srcFile))
	if opts.Verify != nil {
		if verr := opts.Verify(file); verr != nil {
			return fmt.Errorf("btrfs replicate %s: the received copy is refused: %w", srcFile, verr)
		}
	}
	return placeClone(file, filepath.Join(root, btrfsStageMarker+"place-"+tag), dst)
}

// checkDiskSubvolume refuses a disk that is not alone in its own subvolume
// directly under its pool's root srcRoot: a send copies the whole subvolume,
// and its snapshot is staged beside it, in that pool.
func (d *btrfsDriver) checkDiskSubvolume(ctx context.Context, srcRoot, srcFile string) error {
	sub := filepath.Dir(srcFile)
	name := filepath.Base(sub)
	if srcRoot == "" || !filepath.IsAbs(srcRoot) || filepath.Dir(sub) != filepath.Clean(srcRoot) ||
		strings.HasPrefix(name, ".") || strings.HasPrefix(name, "-") {
		return fmt.Errorf("the disk is not in a subvolume of its own directly under its pool %q", srcRoot)
	}
	if fi, err := os.Lstat(sub); err != nil || !fi.IsDir() {
		return fmt.Errorf("the disk's subvolume %s is not a directory", sub)
	}
	ents, err := os.ReadDir(sub)
	if err != nil || len(ents) != 1 || ents[0].Name() != filepath.Base(srcFile) || !ents[0].Type().IsRegular() {
		return fmt.Errorf("the disk's subvolume %s holds more than the disk", sub)
	}
	if out, err := d.btrfs(ctx, "subvolume", "show", "--", sub); err != nil {
		return fmt.Errorf("%s is not a btrfs subvolume: %w: %s", sub, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// placeClone writes a clone of src to the new file tmp, then renames it to dst
// with a rename that refuses an existing name. tmp is removed on any failure;
// it was created exclusively, so it is this call's.
func placeClone(src, tmp, dst string) (err error) {
	in, err := os.OpenFile(src, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("btrfs replicate: open the received copy: %w", err)
	}
	defer in.Close()
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("btrfs replicate: the received %s is not a regular file", src)
	}
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, fi.Mode().Perm())
	if err != nil {
		return fmt.Errorf("btrfs replicate: create the copy: %w", err)
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if err = cloneFile(out, in); err != nil {
		out.Close()
		return fmt.Errorf("btrfs replicate: write the copy: %w", err)
	}
	if err = out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	if err = renameNoReplace(tmp, dst); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("btrfs replicate → %s: %w", dst, ErrDestinationExists)
		}
		return fmt.Errorf("btrfs replicate → %s: place the copy: %w", dst, err)
	}
	return nil
}

// btrfsPipe runs the send | receive pipeline; tests may replace it.
var btrfsPipe = pipeCmds

// removeStaged deletes the subvolumes among subs that exist, then the
// private directory dir. Only paths inside dir — this run's — are touched; a
// failure is logged (the names are this run's alone, so a leftover never
// gets in a later run's way, and a later copy sweeps it). It runs even when
// the copy's context was cancelled (a client that went away), within a bound
// of its own.
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

// sweepStaging removes, in each of dirs, the staging a copy that never
// finished left (a daemon that died mid-copy): only names this driver mints
// (btrfsStagingName), older than btrfsStagingMaxAge by the time in the name,
// in the shape it makes them — a send or receive directory holding nothing
// but its snapshot, or a place file — and only when inUse claims none of the
// files in it. Anything else is left; a failure is ignored.
func (d *btrfsDriver) sweepStaging(ctx context.Context, now time.Time, inUse func(string) bool, dirs ...string) {
	seen := map[string]bool{}
	for _, dir := range dirs {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		ents, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			m := btrfsStagingName.FindStringSubmatch(e.Name())
			if m == nil {
				continue
			}
			secs, err := strconv.ParseInt(m[2], 10, 64)
			if err != nil || now.Sub(time.Unix(secs, 0)) < btrfsStagingMaxAge {
				continue
			}
			p := filepath.Join(dir, e.Name())
			if m[1] == "place" {
				if e.Type().IsRegular() && !inUse(p) {
					if os.Remove(p) == nil {
						slog.Info("btrfs: removed a copy file a crashed replicate left", "file", p)
					}
				}
				continue
			}
			if !e.IsDir() || !stagingDirSweepable(p, inUse) {
				continue
			}
			d.removeStaged(ctx, p, filepath.Join(p, btrfsSnapName))
			if _, err := os.Lstat(p); os.IsNotExist(err) {
				slog.Info("btrfs: removed staging a crashed replicate left", "dir", p)
			}
		}
	}
}

// stagingDirSweepable reports whether the send or receive directory p holds
// nothing but its snapshot, and nothing in that snapshot is in use.
func stagingDirSweepable(p string, inUse func(string) bool) bool {
	ents, err := os.ReadDir(p)
	if err != nil {
		return false
	}
	for _, e := range ents {
		if e.Name() != btrfsSnapName || !e.IsDir() {
			return false
		}
	}
	files, err := os.ReadDir(filepath.Join(p, btrfsSnapName))
	if err != nil && !os.IsNotExist(err) {
		return false
	}
	for _, f := range files {
		if inUse(filepath.Join(p, btrfsSnapName, f.Name())) {
			return false
		}
	}
	return true
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
