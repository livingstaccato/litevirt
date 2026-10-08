package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// btrfsReplicateRefused runs a btrfs Replicate that must be refused before
// anything runs: no btrfs command, no pipe, nothing staged.
func btrfsReplicateRefused(t *testing.T, root string, opts ReplicateOptions) error {
	t.Helper()
	prev := btrfsPipe
	piped := false
	btrfsPipe = func(context.Context, string, string, []string, string, []string) ([]byte, error) {
		piped = true
		return nil, nil
	}
	t.Cleanup(func() { btrfsPipe = prev })
	var ran [][]string
	d := &btrfsDriver{subvolRoot: root, run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		ran = append(ran, args)
		return nil, nil
	}}
	err := d.Replicate(context.Background(), opts)
	if len(ran) > 0 || piped {
		t.Errorf("btrfs ran %q (piped %v) for a refused copy", ran, piped)
	}
	return err
}

// The copy is a new file directly under this pool's root, never an existing
// name, a path elsewhere or a hidden (staging) name.
func TestBtrfsReplicate_RefusesADestinationOutsideThePoolOrExisting(t *testing.T) {
	root, srcRoot := t.TempDir(), t.TempDir()
	src := filepath.Join(srcRoot, "vm1-root")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "vm1-root.qcow2"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(root, "taken.qcow2")
	if err := os.WriteFile(existing, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for name, dst := range map[string]string{
		"pool root":      root,
		"nested":         filepath.Join(root, "a", "b"),
		"another pool":   filepath.Join(srcRoot, "copy"),
		"hidden":         filepath.Join(root, ".litevirt-place-x"),
		"relative":       "copy",
		"existing":       existing,
		"escapes by ../": filepath.Join(root, "..", "copy"),
	} {
		t.Run(name, func(t *testing.T) {
			err := btrfsReplicateRefused(t, root, ReplicateOptions{SrcRef: filepath.Join(src, "vm1-root.qcow2"), SrcRoot: srcRoot, DstRef: dst})
			if err == nil {
				t.Fatalf("copy to %q was not refused", dst)
			}
			if name == "existing" && !errors.Is(err, ErrDestinationExists) {
				t.Errorf("copy onto an existing name: %v, want ErrDestinationExists", err)
			}
		})
	}
	if e, _ := os.ReadDir(srcRoot); len(e) != 1 {
		t.Errorf("source pool holds %d entries after refused copies, want only the disk's subvolume", len(e))
	}
}

// The copy is placed by a local no-replace rename, so a cross-host receive is
// refused rather than run without that guarantee.
func TestBtrfsReplicate_RefusesACrossHostCopy(t *testing.T) {
	root, srcRoot := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(srcRoot, "vm1-root"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(srcRoot, "vm1-root", "vm1-root.qcow2"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := btrfsReplicateRefused(t, root, ReplicateOptions{
		SrcRef: filepath.Join(srcRoot, "vm1-root", "vm1-root.qcow2"), SrcRoot: srcRoot, DstRef: filepath.Join(root, "copy.qcow2"), SSHTarget: "root@peer",
	})
	if err == nil {
		t.Fatal("a cross-host btrfs copy was not refused")
	}
}

// A copy whose client goes away mid-receive still removes what it staged: the
// cleanup does not run on the cancelled context (a btrfs command run on one
// is killed before it starts).
func TestBtrfsReplicate_CancelledCopyStillRemovesItsStaging(t *testing.T) {
	root, srcRoot := t.TempDir(), t.TempDir()
	src := filepath.Join(srcRoot, "vm1-root")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "vm1-root.qcow2"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prev := btrfsPipe
	piped := false
	btrfsPipe = func(_ context.Context, _, _ string, _ []string, _ string, recv []string) ([]byte, error) {
		piped = true
		// A partial receive, then the client goes away.
		if err := os.Mkdir(filepath.Join(recv[len(recv)-1], btrfsSnapName), 0o755); err != nil {
			t.Error(err)
		}
		cancel()
		return nil, context.Canceled
	}
	t.Cleanup(func() { btrfsPipe = prev })
	d := &btrfsDriver{subvolRoot: root, run: func(ctx context.Context, _ string, args ...string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		switch {
		case args[0] == "subvolume" && args[1] == "snapshot":
			return nil, os.Mkdir(args[len(args)-1], 0o755)
		case args[0] == "subvolume" && args[1] == "delete":
			return nil, os.RemoveAll(args[len(args)-1])
		}
		return nil, nil
	}}
	if err := d.Replicate(ctx, ReplicateOptions{SrcRef: filepath.Join(src, "vm1-root.qcow2"), SrcRoot: srcRoot, DstRef: filepath.Join(root, "copy.qcow2")}); err == nil {
		t.Fatal("a cancelled copy reported success")
	}
	if !piped {
		t.Fatal("the copy was refused before it was sent; the cancellation was never reached")
	}
	if e, _ := os.ReadDir(root); len(e) != 0 {
		t.Errorf("target pool holds %d entries after a cancelled copy, want none", len(e))
	}
	if e, _ := os.ReadDir(srcRoot); len(e) != 1 {
		t.Errorf("source pool holds %d entries after a cancelled copy, want only the disk's subvolume", len(e))
	}
}

// Only a disk alone in its own subvolume directly under its pool is sent: a
// disk file directly in the pool's directory, one in a nested directory, or a
// subvolume holding other files is refused before anything runs.
func TestBtrfsReplicate_RefusesADiskOutsideItsOwnSubvolume(t *testing.T) {
	for name, layout := range map[string]func(srcRoot string) string{
		"in the pool directory": func(srcRoot string) string { return filepath.Join(srcRoot, "vm1-root.qcow2") },
		"nested":                func(srcRoot string) string { return filepath.Join(srcRoot, "a", "vm1-root", "vm1-root.qcow2") },
		"beside another file": func(srcRoot string) string {
			_ = os.MkdirAll(filepath.Join(srcRoot, "vm1-root"), 0o755)
			_ = os.WriteFile(filepath.Join(srcRoot, "vm1-root", "other.qcow2"), nil, 0o600)
			return filepath.Join(srcRoot, "vm1-root", "vm1-root.qcow2")
		},
	} {
		t.Run(name, func(t *testing.T) {
			root, srcRoot := t.TempDir(), t.TempDir()
			disk := layout(srcRoot)
			if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(disk, []byte("disk"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := btrfsReplicateRefused(t, root, ReplicateOptions{SrcRef: disk, SrcRoot: srcRoot, DstRef: filepath.Join(root, "copy.qcow2")}); err == nil {
				t.Fatal("sent")
			}
		})
	}
}

// The sweep removes only stale staging it can tell is its own — a directory
// of its name carrying its marker, not in flight, of its shape, nothing in it
// in use — and never a file, whatever its name.
func TestBtrfsSweepStaging_RemovesOnlyStaleUnusedMarkedStaging(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	old, fresh := now.Add(-25*time.Hour).Unix(), now.Add(-time.Hour).Unix()
	mk := func(name string, marked, withSnap bool, extra ...string) string {
		p := filepath.Join(dir, name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		if marked {
			if err := os.WriteFile(filepath.Join(p, btrfsStagingFile), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if withSnap {
			if err := os.Mkdir(filepath.Join(p, btrfsSnapName), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(p, btrfsSnapName, "d.qcow2"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		for _, e := range extra {
			if err := os.WriteFile(filepath.Join(p, e), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return p
	}
	name := func(kind string, at int64, id string) string { return fmt.Sprintf(".litevirt-%s-%d-%s", kind, at, id) }
	staleRecv := mk(name("recv", old, "aaaaaaaaaaaa"), true, true, btrfsPlaceName)
	staleSend := mk(name("send", old, "a1a1a1a1a1a1"), true, true)
	staleEmpty := mk(name("send", old, "bbbbbbbbbbbb"), true, false)
	unmarked := mk(name("recv", old, "b1b1b1b1b1b1"), false, true)
	freshOne := mk(name("recv", fresh, "cccccccccccc"), true, true)
	inflight := mk(name("recv", old, "c1c1c1c1c1c1"), true, true)
	used := mk(name("recv", old, "dddddddddddd"), true, true)
	usedPlace := mk(name("recv", old, "d1d1d1d1d1d1"), true, true, btrfsPlaceName)
	odd := mk(name("recv", old, "eeeeeeeeeeee"), true, true, "notours")
	sendWithPlace := mk(name("send", old, "e1e1e1e1e1e1"), true, true, btrfsPlaceName)
	shortID := mk(fmt.Sprintf(".litevirt-recv-%d-abc", old), true, true)
	var files []string
	for _, n := range []string{fmt.Sprintf(".litevirt-place-%d-ffffffffffff", old), name("recv", old, "f1f1f1f1f1f1")} {
		f := filepath.Join(dir, n)
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	btrfsInflight.Store(filepath.Clean(inflight), true)
	t.Cleanup(func() { btrfsInflight.Delete(filepath.Clean(inflight)) })
	d := &btrfsDriver{subvolRoot: dir, run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "subvolume" && args[1] == "delete" {
			return nil, os.RemoveAll(args[len(args)-1])
		}
		return nil, nil
	}}
	inUse := func(p string) bool {
		return p == filepath.Join(used, btrfsSnapName, "d.qcow2") || p == filepath.Join(usedPlace, btrfsPlaceName)
	}
	d.sweepStaging(context.Background(), now, inUse, dir)
	for _, p := range []string{staleRecv, staleSend, staleEmpty} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("%s was not swept", filepath.Base(p))
		}
	}
	keep := []string{unmarked, filepath.Join(unmarked, btrfsSnapName), freshOne, inflight, used, usedPlace,
		odd, filepath.Join(odd, btrfsSnapName), sendWithPlace, shortID}
	for _, p := range append(keep, files...) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was swept: %v", p, err)
		}
	}
}

// A copy's staging carries the marker and is in flight while the copy runs,
// and neither outlives it.
func TestBtrfsReplicate_StagingIsMarkedAndInFlightWhileTheCopyRuns(t *testing.T) {
	root, srcRoot := t.TempDir(), t.TempDir()
	src := filepath.Join(srcRoot, "vm1-root")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "vm1-root.qcow2"), []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := btrfsPipe
	var stage string
	btrfsPipe = func(_ context.Context, _, _ string, _ []string, _ string, recv []string) ([]byte, error) {
		stage = recv[len(recv)-1]
		if _, err := os.Stat(filepath.Join(stage, btrfsStagingFile)); err != nil {
			t.Errorf("the receive directory carries no marker: %v", err)
		}
		if _, ok := btrfsInflight.Load(filepath.Clean(stage)); !ok {
			t.Error("the receive directory is not in flight while the copy runs")
		}
		return nil, errors.New("receive failed")
	}
	t.Cleanup(func() { btrfsPipe = prev })
	d := &btrfsDriver{subvolRoot: root, run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "subvolume" && args[1] == "snapshot" {
			return nil, os.Mkdir(args[len(args)-1], 0o755)
		}
		if args[0] == "subvolume" && args[1] == "delete" {
			return nil, os.RemoveAll(args[len(args)-1])
		}
		return nil, nil
	}}
	_ = d.Replicate(context.Background(), ReplicateOptions{SrcRef: filepath.Join(src, "vm1-root.qcow2"), SrcRoot: srcRoot, DstRef: filepath.Join(root, "copy.qcow2")})
	if stage == "" {
		t.Fatal("the receive was never reached")
	}
	if _, ok := btrfsInflight.Load(filepath.Clean(stage)); ok {
		t.Error("the receive directory is still in flight after the copy ended")
	}
	if _, err := os.Lstat(stage); err == nil {
		t.Error("the receive directory outlived the copy")
	}
}
