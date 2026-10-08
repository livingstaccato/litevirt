package storage

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
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

// The destination is a new subvolume directly under this pool's root, never
// an existing name, a path elsewhere, a hidden name or one read as an option.
func TestBtrfsReplicate_RefusesADestinationOutsideThePoolOrExisting(t *testing.T) {
	root, srcRoot := t.TempDir(), t.TempDir()
	src := filepath.Join(srcRoot, "vm1-root")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatal(err)
	}
	existing := filepath.Join(root, "taken")
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, dst := range map[string]string{
		"pool root":      root,
		"nested":         filepath.Join(root, "a", "b"),
		"another pool":   filepath.Join(srcRoot, "copy"),
		"hidden":         filepath.Join(root, ".litevirt-recv-x"),
		"option-like":    filepath.Join(root, "-copy"),
		"relative":       "copy",
		"existing":       existing,
		"escapes by ../": filepath.Join(root, "..", "copy"),
	} {
		t.Run(name, func(t *testing.T) {
			err := btrfsReplicateRefused(t, root, ReplicateOptions{SrcRef: src, DstRef: dst})
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
	err := btrfsReplicateRefused(t, root, ReplicateOptions{
		SrcRef: filepath.Join(srcRoot, "vm1-root"), DstRef: filepath.Join(root, "copy"), SSHTarget: "root@peer",
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	prev := btrfsPipe
	btrfsPipe = func(_ context.Context, _, _ string, _ []string, _ string, recv []string) ([]byte, error) {
		// A partial receive, then the client goes away.
		if err := os.Mkdir(filepath.Join(recv[len(recv)-1], "copy"), 0o755); err != nil {
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
	if err := d.Replicate(ctx, ReplicateOptions{SrcRef: src, DstRef: filepath.Join(root, "copy")}); err == nil {
		t.Fatal("a cancelled copy reported success")
	}
	if e, _ := os.ReadDir(root); len(e) != 0 {
		t.Errorf("target pool holds %d entries after a cancelled copy, want none", len(e))
	}
	if e, _ := os.ReadDir(srcRoot); len(e) != 1 {
		t.Errorf("source pool holds %d entries after a cancelled copy, want only the disk's subvolume", len(e))
	}
}
