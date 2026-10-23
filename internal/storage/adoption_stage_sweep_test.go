package storage

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
)

// (re-review rr3 1) The startup sweep of leftover adoption staging mounts:
// only directories directly in <data_dir>/mounts whose names start with
// .adopt- are touched; a mounted one is unmounted without canonicalizing the
// path, lazily when the plain unmount fails (busy); then the empty directory
// is removed. A symlink of that name, a pool's own mount point, and anything
// deeper are left alone.
//
// Mutations: follow a symlink (stat instead of the entry type) — the link's
// target is unmounted, red; skip the lazy retry — the busy stage stays, red;
// drop the prefix check — the pool's mount point is unmounted, red.
func TestSweepAdoptionStages_OnlyLeftoverStages(t *testing.T) {
	data := t.TempDir()
	mounts := filepath.Join(data, "mounts")
	stage := filepath.Join(mounts, ".adopt-p")
	busy := filepath.Join(mounts, ".adopt-busy")
	idle := filepath.Join(mounts, ".adopt-idle")
	pool := filepath.Join(mounts, "nas_vols")
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	deep := filepath.Join(pool, ".adopt-deep")
	for _, d := range []string{stage, busy, idle, pool, elsewhere, deep} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(elsewhere, filepath.Join(mounts, ".adopt-link")); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	mounted := map[string]bool{stage: true, busy: true, pool: true, elsewhere: true, deep: true}
	var calls []string
	t.Cleanup(OverrideMountInfoForTest(func() ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		var b strings.Builder
		b.WriteString("22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n")
		i := 0
		for d, on := range mounted {
			if on {
				fmt.Fprintf(&b, "%d 22 0:%d / %s rw - nfs4 srv:/x rw\n", 100+i, 50+i, d)
				i++
			}
		}
		return []byte(b.String()), nil
	}))
	t.Cleanup(OverrideNFSMountCommandForTest(func(_ context.Context, name string, args ...string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, name+" "+strings.Join(args, " "))
		if name != "umount" || !slices.Contains(args, "--no-canonicalize") {
			return nil, errors.New("unexpected")
		}
		dir := args[len(args)-1]
		if dir == busy && !slices.Contains(args, "-l") {
			return []byte("target is busy"), errors.New("exit status 32")
		}
		mounted[dir] = false
		return nil, nil
	}))
	if errs := SweepAdoptionStages(context.Background(), data); len(errs) != 0 {
		t.Fatalf("sweep errors: %v", errs)
	}
	t.Logf("commands: %v", calls)
	for _, d := range []string{stage, busy, idle} {
		if _, err := os.Lstat(d); !os.IsNotExist(err) {
			t.Errorf("leftover stage %s not removed (%v)", d, err)
		}
	}
	for _, d := range []string{pool, elsewhere, deep, filepath.Join(mounts, ".adopt-link")} {
		if _, err := os.Lstat(d); err != nil {
			t.Errorf("%s was removed: %v", d, err)
		}
	}
	for _, d := range []string{pool, elsewhere, deep} {
		if !mounted[d] {
			t.Errorf("%s was unmounted", d)
		}
	}
	if !slices.Contains(calls, "umount -l --no-canonicalize -- "+busy) {
		t.Errorf("the busy stage was not unmounted lazily: %v", calls)
	}
}
