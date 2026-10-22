package storage

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// cachedMountTable serves table through the mount table cache, as the host's
// /proc/self/mountinfo is served, with changed standing for the kernel's
// change mark. It counts the reads.
func cachedMountTable(t *testing.T, table *atomic.Value, changed *atomic.Bool) *atomic.Int64 {
	t.Helper()
	var reads atomic.Int64
	t.Cleanup(procMountInfo.set(func() ([]byte, error) {
		reads.Add(1)
		return []byte(table.Load().(string)), nil
	}))
	t.Cleanup(mountTableChanged.set(func() bool { return changed.Swap(false) }))
	resetMountCache()
	t.Cleanup(resetMountCache)
	return &reads
}

// Opening pool files reads the mount table once while it does not change:
// every open after the first, and the pool checks beside them, are judged
// against the table read then. Before, each open read and parsed
// /proc/self/mountinfo again.
//
// Mutation "no cache" (mounts reads procMountInfo on every call): 7 reads, red.
func TestMountCache_PoolOpensReadTheTableOnceWhileItDoesNotChange(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "disk.qcow2")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var table atomic.Value
	table.Store("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
	var changed atomic.Bool
	reads := cachedMountTable(t, &table, &changed)

	for range 5 {
		f, err := OpenPoolFile(file, os.O_RDONLY, 0)
		if err != nil {
			t.Fatalf("OpenPoolFile: %v", err)
		}
		f.Close()
	}
	if err := CheckPoolPathNoSymlinks(file); err != nil {
		t.Fatalf("CheckPoolPathNoSymlinks: %v", err)
	}
	if _, err := ReadMountTable(); err != nil {
		t.Fatalf("ReadMountTable: %v", err)
	}
	if got := reads.Load(); got != 1 {
		t.Errorf("seven mount-table uses with no change read it %d times, want 1", got)
	}

	changed.Store(true)
	if _, err := ReadMountTable(); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 2 {
		t.Errorf("a use after the table changed read it %d times in all, want 2 (one more)", got)
	}
}

// The cache never accepts a remounted path: an export remounted without
// nosymfollow after the table was read is judged by the new table at the next
// open, so a symlink on it is refused as before the cache.
//
// Mutation "cache ignores the change mark" (mounts serves the cached table
// whatever mountTableChanged says): the symlink is followed, red.
func TestMountCache_AnExportRemountedWithoutNosymfollowIsJudgedAfresh(t *testing.T) {
	mnt := t.TempDir()
	if err := os.WriteFile(filepath.Join(mnt, "real"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(mnt, "link")
	if err := os.Symlink("real", link); err != nil {
		t.Fatal(err)
	}
	line := func(flags string) string {
		return fmt.Sprintf("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n40 1 0:60 / %s %s - nfs4 nas:/lv rw\n", mnt, flags)
	}
	var table atomic.Value
	table.Store(line(hardenedFlags))
	var changed atomic.Bool
	reads := cachedMountTable(t, &table, &changed)

	// Hardened: the kernel refuses symlinks, so litevirt opens as usual.
	f, err := OpenPoolFile(link, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open through the hardened export: %v", err)
	}
	f.Close()

	// Remounted without nosymfollow: the kernel marks the table changed.
	table.Store(line("rw,nosuid,nodev,noexec,relatime"))
	changed.Store(true)
	if f, err := OpenPoolFile(link, os.O_RDONLY, 0); err == nil {
		f.Close()
		t.Fatal("a symlink on an export remounted without nosymfollow was followed: the cached table was used")
	}
	if got := reads.Load(); got != 2 {
		t.Errorf("read the table %d times, want 2 (once, and once after the change)", got)
	}
}

// A missed change mark leaves the table stale for at most mountTableMaxAge:
// an export mounted after the read, with no mark, is seen once the table is
// that old, and not before (the cache still saves the reads in between).
//
// Mutation "no age bound" (cachedMounts ignores readAt): the mount is never
// seen, red.
func TestMountCache_AMissedMarkIsBoundedByTheTablesAge(t *testing.T) {
	var table atomic.Value
	table.Store("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n")
	var changed atomic.Bool // never set: the kernel's mark was missed
	reads := cachedMountTable(t, &table, &changed)
	now := time.Unix(1_000_000, 0)
	var clock atomic.Int64
	clock.Store(now.UnixNano())
	t.Cleanup(mountTableNow.set(func() time.Time { return time.Unix(0, clock.Load()) }))

	if _, err := ReadMountTable(); err != nil {
		t.Fatal(err)
	}
	table.Store("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n40 1 0:60 / /mnt/x rw - nfs4 nas:/lv rw\n")
	clock.Store(now.Add(mountTableMaxAge - time.Second).UnixNano())
	if _, err := ReadMountTable(); err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 1 {
		t.Errorf("a table younger than mountTableMaxAge was read again (%d reads, want 1)", got)
	}
	clock.Store(now.Add(mountTableMaxAge).UnixNano())
	all, err := ReadMountTable()
	if err != nil {
		t.Fatal(err)
	}
	if got := reads.Load(); got != 2 {
		t.Errorf("a table mountTableMaxAge old was not read again (%d reads, want 2)", got)
	}
	if len(all.all) != 2 {
		t.Errorf("after mountTableMaxAge the table holds %d mounts, want 2 (the export mounted with no mark)", len(all.all))
	}
}

// A table that cannot be read is not kept: the next use reads again.
func TestMountCache_AFailedReadIsNotCached(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	var reads atomic.Int64
	t.Cleanup(procMountInfo.set(func() ([]byte, error) {
		reads.Add(1)
		if fail.Load() {
			return nil, errors.New("EIO")
		}
		return []byte("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n"), nil
	}))
	t.Cleanup(mountTableChanged.set(func() bool { return false }))
	resetMountCache()
	t.Cleanup(resetMountCache)
	if _, err := ReadMountTable(); err == nil {
		t.Fatal("a failed read was not reported")
	}
	fail.Store(false)
	if _, err := ReadMountTable(); err != nil {
		t.Fatalf("after the failure: %v", err)
	}
	if got := reads.Load(); got != 2 {
		t.Errorf("reads = %d, want 2", got)
	}
}

// The kernel's change mark on the real /proc/self/mountinfo: a watch that
// was just opened says changed (nothing is cached against it yet), and then,
// with no mount made or changed in between, says unchanged. A host that
// mounts something during the test can make one poll say changed, so a few
// are allowed.
func TestProcMountWatch_SaysUnchangedWhenNothingChanged(t *testing.T) {
	w := &procMountWatch{}
	defer w.close()
	if !w.changed() {
		t.Fatal("a new watch said unchanged: nothing was read against it yet")
	}
	for range 5 {
		if !w.changed() {
			return
		}
	}
	t.Fatal("the watch never said unchanged: every use would read the table")
}
