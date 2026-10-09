//go:build linux

package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Native btrfs send/receive in ReplicateVolume, restored with the safety the
// zfs/ceph native path has: the copy is a NEW subvolume the daemon names in
// the target pool, never an existing one; nothing is overwritten; the copy is
// recorded as the VM's project's; a failed run removes only what it created.

// fakeBtrfs puts a fake btrfs on PATH that keeps real directories: a
// "subvolume" is a directory whose inode is listed in the subvols file (a
// rename keeps it one); snapshot copies one;
// send writes the snapshot's name then a tar of it; receive creates
// <dir>/<name> from that stream, refusing an existing name. Every call is
// appended to the returned log. BTRFS_FAIL_RECEIVE=1 makes receive create a
// partial subvolume and fail; BTRFS_RECEIVE_ALSO_CREATES=<path> makes it
// create the file <path> (someone else's) while it runs;
// BTRFS_RECEIVE_REPLACE_WITH=<file> makes what it receives that file's bytes;
// BTRFS_FAIL_SNAPSHOT=1 makes every snapshot fail (a read-only source pool).
func fakeBtrfs(t *testing.T) (logPath, subvols string) {
	t.Helper()
	dir := t.TempDir()
	logPath = filepath.Join(dir, "calls.log")
	subvols = filepath.Join(dir, "subvols")
	if err := os.WriteFile(subvols, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	script := `#!/bin/sh
echo "btrfs $*" >> ` + logPath + `
last=""; for a in "$@"; do last="$a"; done
pos=""; seen=""; for a in "$@"; do
  if [ -n "$seen" ]; then pos="$pos
$a"; fi
  [ "$a" = "--" ] && seen=1
done
first=$(printf '%s\n' "$pos" | sed -n 2p)
second=$(printf '%s\n' "$pos" | sed -n 3p)
case "$1 $2" in
  "subvolume show") [ -d "$last" ] && grep -qxF -- "$(stat -c %i "$last")" ` + subvols + ` && exit 0; echo "not a subvolume" >&2; exit 1 ;;
  "subvolume snapshot")
    [ "$BTRFS_FAIL_SNAPSHOT" = 1 ] && { echo "read-only file system" >&2; exit 1; }
    grep -qxF -- "$(stat -c %i "$first")" ` + subvols + ` || { echo "not a subvolume" >&2; exit 1; }
    [ -e "$second" ] && { echo "exists" >&2; exit 1; }
    cp -a "$first" "$second" || exit 1
    stat -c %i "$second" >> ` + subvols + `; exit 0 ;;
  "subvolume delete")
    ino=$(stat -c %i "$last")
    grep -qxF -- "$ino" ` + subvols + ` || { echo "not a subvolume" >&2; exit 1; }
    rm -rf -- "$last"; grep -vxF -- "$ino" ` + subvols + ` > ` + subvols + `.n; mv ` + subvols + `.n ` + subvols + `; exit 0 ;;
esac
case "$1" in
  send) basename "$last"; tar -C "$last" -cf - . ; exit 0 ;;
  receive)
    read name
    [ -n "$BTRFS_RECEIVE_ALSO_CREATES" ] && echo theirs > "$BTRFS_RECEIVE_ALSO_CREATES"
    [ -e "$last/$name" ] && { cat >/dev/null; echo "exists" >&2; exit 1; }
    mkdir "$last/$name" && stat -c %i "$last/$name" >> ` + subvols + `
    if [ "$BTRFS_FAIL_RECEIVE" = 1 ]; then cat >/dev/null; echo partial > "$last/$name/partial"; exit 1; fi
    tar -xf - -C "$last/$name" || exit 1
    if [ -n "$BTRFS_RECEIVE_REPLACE_WITH" ]; then for f in "$last/$name"/*; do cp "$BTRFS_RECEIVE_REPLACE_WITH" "$f"; done; fi
    exit 0 ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath, subvols
}

// btrfsVM is project a's running VM "vm1" on this host whose root disk is
// the standalone qcow2 <src>/vm1-root/vm1-root.qcow2 in btrfs pool "src", its
// directory a per-disk subvolume, and an empty global btrfs pool "copies" at
// <dst>.
func btrfsVM(t *testing.T) (s *Server, alice context.Context, src, dst, payload string, subvols string, log string) {
	t.Helper()
	log, subvols = fakeBtrfs(t)
	s = newPoolTestServer(t)
	src, dst = t.TempDir(), t.TempDir()
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "src", Driver: "btrfs", Source: src})
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "copies", Driver: "btrfs", Source: dst})
	sub := filepath.Join(src, "vm1-root")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	payload = string(qcow2Bytes(t))
	// 0644, as qcow2.Create makes a disk: the copy must still be 0600.
	if err := os.WriteFile(filepath.Join(sub, "vm1-root.qcow2"), []byte(payload), 0o644); err != nil {
		t.Fatal(err)
	}
	markSubvol(t, subvols, sub)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Project: "a", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "running", Project: "a", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: s.hostName, Path: filepath.Join(sub, "vm1-root.qcow2"),
			SizeBytes: 1 << 20, StorageType: "btrfs", StorageVolume: "src"}}); err != nil {
		t.Fatal(err)
	}
	return s, grantUser(t, s, "alice", "/projects/a", "Operator"), src, dst, payload, subvols, log
}

func inode(t *testing.T, p string) string {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		return ""
	}
	return fmt.Sprint(fi.Sys().(*syscall.Stat_t).Ino)
}

func markSubvol(t *testing.T, subvols, p string) {
	t.Helper()
	f, err := os.OpenFile(subvols, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(inode(t, p) + "\n"); err != nil {
		t.Fatal(err)
	}
}

// liveSubvols is every subvolume the fake still holds: by path when it is
// within two levels of one of roots, otherwise by inode.
func liveSubvols(t *testing.T, subvols string, roots ...string) []string {
	t.Helper()
	b, _ := os.ReadFile(subvols)
	left := map[string]bool{}
	for _, l := range strings.Fields(string(b)) {
		left[l] = true
	}
	var out []string
	for _, r := range roots {
		_ = filepath.WalkDir(r, func(p string, d os.DirEntry, err error) error {
			if err != nil || !d.IsDir() {
				return nil
			}
			if rel, _ := filepath.Rel(r, p); strings.Count(rel, string(filepath.Separator)) > 1 {
				return filepath.SkipDir
			}
			if ino := inode(t, p); left[ino] {
				out = append(out, p)
				delete(left, ino)
			}
			return nil
		})
	}
	for ino := range left {
		out = append(out, "inode "+ino)
	}
	sort.Strings(out)
	return out
}

func entries(t *testing.T, dir string) []string {
	t.Helper()
	des, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, de := range des {
		out = append(out, de.Name())
	}
	return out
}

// nativeTried reports whether the copy announced a native send/receive.
func nativeTried(rec *streamRecorder[pb.ReplicateVolumeProgress]) bool {
	for _, m := range rec.Sent {
		if strings.Contains(m.Status, "native") {
			return true
		}
	}
	return false
}

func btrfsSent(t *testing.T, log string) bool {
	t.Helper()
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "btrfs send ") || strings.HasPrefix(c, "btrfs receive ") {
			return true
		}
	}
	return false
}

func replicateBtrfs(t *testing.T, s *Server, ctx context.Context, target string) (*streamRecorder[pb.ReplicateVolumeProgress], error) {
	t.Helper()
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: ctx}
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: target}, rec)
	return rec, err
}

// btrfs→btrfs goes through btrfs send | btrfs receive — not a qemu-img copy —
// and the copy is the same new file in the pool's directory a file copy
// makes: <pool>/<vm>-<disk>-copy-<time>-<id>.qcow2, holding the disk's bytes.
func TestReplicateVolume_NativeBtrfsWorksIntoAFreshFile(t *testing.T) {
	s, alice, _, dst, payload, subvols, log := btrfsVM(t)
	rec, err := replicateBtrfs(t, s, alice, "")
	if err != nil {
		t.Fatalf("native btrfs ReplicateVolume: %v", err)
	}
	got := rec.Sent[len(rec.Sent)-1].TargetPath
	if filepath.Dir(got) != dst || !strings.HasPrefix(filepath.Base(got), "vm1-root-copy-") || filepath.Ext(got) != ".qcow2" {
		t.Fatalf("copy at %q, want <copies>/vm1-root-copy-<time>-<id>.qcow2", got)
	}
	if fi, err := os.Lstat(got); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("copy %q is not a regular file: %v", got, err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("copy mode %v, want 0600 as a file copy's", fi.Mode().Perm())
	}
	if b, err := os.ReadFile(got); err != nil || string(b) != payload {
		t.Errorf("copy holds other bytes than the disk (%v)", err)
	}
	if !btrfsSent(t, log) {
		t.Errorf("no native btrfs send | receive ran (calls %q)", calls(t, log))
	}
	if !strings.Contains(rec.Sent[len(rec.Sent)-1].Status, "native") {
		t.Errorf("status %q does not say the copy was native", rec.Sent[len(rec.Sent)-1].Status)
	}
	_ = subvols
}

// The copy is recorded as the VM's project's copy of the disk, as a
// file-copy is.
func TestReplicateVolume_NativeBtrfsRecordsTheCopy(t *testing.T) {
	s, alice, _, _, _, _, _ := btrfsVM(t)
	rec, err := replicateBtrfs(t, s, alice, "")
	if err != nil {
		t.Fatal(err)
	}
	got := rec.Sent[len(rec.Sent)-1].TargetPath
	m, err := s.readPoolUploads()
	if err != nil {
		t.Fatal(err)
	}
	u, ok := m[filepath.Clean(got)]
	if !ok || !u.Copy || u.Pool != "copies" || u.Project != "a" || u.VM != "vm1" || u.Disk != "root" {
		t.Errorf("record of %q = %+v (present %v), want the VM's project's copy of vm1/root in pool copies", got, u, ok)
	}
}

// A successful copy leaves nothing behind but the copy: the read-only send
// snapshot, the received subvolume and the staging directories are removed.
func TestReplicateVolume_NativeBtrfsLeavesOnlyTheCopy(t *testing.T) {
	s, alice, src, dst, _, subvols, log := btrfsVM(t)
	rec, err := replicateBtrfs(t, s, alice, "")
	if err != nil {
		t.Fatal(err)
	}
	copyFile := rec.Sent[len(rec.Sent)-1].TargetPath
	if e := entries(t, src); len(e) != 1 || e[0] != "vm1-root" {
		t.Errorf("source pool holds %q, want only the disk's subvolume", e)
	}
	if e := entries(t, dst); len(e) != 1 || e[0] != filepath.Base(copyFile) {
		t.Errorf("target pool holds %q, want only the copy", e)
	}
	if got, want := liveSubvols(t, subvols, src, dst), []string{filepath.Join(src, "vm1-root")}; !slices.Equal(got, want) {
		t.Errorf("subvolumes left %q, want %q", got, want)
	}
	var ro int
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "btrfs subvolume snapshot -r -- "+filepath.Join(src, "vm1-root")+" ") {
			ro++
		} else if strings.HasPrefix(c, "btrfs subvolume snapshot ") {
			t.Errorf("a snapshot other than the read-only send snapshot: %q", c)
		}
		if !strings.Contains(c, " -- ") {
			t.Errorf("btrfs argv without \"--\" before its paths: %q", c)
		}
	}
	if ro != 1 {
		t.Errorf("read-only source snapshots %d, want 1 (calls %q)", ro, calls(t, log))
	}
}

// An admin may name the copy, but an existing name is refused before
// anything is snapshotted or sent, and is left as it was.
func TestReplicateVolume_NativeBtrfsNeverReplacesAnExistingDestination(t *testing.T) {
	s, _, _, dst, _, _, log := btrfsVM(t)
	theirs := filepath.Join(dst, "db-copy.qcow2")
	if err := os.WriteFile(theirs, []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := replicateBtrfs(t, s, adminCtx(), "db-copy.qcow2")
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("native btrfs copy onto an existing name: got %v, want AlreadyExists", err)
	}
	if btrfsSent(t, log) {
		t.Errorf("something was sent toward an existing destination: %q", calls(t, log))
	}
	if b, _ := os.ReadFile(theirs); string(b) != "theirs" {
		t.Errorf("the existing destination was changed: %q", b)
	}
}

// A name that appears while the copy is received is never replaced either:
// the copy is placed with a rename that refuses an existing name, and only
// what this run created is removed.
func TestReplicateVolume_NativeBtrfsDestinationCreatedMidCopyIsKept(t *testing.T) {
	s, _, src, dst, _, subvols, _ := btrfsVM(t)
	theirs := filepath.Join(dst, "db-copy.qcow2")
	t.Setenv("BTRFS_RECEIVE_ALSO_CREATES", theirs)
	_, err := replicateBtrfs(t, s, adminCtx(), "db-copy.qcow2")
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("a destination created mid-copy: got %v, want AlreadyExists", err)
	}
	if b, _ := os.ReadFile(theirs); string(b) != "theirs\n" {
		t.Errorf("the destination created mid-copy was changed: %q", b)
	}
	if e := entries(t, dst); len(e) != 1 || e[0] != "db-copy.qcow2" {
		t.Errorf("target pool holds %q, want only the other file", e)
	}
	if e := entries(t, src); len(e) != 1 {
		t.Errorf("source pool holds %q, want only the disk's subvolume", e)
	}
	if got := liveSubvols(t, subvols, src, dst); !slices.Equal(got, []string{filepath.Join(src, "vm1-root")}) {
		t.Errorf("subvolumes left %q", got)
	}
}

// requireFileCopy checks that the last replicate made the qemu-img file copy:
// a standalone file at the target, the status not native. The file copy never
// replaces a file, so its success also proves the native attempt left nothing
// at the target.
func requireFileCopy(t *testing.T, rec *streamRecorder[pb.ReplicateVolumeProgress], err error) string {
	t.Helper()
	needQemuImg(t)
	if err != nil {
		t.Fatalf("replicate-volume: %v, want the file copy", err)
	}
	last := rec.Sent[len(rec.Sent)-1]
	if strings.Contains(last.Status, "native") {
		t.Errorf("status %q: want the file copy", last.Status)
	}
	if err := qcow2.AssertStandalone(last.TargetPath); err != nil {
		t.Errorf("copy %s: %v", last.TargetPath, err)
	}
	if fi, err := os.Lstat(last.TargetPath); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("no file copy at %s: %v", last.TargetPath, err)
	}
	return last.TargetPath
}

// A native copy that fails — here the receive — removes the partial
// subvolume and the send snapshot it created, places nothing, and the file
// copy is made instead: btrfs→btrfs worked through the file copy before the
// native path, and a native failure never newly refuses it.
func TestReplicateVolume_NativeBtrfsFailedReceiveFallsBackToTheFileCopy(t *testing.T) {
	s, alice, src, dst, _, subvols, _ := btrfsVM(t)
	t.Setenv("BTRFS_FAIL_RECEIVE", "1")
	rec, err := replicateBtrfs(t, s, alice, "")
	copyFile := requireFileCopy(t, rec, err)
	if e := entries(t, dst); len(e) != 1 || e[0] != filepath.Base(copyFile) {
		t.Errorf("target pool holds %q, want only the file copy", e)
	}
	if e := entries(t, src); len(e) != 1 {
		t.Errorf("source pool holds %q after a failed native copy, want only the disk's subvolume", e)
	}
	if got := liveSubvols(t, subvols, src, dst); !slices.Equal(got, []string{filepath.Join(src, "vm1-root")}) {
		t.Errorf("subvolumes left after a failed native copy %q", got)
	}
}

// A source pool where nothing can be snapshotted (read-only, full) still gets
// its copy: the file copy, which only reads it.
func TestReplicateVolume_NativeBtrfsFailedSnapshotFallsBackToTheFileCopy(t *testing.T) {
	s, alice, src, _, _, _, _ := btrfsVM(t)
	t.Setenv("BTRFS_FAIL_SNAPSHOT", "1")
	rec, err := replicateBtrfs(t, s, alice, "")
	requireFileCopy(t, rec, err)
	if e := entries(t, src); len(e) != 1 {
		t.Errorf("source pool holds %q after a failed snapshot, want only the disk's subvolume", e)
	}
}

// The native path writes into the source pool (its send snapshot, the
// sweep), so a source pool the write check refuses is only read: the file
// copy.
func TestReplicateVolume_NativeBtrfsRefusedSourcePoolTakesTheFileCopy(t *testing.T) {
	s, alice, _, _, _, subvols, log := btrfsVM(t)
	// A pool inside the daemon's data directory (not disks/, pools/ or
	// mounts/) is refused for writes.
	refused := filepath.Join(s.dataDir, "state")
	sub := filepath.Join(refused, "vm1-root")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	writeQcow2(t, filepath.Join(sub, "vm1-root.qcow2"))
	markSubvol(t, subvols, sub)
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "src", Driver: "btrfs", Source: refused})
	setDiskPath(t, s, filepath.Join(sub, "vm1-root.qcow2"))
	if _, ok := s.resolvePool(context.Background(), "src"); !ok {
		t.Fatal("the source pool does not resolve")
	}
	if cerr, _ := s.poolRefusal(context.Background(), "src", StoragePoolRef{Driver: "btrfs", Source: refused}); cerr == nil {
		t.Fatal("the test's source pool is not refused")
	}
	rec, err := replicateBtrfs(t, s, alice, "")
	requireFileCopy(t, rec, err)
	if btrfsSent(t, log) {
		t.Errorf("sent natively from a refused pool: %q", calls(t, log))
	}
	for _, c := range calls(t, log) {
		if strings.Contains(c, "snapshot") || strings.Contains(c, "delete") {
			t.Errorf("btrfs wrote into the refused source pool: %q", c)
		}
	}
	if e := entries(t, refused); len(e) != 1 {
		t.Errorf("refused source pool holds %q, want only the disk's subvolume", e)
	}
}

// A copy never depends on a file outside itself: what was received is
// checked again, and a received copy that names a backing file is not placed
// — the file copy, which flattens, is made instead.
func TestReplicateVolume_NativeBtrfsReceivedCopyWithABackingFileTakesTheFileCopy(t *testing.T) {
	s, alice, src, dst, _, subvols, _ := btrfsVM(t)
	base := filepath.Join(t.TempDir(), "base.qcow2")
	writeQcow2(t, base)
	overlay := filepath.Join(t.TempDir(), "overlay.qcow2")
	if err := qcow2.CreateWithBacking(overlay, base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BTRFS_RECEIVE_REPLACE_WITH", overlay)
	rec, err := replicateBtrfs(t, s, alice, "")
	copyFile := requireFileCopy(t, rec, err)
	if e := entries(t, dst); len(e) != 1 || e[0] != filepath.Base(copyFile) {
		t.Errorf("target pool holds %q, want only the file copy", e)
	}
	if got := liveSubvols(t, subvols, src, dst); !slices.Equal(got, []string{filepath.Join(src, "vm1-root")}) {
		t.Errorf("subvolumes left %q", got)
	}
}

// A project Operator cannot name the copy; an admin's name outside the pool's
// directory, or a hidden one, gets the file copy there — never a native send,
// and never a refusal.
func TestReplicateVolume_NativeBtrfsTargetOutsideThePoolTakesTheFileCopy(t *testing.T) {
	s, alice, _, _, _, _, log := btrfsVM(t)
	if _, err := replicateBtrfs(t, s, alice, "db-copy.qcow2"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator naming the copy: got %v, want PermissionDenied", err)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.qcow2")
	for _, target := range []string{elsewhere, ".hidden.qcow2"} {
		rec, err := replicateBtrfs(t, s, adminCtx(), target)
		got := requireFileCopy(t, rec, err)
		if target == elsewhere && got != elsewhere {
			t.Errorf("copy at %s, want %s", got, elsewhere)
		}
		if nativeTried(rec) {
			t.Errorf("a native copy was tried for %s", target)
		}
	}
	if btrfsSent(t, log) {
		t.Errorf("sent natively: %q", calls(t, log))
	}
}

// Only a standalone disk alone in its own subvolume directly under its pool
// is sent natively; anything else keeps the file copy — a disk on a base
// image above all, which the qemu-img copy flattens.
func TestReplicateVolume_BtrfsOtherwiseKeepsTheFileCopy(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, s *Server, src, subvols string){
		"disk with a backing file": func(t *testing.T, s *Server, src, subvols string) {
			base := filepath.Join(t.TempDir(), "base.qcow2")
			writeQcow2(t, base)
			p := filepath.Join(src, "vm1-root", "vm1-root.qcow2")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := qcow2.CreateWithBacking(p, base, 1<<20, nil); err != nil {
				t.Fatal(err)
			}
		},
		"disk in the pool directory": func(t *testing.T, s *Server, src, subvols string) {
			p := filepath.Join(src, "vm1-root-flat.qcow2")
			writeQcow2(t, p)
			setDiskPath(t, s, p)
		},
		"not a subvolume": func(t *testing.T, s *Server, src, subvols string) {
			if err := os.WriteFile(subvols, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"subvolume holds another file": func(t *testing.T, s *Server, src, subvols string) {
			writeQcow2(t, filepath.Join(src, "vm1-root", "other.qcow2"))
		},
		"target of another driver": func(t *testing.T, s *Server, src, subvols string) {
			upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "copies", Driver: "dir", Target: t.TempDir()})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, src, _, _, subvols, log := btrfsVM(t)
			setup(t, s, src, subvols)
			rec, err := replicateBtrfs(t, s, adminCtx(), "")
			if btrfsSent(t, log) || nativeTried(rec) {
				t.Errorf("sent natively: %q", calls(t, log))
			}
			if err != nil && strings.Contains(err.Error(), "native") {
				t.Errorf("the native path refused instead of the file copy running: %v", err)
			}
		})
	}
}

func setDiskPath(t *testing.T, s *Server, p string) {
	t.Helper()
	if _, err := s.db.ExecuteRows(context.Background(), `UPDATE vm_disks SET path = ? WHERE vm_name = 'vm1' AND disk_name = 'root'`, p); err != nil {
		t.Fatal(err)
	}
}

// A native btrfs copy is found where every copy is: its project's operator
// promotes it by name, and the VM is defined on and boots from it.
func TestReplicateVolume_NativeBtrfsCopyIsPromotedAndBooted(t *testing.T) {
	s, _, _, dst, _, _, log := btrfsVM(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("a"))
	rec, err := replicateBtrfs(t, s, pat, "")
	if err != nil {
		t.Fatalf("replicate-volume: %v", err)
	}
	if !btrfsSent(t, log) {
		t.Fatal("the copy was not native")
	}
	copyFile := rec.Sent[len(rec.Sent)-1].TargetPath
	if err := promote(pat, s, &pb.PromoteReplicaRequest{VmName: "vm1", TargetPool: "copies", Replica: filepath.Base(copyFile), NoLocalize: true}); err != nil {
		t.Fatalf("promoting the native copy by name: %v", err)
	}
	if !promotedFrom(dst, "vm1", filepath.Base(copyFile)) {
		t.Fatalf("vm1 was not promoted from %s (pool holds %q)", copyFile, entries(t, dst))
	}
	stem := strings.TrimSuffix(filepath.Base(copyFile), ".qcow2")
	overlay := filepath.Join(dst, "vm1-promoted-"+stem+".qcow2")
	if info, err := qcow2.Info(overlay); err != nil || info.BackingFile != copyFile {
		t.Errorf("the promoted disk's backing = %+v (%v), want the copy %s", info, err, copyFile)
	}
	fake := s.virt.(*libvirtfake.Fake)
	if st, _ := fake.DomainState("vm1"); st != "running" {
		t.Errorf("vm1 after promotion: %q, want running", st)
	}
	if xml := fake.DefinedXML("vm1"); !strings.Contains(xml, overlay) {
		t.Errorf("vm1's definition does not boot from %s:\n%s", overlay, xml)
	}
}

// A copy that never finished (a daemon that died mid-copy) leaves staging; a
// later copy removes the stale staging this driver made — a directory of its
// name carrying its marker — and nothing else: not a fresh one, not one a
// disk uses, not an unmarked directory of the same name, and never a file
// such as an admin-named ".litevirt-place-…" copy whose record was lost.
func TestReplicateVolume_NativeBtrfsSweepsStaleStaging(t *testing.T) {
	s, alice, src, dst, _, subvols, _ := btrfsVM(t)
	old := time.Now().Add(-25 * time.Hour).Unix()
	fresh := time.Now().Add(-time.Hour).Unix()
	stage := func(root, kind string, at int64, id string, marked bool) string {
		d := filepath.Join(root, fmt.Sprintf(".litevirt-%s-%d-%s", kind, at, id))
		snap := filepath.Join(d, "snap")
		if err := os.MkdirAll(snap, 0o700); err != nil {
			t.Fatal(err)
		}
		writeQcow2(t, filepath.Join(snap, "vm1-root.qcow2"))
		markSubvol(t, subvols, snap)
		if marked {
			if err := os.WriteFile(filepath.Join(d, ".litevirt-staging"), []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return d
	}
	staleSend := stage(src, "send", old, "aaaaaaaaaaaa", true)
	staleRecv := stage(dst, "recv", old, "bbbbbbbbbbbb", true)
	writeQcow2(t, filepath.Join(staleRecv, "place"))
	freshRecv := stage(dst, "recv", fresh, "cccccccccccc", true)
	usedRecv := stage(dst, "recv", old, "dddddddddddd", true)
	unmarked := stage(dst, "recv", old, "abababababab", false)
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm2", HostName: s.hostName, State: "stopped", Project: "a"},
		nil, []corrosion.DiskRecord{{VMName: "vm2", DiskName: "root", HostName: s.hostName,
			Path: filepath.Join(usedRecv, "snap", "vm1-root.qcow2"), StorageType: "btrfs"}}); err != nil {
		t.Fatal(err)
	}
	adminFile := filepath.Join(dst, fmt.Sprintf(".litevirt-place-%d-eeeeeeeeeeee", old))
	writeQcow2(t, adminFile)
	adminRecvFile := filepath.Join(dst, fmt.Sprintf(".litevirt-recv-%d-ffffffffffff", old))
	writeQcow2(t, adminRecvFile)
	if _, err := replicateBtrfs(t, s, alice, ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{staleSend, staleRecv} {
		if _, err := os.Lstat(p); err == nil {
			t.Errorf("stale staging %s outlived the next copy", p)
		}
	}
	for _, p := range []string{freshRecv, usedRecv, unmarked, filepath.Join(unmarked, "snap"), adminFile, adminRecvFile} {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("%s was swept: %v", p, err)
		}
	}
}

// A native btrfs copy is where and what a file copy is — a file in the pool's
// directory, recorded as the VM's project's copy — so every path that finds
// copies treats it as one: the project's pool listing shows it, a replication
// run's prune never takes it (a copy is not a replica), and it is deleted by
// name like any file in the pool (here a global pool, so by an admin).
func TestReplicateVolume_NativeBtrfsCopyIsListedKeptAndDeletableAsAFileCopy(t *testing.T) {
	s, _, _, dst, _, _, log := btrfsVM(t)
	pat := hostPathEngineCtx(t, s, "pat", "Operator", projectRBACBase("a"))
	rec, err := replicateBtrfs(t, s, pat, "")
	if err != nil || !btrfsSent(t, log) {
		t.Fatalf("native replicate-volume: %v (sent %v)", err, btrfsSent(t, log))
	}
	copyFile := rec.Sent[len(rec.Sent)-1].TargetPath
	resp, err := s.ListStoragePoolContents(pat, &pb.ListStoragePoolContentsRequest{PoolName: "copies"})
	if err != nil {
		t.Fatalf("list the pool: %v", err)
	}
	listed := false
	for _, c := range resp.Contents {
		listed = listed || c.Path == copyFile
	}
	if !listed {
		t.Errorf("the pool listing %v does not show the copy %s", resp.Contents, copyFile)
	}
	s.pruneLocalReplicas(context.Background(), dst, replicaKey{VM: "vm1", Disk: "root", Project: "a"}, 0)
	if _, err := os.Stat(copyFile); err != nil {
		t.Fatalf("a keep-0 prune of vm1's replicas took the copy: %v", err)
	}
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "copies", Filename: filepath.Base(copyFile)}); err != nil {
		t.Fatalf("deleting the copy by name: %v", err)
	}
	if _, err := os.Stat(copyFile); err == nil {
		t.Errorf("the copy outlived its delete")
	}
}
