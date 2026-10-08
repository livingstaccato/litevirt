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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
// create <path> (someone else's directory, holding a file "keep" unless
// BTRFS_RECEIVE_ALSO_CREATES_EMPTY is set) while it runs.
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
    [ -n "$BTRFS_RECEIVE_ALSO_CREATES" ] && mkdir -p "$BTRFS_RECEIVE_ALSO_CREATES" && [ -z "$BTRFS_RECEIVE_ALSO_CREATES_EMPTY" ] && echo theirs > "$BTRFS_RECEIVE_ALSO_CREATES/keep"
    [ -e "$last/$name" ] && { cat >/dev/null; echo "exists" >&2; exit 1; }
    mkdir "$last/$name" && stat -c %i "$last/$name" >> ` + subvols + `
    if [ "$BTRFS_FAIL_RECEIVE" = 1 ]; then cat >/dev/null; echo partial > "$last/$name/partial"; exit 1; fi
    tar -xf - -C "$last/$name"; exit $? ;;
esac
exit 0
`
	if err := os.WriteFile(filepath.Join(dir, "btrfs"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	return logPath, subvols
}

// btrfsVM is project a's VM "vm1" whose root disk is
// <src>/vm1-root/vm1-root.qcow2 in btrfs pool "src", its directory a
// per-disk subvolume, and an empty btrfs pool "copies" at <dst>.
func btrfsVM(t *testing.T) (s *Server, alice context.Context, src, dst, payload string, subvols string, log string) {
	t.Helper()
	log, subvols = fakeBtrfs(t)
	s = testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	src, dst = t.TempDir(), t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{
		"src":    {Driver: "btrfs", Source: src},
		"copies": {Driver: "btrfs", Source: dst},
	})
	sub := filepath.Join(src, "vm1-root")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	payload = "DISK BYTES of vm1 root"
	if err := os.WriteFile(filepath.Join(sub, "vm1-root.qcow2"), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	markSubvol(t, subvols, sub)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Project: "a"})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped", Project: "a", Spec: string(spec)},
		nil, []corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: "test-host", Path: filepath.Join(sub, "vm1-root.qcow2"),
			SizeBytes: int64(len(payload)), StorageType: "btrfs", StorageVolume: "src"}}); err != nil {
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

func isSubvol(t *testing.T, subvols, p string) bool {
	t.Helper()
	ino := inode(t, p)
	b, _ := os.ReadFile(subvols)
	return ino != "" && slices.Contains(strings.Fields(string(b)), ino)
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

// btrfs→btrfs goes through btrfs send | btrfs receive into a new subvolume
// the daemon names in the target pool — not through a qemu-img file copy.
func TestReplicateVolume_NativeBtrfsWorksIntoAFreshSubvolume(t *testing.T) {
	s, alice, _, dst, payload, subvols, log := btrfsVM(t)
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"}, rec); err != nil {
		t.Fatalf("native btrfs ReplicateVolume: %v", err)
	}
	got := rec.Sent[len(rec.Sent)-1].TargetPath
	sub := filepath.Dir(got)
	if filepath.Dir(sub) != dst || !strings.HasPrefix(filepath.Base(sub), "vm1-root-copy-") || filepath.Base(got) != "vm1-root.qcow2" {
		t.Fatalf("copy at %q, want <copies>/vm1-root-copy-<time>-<id>/vm1-root.qcow2", got)
	}
	if !isSubvol(t, subvols, sub) {
		t.Errorf("%q is not a subvolume", sub)
	}
	if b, err := os.ReadFile(got); err != nil || string(b) != payload {
		t.Errorf("copy holds %q (%v), want the disk's bytes", b, err)
	}
	var send, recv bool
	for _, c := range calls(t, log) {
		send = send || strings.HasPrefix(c, "btrfs send ")
		recv = recv || strings.HasPrefix(c, "btrfs receive ")
	}
	if !send || !recv {
		t.Errorf("send=%v receive=%v: want a native btrfs send | receive (calls %q)", send, recv, calls(t, log))
	}
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

func btrfsSent(t *testing.T, log string) bool {
	t.Helper()
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "btrfs send ") || strings.HasPrefix(c, "btrfs receive ") {
			return true
		}
	}
	return false
}

// The copy is recorded as the VM's project's copy of the disk, as a
// file-copy is: promotable by its project, never another's.
func TestReplicateVolume_NativeBtrfsRecordsTheCopy(t *testing.T) {
	s, alice, _, _, _, _, _ := btrfsVM(t)
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"}, rec); err != nil {
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
	if strings.Contains(rec.Sent[len(rec.Sent)-1].Status, "not recorded") {
		t.Errorf("status %q", rec.Sent[len(rec.Sent)-1].Status)
	}
}

// A successful copy leaves nothing behind but the copy: the read-only send
// snapshot in the source pool and the received subvolume are removed.
func TestReplicateVolume_NativeBtrfsLeavesOnlyTheCopy(t *testing.T) {
	s, alice, src, dst, _, subvols, log := btrfsVM(t)
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"}, rec); err != nil {
		t.Fatal(err)
	}
	copySub := filepath.Dir(rec.Sent[len(rec.Sent)-1].TargetPath)
	if e := entries(t, src); len(e) != 1 || e[0] != "vm1-root" {
		t.Errorf("source pool holds %q, want only the disk's subvolume", e)
	}
	if e := entries(t, dst); len(e) != 1 || e[0] != filepath.Base(copySub) {
		t.Errorf("target pool holds %q, want only the copy", e)
	}
	if got, want := liveSubvols(t, subvols, src, dst), []string{filepath.Join(src, "vm1-root"), copySub}; !slices.Equal(got, want) {
		t.Errorf("subvolumes left %q, want %q", got, want)
	}
	// The source is sent from a read-only snapshot; the copy placed is a
	// writable one (a received subvolume is read-only, and a copy is a disk
	// to promote).
	var ro, rw int
	for _, c := range calls(t, log) {
		if strings.HasPrefix(c, "btrfs subvolume snapshot -r -- "+filepath.Join(src, "vm1-root")+" ") {
			ro++
		} else if strings.HasPrefix(c, "btrfs subvolume snapshot -- ") {
			rw++
		}
	}
	if ro != 1 || rw != 1 {
		t.Errorf("read-only source snapshots %d, writable snapshots %d: want 1 and 1 (calls %q)", ro, rw, calls(t, log))
	}
	for _, c := range calls(t, log) {
		if !strings.Contains(c, " -- ") {
			t.Errorf("btrfs argv without \"--\" before its paths: %q", c)
		}
	}
}

// An admin may name the copy, but an existing name is refused before
// anything is snapshotted or sent, and is left as it was.
func TestReplicateVolume_NativeBtrfsNeverReplacesAnExistingDestination(t *testing.T) {
	s, _, _, dst, _, _, log := btrfsVM(t)
	theirs := filepath.Join(dst, "db-root")
	if err := os.MkdirAll(theirs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(theirs, "keep"), []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: "db-root"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("native btrfs copy onto an existing name: got %v, want AlreadyExists", err)
	}
	if btrfsSent(t, log) {
		t.Errorf("something was sent toward an existing destination: %q", calls(t, log))
	}
	if b, _ := os.ReadFile(filepath.Join(theirs, "keep")); string(b) != "theirs" {
		t.Errorf("the existing destination was changed: keep=%q", b)
	}
}

// A name that appears while the copy is received is never replaced either —
// an empty directory included, which a plain rename would replace: the copy
// is placed with a rename that refuses an existing name, and only what this
// run created is removed.
func TestReplicateVolume_NativeBtrfsDestinationCreatedMidCopyIsKept(t *testing.T) {
	for _, empty := range []bool{false, true} {
		t.Run(fmt.Sprintf("empty=%v", empty), func(t *testing.T) {
			s, _, src, dst, _, subvols, _ := btrfsVM(t)
			theirs := filepath.Join(dst, "db-root")
			t.Setenv("BTRFS_RECEIVE_ALSO_CREATES", theirs)
			want := []string{"keep"}
			if empty {
				t.Setenv("BTRFS_RECEIVE_ALSO_CREATES_EMPTY", "1")
				want = nil
			}
			err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: "db-root"},
				&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
			if status.Code(err) != codes.AlreadyExists {
				t.Errorf("a destination created mid-copy: got %v, want AlreadyExists", err)
			}
			if e := entries(t, theirs); !slices.Equal(e, want) {
				t.Errorf("the destination created mid-copy now holds %q, want %q", e, want)
			}
			if b, _ := os.ReadFile(filepath.Join(theirs, "keep")); !empty && string(b) != "theirs\n" {
				t.Errorf("the destination created mid-copy was changed: keep=%q", b)
			}
			if e := entries(t, dst); len(e) != 1 || e[0] != "db-root" {
				t.Errorf("target pool holds %q, want only the other directory", e)
			}
			if e := entries(t, src); len(e) != 1 {
				t.Errorf("source pool holds %q, want only the disk's subvolume", e)
			}
			if got := liveSubvols(t, subvols, src, dst); !slices.Equal(got, []string{filepath.Join(src, "vm1-root")}) {
				t.Errorf("subvolumes left %q", got)
			}
		})
	}
}

// A failed receive removes the partial subvolume and the send snapshot it
// created, and the next run works.
func TestReplicateVolume_NativeBtrfsFailedReceiveLeavesNothing(t *testing.T) {
	s, alice, src, dst, payload, subvols, _ := btrfsVM(t)
	t.Setenv("BTRFS_FAIL_RECEIVE", "1")
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice})
	if err == nil {
		t.Fatal("a failed receive reported success")
	}
	if e := entries(t, dst); len(e) != 0 {
		t.Errorf("target pool holds %q after a failed copy, want nothing", e)
	}
	if e := entries(t, src); len(e) != 1 {
		t.Errorf("source pool holds %q after a failed copy, want only the disk's subvolume", e)
	}
	if got := liveSubvols(t, subvols, src, dst); !slices.Equal(got, []string{filepath.Join(src, "vm1-root")}) {
		t.Errorf("subvolumes left after a failed copy %q", got)
	}
	t.Setenv("BTRFS_FAIL_RECEIVE", "")
	rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice}
	if err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"}, rec); err != nil {
		t.Fatalf("the run after a failed one: %v", err)
	}
	if b, err := os.ReadFile(rec.Sent[len(rec.Sent)-1].TargetPath); err != nil || string(b) != payload {
		t.Errorf("copy holds %q (%v)", b, err)
	}
}

// A project Operator cannot name the copy, and an admin's name is a leaf in
// the pool, never a path or a hidden name.
func TestReplicateVolume_NativeBtrfsTargetIsAnAdminLeaf(t *testing.T) {
	s, alice, _, _, _, _, log := btrfsVM(t)
	err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: "db-root"},
		&streamRecorder[pb.ReplicateVolumeProgress]{ctx: alice})
	if status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator naming a native destination: got %v, want PermissionDenied", err)
	}
	for _, leaf := range []string{"../x", "a/b", "/abs/x", ".hidden", "-x"} {
		err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies", TargetPath: leaf},
			&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("target_path %q: got %v, want InvalidArgument", leaf, err)
		}
	}
	if btrfsSent(t, log) {
		t.Errorf("something was sent for a refused request: %q", calls(t, log))
	}
}

// Only a disk alone in its own subvolume directly under its pool is sent
// natively; anything else — a disk file in the pool's directory, a directory
// that is not a subvolume, a subvolume holding other files, a target of
// another driver — keeps the file copy.
func TestReplicateVolume_BtrfsOtherwiseKeepsTheFileCopy(t *testing.T) {
	for name, setup := range map[string]func(t *testing.T, s *Server, src, subvols string){
		"disk in the pool directory": func(t *testing.T, s *Server, src, subvols string) {
			p := filepath.Join(src, "vm1-root-flat.qcow2")
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			setDiskPath(t, s, p)
		},
		"not a subvolume": func(t *testing.T, s *Server, src, subvols string) {
			if err := os.WriteFile(subvols, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"subvolume holds another file": func(t *testing.T, s *Server, src, subvols string) {
			if err := os.WriteFile(filepath.Join(src, "vm1-root", "other.qcow2"), []byte("y"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"target of another driver": func(t *testing.T, s *Server, src, subvols string) {
			s.SetStoragePoolsByName(map[string]StoragePoolRef{
				"src":    {Driver: "btrfs", Source: src},
				"copies": {Driver: "dir", Target: t.TempDir()},
			})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, _, src, _, _, subvols, log := btrfsVM(t)
			setup(t, s, src, subvols)
			_ = s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "copies"},
				&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
			if btrfsSent(t, log) {
				t.Errorf("sent natively: %q", calls(t, log))
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
