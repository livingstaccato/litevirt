package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// I-5. A --no-localize promotion boots qemu, which runs as the distro's qemu
// user, on a replica in its owner directory; libvirt labels the file, never
// the directories above it. So the replica area and each owner directory are
// searchable by every user (qemu reaches the file by name), and listable by
// none but the daemon — whatever the umask, and for a directory an earlier
// build of the area made 0700.
func TestReplicaArea_QemuCanReachAReplicaByName(t *testing.T) {
	old := syscall.Umask(0o077)
	t.Cleanup(func() { syscall.Umask(old) })
	pool := t.TempDir()
	rec := newReplicaRecord("a", "web", "root", "web/dr", "20260901-000000", "qcow2")
	path, err := publishRecordedReplica(context.Background(), pool, rec, func(tmp string) error {
		return os.WriteFile(tmp, []byte("replica"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{filepath.Join(pool, replicaAreaDir), filepath.Dir(path)} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != 0o711 {
			t.Errorf("%s is %o, want 0711: searchable by qemu, listable by the daemon only", d, got)
		}
	}

	// An owner directory an earlier build made 0700 gets its search bits
	// the next time the daemon writes there.
	owner := replicaOwnerDir(pool, "b", "db")
	if err := os.Mkdir(owner, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(owner, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDirChecked(pool, "b", "db", true); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(owner); fi.Mode().Perm() != 0o711 {
		t.Errorf("an owner directory made 0700 is %o after a write, want 0711", fi.Mode().Perm())
	}
	// Reading the area changes nothing.
	if err := os.Chmod(owner, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := ownerDirChecked(pool, "b", "db", false); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(owner); fi.Mode().Perm() != 0o700 {
		t.Errorf("a read changed an owner directory's mode to %o", fi.Mode().Perm())
	}
}
