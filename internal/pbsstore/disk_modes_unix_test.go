//go:build unix

package pbsstore

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A disk restored from the backup store is a guest's data: owner-only, not
// the group-readable 0640 it was.
//
// Mutation: the restore temp chmod-ed to 0o640 again — this goes red.
func TestRestoreToFile_TheDiskIsOwnerOnly(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	r := newTestRepo(t)
	src := randomBytes(t, ChunkSize+17)
	m, err := PushDisk(context.Background(), r, bytes.NewReader(src), PushOptions{VMName: "vm1", DiskName: "root", Timestamp: "2026-10-11T10:00:00Z"})
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "restored.raw")
	if err := RestoreToFile(context.Background(), r, m, dst, RestoreOptions{}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dst)
	if err != nil {
		t.Fatal(err)
	}
	if got := fi.Mode().Perm(); got != 0o600 {
		t.Errorf("restored disk is %04o, want 0600", got)
	}
}
