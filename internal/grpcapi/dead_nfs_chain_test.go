package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/storage"
)

// The known gap of round 4 (lab 2 SD): a snapshot delete or revert, and a VM
// delete's keep set, read every VM disk's header chain (chainReaches)
// unbounded. With another VM's disk on a mount whose server did not answer,
// `lv snapshot rm` of a local VM waited in a stat of that disk.

// deadChainDir is a directory every header read under which (chainStat)
// blocks until the test ends, as one on a dead hard NFS mount does.
func deadChainDir(t *testing.T) string {
	t.Helper()
	dead := t.TempDir()
	release := make(chan struct{})
	prev := chainStat
	chainStat = func(p string) (os.FileInfo, error) {
		if pathWithin(dead, p) {
			<-release
		}
		return prev(p)
	}
	t.Cleanup(func() { chainStat = prev })
	t.Cleanup(func() { close(release) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(200 * time.Millisecond))
	return dead
}

func insertOneDiskVM(t *testing.T, s *Server, vm, disk string, deleteWithVM bool) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: vm, HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: vm, DiskName: "root", HostName: s.hostName, Path: disk, SizeBytes: 1 << 20,
			StorageType: "local", DeleteWithVM: deleteWithVM}}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE vm_disks SET delete_with_vm = ? WHERE vm_name = ?`, deleteWithVM, vm); err != nil {
		t.Fatal(err)
	}
}

// Who uses a local VM's snapshot file, while another VM's disk does not
// answer: that VM's chain was not read, so it counts as a user, and the call
// fails with the no-answer (the delete or revert is refused Unavailable).
// It never concludes "not reached".
//
// Mutations: "chainReaches unbounded" — hangs: red. "a chain not read is
// not reached" — no error: red.
func TestSnapshotFileUsers_AChainThatDoesNotAnswerIsNeverNotReached(t *testing.T) {
	s := testServer(t)
	local := t.TempDir()
	snap := filepath.Join(local, "a-root.qcow2")
	if err := qcow2.Create(snap, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertOneDiskVM(t, s, "a", snap, true)
	dead := deadChainDir(t)
	other := filepath.Join(dead, "b-root.qcow2")
	if err := qcow2.Create(other, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertOneDiskVM(t, s, "b", other, true)
	var users []string
	err := within(t, 5*time.Second, "who uses a file while another VM's disk does not answer", func() error {
		var err error
		users, err = s.snapshotFileUsers(context.Background(), "a", []string{snap})
		return err
	})
	if !storage.IsFSNoAnswer(err) || snapshotFileUsersCode(err) != codes.Unavailable {
		t.Fatalf("users %v, err %v; want the no-answer, refused Unavailable", users, err)
	}
}

// A VM delete keeps every layer of a disk recorded delete_with_vm=false. A
// chain that does not answer keeps every file (nil), promptly, instead of a
// keep set that misses the layers it could not read.
//
// Mutation "a chain not read is ignored" — a keep set without its layers:
// red.
func TestKeptDiskFiles_AChainThatDoesNotAnswerKeepsEverything(t *testing.T) {
	s := testServer(t)
	dead := deadChainDir(t)
	disk := filepath.Join(dead, "c-root.qcow2")
	if err := qcow2.Create(disk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertOneDiskVM(t, s, "c", disk, false)
	kept := within(t, 5*time.Second, "the keep set of a VM whose kept disk does not answer", func() map[string]bool {
		return s.keptDiskFiles(context.Background(), "c")
	})
	if kept != nil {
		t.Fatalf("keep set %v; want nil (keep every file)", kept)
	}
}

// A prune's scan reads each disk's chain one header at a time under the
// bound: a disk whose header does not answer refuses the prune promptly, not
// at the scan's two-minute deadline, and nothing is removed.
//
// Mutation "layerBacking unbounded" — waits for the deadline: red.
func TestPruneImages_ADiskHeaderThatDoesNotAnswerRefusesWithinTheBound(t *testing.T) {
	s, old, used := prunableStore(t)
	dead := deadChainDir(t)
	disk := filepath.Join(dead, "d-root.qcow2")
	if err := qcow2.CreateWithBacking(disk, used, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	insertOneDiskVM(t, s, "d", disk, true)
	wantNothingPruned(t, s, "a prune while a disk's header does not answer", old, used)
}
