package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// lab5-trims-review A-P1. An admin's absolute target_path (restore-from,
// restore-live, replicate-volume) was never judged against the daemon's own
// state: resolveRestoreTarget returned any absolute path, refuseExistingFile
// stopped only an existing file, and stagingTemp's MkdirAll then created the
// parents. So an admin could plant <data_dir>/pending-audit/<x> (folded at
// startup), a capability latch marker, or a VM owner-epoch marker. Nobody,
// admin included, may aim a restore at the daemon's own state; the same
// owned-children rule as for pools (storage.dataDirOwned, judged by path
// components, as written and through symlinks) now refuses it before anything
// is created. Anywhere else an admin's target works as before.

// daemonStateTargets are paths in the daemon's own state under dataDir, with
// the directories each would create, none of which exists beforehand.
func daemonStateTargets(t *testing.T, dataDir string) map[string]struct{ target, created string } {
	t.Helper()
	// A link at an innocent name into vms/: the parents the restore would
	// create land in daemon state.
	if err := os.MkdirAll(filepath.Join(dataDir, "vms"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dataDir, "vms"), filepath.Join(dataDir, "innocent")); err != nil {
		t.Fatal(err)
	}
	return map[string]struct{ target, created string }{
		"pending-audit":  {filepath.Join(dataDir, "pending-audit", "x.json"), filepath.Join(dataDir, "pending-audit")},
		"latch marker":   {filepath.Join(dataDir, "split_brain_activated.voter_config_v1"), ""},
		"owner marker":   {filepath.Join(dataDir, "vms", "web", "owner_epoch"), filepath.Join(dataDir, "vms", "web")},
		"genesis marker": {filepath.Join(dataDir, "genesis-pending"), ""},
		"via a symlink":  {filepath.Join(dataDir, "innocent", "new", "x.img"), filepath.Join(dataDir, "vms", "new")},
	}
}

func requireNothingCreated(t *testing.T, err error, target, created string) {
	t.Helper()
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("target_path %s: got %v, want InvalidArgument", target, err)
	}
	if _, serr := os.Lstat(target); serr == nil {
		t.Errorf("%s was created", target)
	}
	if created != "" {
		if _, serr := os.Lstat(created); serr == nil {
			t.Errorf("directory %s was created", created)
		}
	}
}

// Red against 4644907f: each restore succeeds (or fails later) after
// writing into the daemon's state.
func TestRestoreFromBackup_AdminTargetInDaemonStateIsRefused(t *testing.T) {
	f := newRestoreFixture(t)
	for name, c := range daemonStateTargets(t, f.s.dataDir) {
		t.Run(name, func(t *testing.T) {
			err := restoreTargetPath(adminCtx(), f, "web", restoreTS, c.target)
			requireNothingCreated(t, err, c.target, c.created)
		})
	}
	// Elsewhere — a directory of the admin's own, or an ordinary child of
	// the data dir — an admin's target works as it did on main.
	for _, target := range []string{
		filepath.Join(t.TempDir(), "new", "web-root.img"),
		filepath.Join(f.s.dataDir, "rc5pool", "web-root.img"),
	} {
		if err := restoreTargetPath(adminCtx(), f, "web", restoreTS, target); err != nil {
			t.Errorf("admin target_path %s: %v", target, err)
		} else if _, err := os.Stat(target); err != nil {
			t.Errorf("admin target_path %s not written: %v", target, err)
		}
	}
	f.assertVictimIntact(t)
}

func TestRestoreLive_AdminTargetInDaemonStateIsRefused(t *testing.T) {
	f := newRestoreFixture(t)
	for name, c := range daemonStateTargets(t, f.s.dataDir) {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(adminCtx())
			cancel()
			err := f.s.RestoreLive(&pb.RestoreLiveRequest{
				RepoPath: "r", VmName: "web", DiskName: "root", Timestamp: restoreTS, TargetPath: c.target,
			}, &progressStream[pb.RestoreLiveProgress]{ctx: ctx})
			requireNothingCreated(t, err, c.target, c.created)
		})
	}
}

func TestReplicateVolume_AdminTargetInDaemonStateIsRefused(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	promotedVMInPool(t, s, victimDisk(t))
	for name, c := range daemonStateTargets(t, s.dataDir) {
		t.Run(name, func(t *testing.T) {
			rec := &streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()}
			err := s.ReplicateVolume(&pb.ReplicateVolumeRequest{
				VmName: "pr", DiskName: "root", TargetPool: "dr", TargetPath: c.target,
			}, rec)
			requireNothingCreated(t, err, c.target, c.created)
		})
	}
}
