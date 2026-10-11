package grpcapi

import (
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// timedPushBackup runs a stopped-VM (disk-file) backup of a 1 MiB disk and
// returns how long it took.
func timedPushBackup(t *testing.T, s *Server, repo *pbsstore.Repo, diskPath, repoRef string, jobBps int64, ts string) time.Duration {
	t.Helper()
	disk := &corrosion.DiskRecord{VMName: "bwvm", DiskName: "data", Path: diskPath, StorageType: "local"}
	req := &pb.BackupSnapshotRequest{VmName: "bwvm", DiskName: "data", RepoPath: repoRef, BwlimitBytesPerSec: jobBps}
	start := time.Now()
	if _, err := s.pushBackup(context.Background(), repo, disk, req, ts,
		func(*pb.BackupSnapshotProgress) error { return nil }, `{"name":"bwvm"}`); err != nil {
		t.Fatalf("pushBackup: %v", err)
	}
	return time.Since(start)
}

// A repo's backup_bwlimits limit applies whether the job names the repo by its
// logical name (an RPC) or by its on-disk path (the scheduler resolves the
// name before it calls pushBackup); a job's own limit applies on its own.
// 1 MiB at 512 KiB/s is >= 2s.
func TestPushBackup_BandwidthLimits(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repoDir := filepath.Join(t.TempDir(), "repo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	diskPath := filepath.Join(t.TempDir(), "data.img")
	buf := make([]byte, 1<<20)
	_, _ = rand.Read(buf)
	if err := os.WriteFile(diskPath, buf, 0o640); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"main": repoDir})

	if d := timedPushBackup(t, s, repo, diskPath, "main", 0, "2026-10-10T01:00:00Z"); d > 1500*time.Millisecond {
		t.Fatalf("unlimited backup of 1 MiB took %v; too slow for the assertions below", d)
	}

	s.SetBackupBandwidthLimits(map[string]int64{"main": 512 << 10})
	for i, ref := range []string{"main", repoDir} {
		d := timedPushBackup(t, s, repo, diskPath, ref, 0, []string{"2026-10-10T02:00:00Z", "2026-10-10T03:00:00Z"}[i])
		if d < 2*time.Second {
			t.Fatalf("backup into repo %q limited to 512KiB/s took %v for 1 MiB; the target limit was not applied", ref, d)
		}
	}

	s.SetBackupBandwidthLimits(nil)
	if d := timedPushBackup(t, s, repo, diskPath, "main", 512<<10, "2026-10-10T04:00:00Z"); d < 2*time.Second {
		t.Fatalf("backup with a 512KiB/s job limit took %v for 1 MiB", d)
	}
}

func TestForwardRate_LowerOfJobAndTarget(t *testing.T) {
	s := testServer(t)
	s.SetBackupRepos(map[string]string{"main": "/srv/main"})
	s.SetBackupBandwidthLimits(map[string]int64{"main": 1 << 20})
	ctx := context.Background()
	for _, tc := range []struct {
		repo string
		job  int64
		want int64
	}{
		{"main", 0, 1 << 20},
		{"main", 512 << 10, 512 << 10},
		{"main", 4 << 20, 1 << 20},
		{"/srv/main", 0, 1 << 20},
		{"other", 0, 0},
		{"other", 700 << 10, 700 << 10},
	} {
		if got := s.forwardRate(ctx, tc.repo, tc.job); got != tc.want {
			t.Errorf("forwardRate(%q, %d) = %d, want %d", tc.repo, tc.job, got, tc.want)
		}
	}
}

// m-8: the repo's limit applies under any spelling of its path.
func TestTargetThrottle_CanonicalPath(t *testing.T) {
	s := testServer(t)
	dir := filepath.Join(t.TempDir(), "repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"main": dir})
	s.SetBackupBandwidthLimits(map[string]int64{"main": 1 << 20})
	ctx := context.Background()
	for _, spelling := range []string{dir, dir + "/", filepath.Dir(dir) + "//repo", dir + "/../repo", alias} {
		if got := s.targetRate(ctx, spelling); got != 1<<20 {
			t.Errorf("%q: target rate %d, want the repo's limit", spelling, got)
		}
	}
}
