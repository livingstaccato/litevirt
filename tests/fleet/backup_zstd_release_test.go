package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// TestFleet_BackupZstd_GatedOnTheReleaseToken drives the real SetBackupRepoCompression
// RPC against real checkers: while a host is on the previous build the release
// token cannot latch and a zstd repository is refused with the release text and
// not created; once every host is on this build the use is recorded, acknowledged
// by every replica, and only then does repo.json say zstd.
func TestFleet_BackupZstd_GatedOnTheReleaseToken(t *testing.T) {
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1301)
	a, old := c.Nodes[0], c.Nodes[2]
	cli := c.SelfClient(a)
	repo := filepath.Join(t.TempDir(), "repo")
	req := &pb.SetBackupRepoCompressionRequest{Repo: repo, Compression: "zstd", Init: true}

	old.Server.SetWALQuarantined(func() bool { return true })
	_, err := cli.SetBackupRepoCompression(ctx, req)
	want := "the cluster upgrade must finish first (backup_zstd needs " + capabilities.ReleaseToken + ")"
	if status.Code(err) != codes.FailedPrecondition || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("zstd repo with %s on the old build: %v, want %q", old.Name, err, want)
	}
	if _, serr := os.Stat(filepath.Join(repo, "repo.json")); serr == nil {
		t.Fatal("a repository was created although the release token had not latched")
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, "backup_zstd") {
			t.Fatalf("%s holds a backup_zstd use that nothing wrote", n.Name)
		}
	}
	old.Server.SetWALQuarantined(old.DB.WALQuarantined)
	var resp *pb.SetBackupRepoCompressionResponse
	eventually(t, 15*time.Second, "the zstd repository to be created on a uniform fleet", func() bool {
		resp, err = cli.SetBackupRepoCompression(ctx, req)
		return err == nil
	})
	if resp.GetCompression() != "zstd" || resp.GetSchemaVersion() != 2 || resp.GetHost() != a.Name {
		t.Fatalf("response %+v, want zstd schema 2 on %s", resp, a.Name)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, "backup_zstd") {
			t.Fatalf("%s does not hold the backup_zstd record although the repo was written", n.Name)
		}
	}
	r, err := pbsstore.Open(repo)
	if err != nil || r.Compression() != pbsstore.CompressionZstd {
		t.Fatalf("repo on disk: %v", err)
	}
}
