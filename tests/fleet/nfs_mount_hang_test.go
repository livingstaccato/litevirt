// Fleet scenario for a mount of an nfs pool's export against a server that
// does not answer (lab 2 F-3): what the other nodes see while it runs.

package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/storage"
)

// F-3: while the owner's mount of an nfs pool's export hangs (its server
// does not answer), every node sees the pool degraded with the reason, not
// active with no condition until the mount gives up; once the server answers
// and the export is mounted, active and resolved everywhere.
func TestFleet_AnNFSMountThatHangsIsDegradedEverywhereWhileItRuns(t *testing.T) {
	mt := &rebootedMounts{dirs: map[string]string{}}
	answer := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-answer:
		default:
			close(answer)
		}
	})
	t.Cleanup(storage.OverrideNosymfollowSupportForTest(false))
	t.Cleanup(storage.OverrideMountInfoForTest(mt.info))
	t.Cleanup(storage.OverrideNFSMountCommandForTest(func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "mount" {
			select {
			case <-answer:
			case <-ctx.Done():
				return []byte("mount.nfs: Connection timed out"), ctx.Err()
			}
		}
		return mt.run(ctx, name, args...)
	}))
	t.Cleanup(grpcapi.OverrideNFSMountSlowAfterForTest(200 * time.Millisecond))
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 1014})
	owner, peer := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	const source = "10.9.9.31:/srv/lv"
	if err := corrosion.UpsertStoragePool(ctx, owner.DB, corrosion.StoragePoolRecord{
		HostName: owner.Name, Name: "hung", Driver: "nfs", Source: source, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	dir := storage.NFSPoolMountDir(filepath.Join(c.tmpRoot, owner.Name, "data"), storage.Config{Driver: "nfs", Source: source})
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stateOnPeer := func() string {
		resp, err := c.SelfClient(peer).ListStoragePools(ctx, &pb.ListStoragePoolsRequest{})
		if err != nil {
			return ""
		}
		for _, p := range resp.Pools {
			if p.Host == owner.Name && p.Name == "hung" {
				return p.State
			}
		}
		return ""
	}
	conditionOnPeer := func() (corrosion.HealthCondition, bool) {
		cond, ok, err := corrosion.GetHealthCondition(ctx, peer.DB, "nfs_pool", "nfs_mount_missing", "host", "hung@"+owner.Name)
		return cond, ok && err == nil
	}

	pass := make(chan struct{})
	go func() {
		owner.Server.ReconcileNFSMounts(ctx)
		close(pass)
	}()
	eventually(t, 20*time.Second, "the peer to see the pool degraded while its mount runs", func() bool {
		cond, ok := conditionOnPeer()
		return stateOnPeer() == "degraded" && ok && cond.Lifecycle != corrosion.ConditionResolved &&
			strings.Contains(cond.Evidence, "has been running since")
	})
	// The owner still answers while its mount hangs.
	if _, err := c.PeerClient(peer, owner).ListStoragePools(ctx, &pb.ListStoragePoolsRequest{}); err != nil {
		t.Fatalf("the owner did not answer while its mount hung: %v", err)
	}

	close(answer)
	select {
	case <-pass:
	case <-time.After(20 * time.Second):
		t.Fatal("the pass did not finish once the server answered")
	}
	eventually(t, 20*time.Second, "the peer to see the pool active and the condition resolved", func() bool {
		cond, ok := conditionOnPeer()
		return stateOnPeer() == "active" && ok && cond.Lifecycle == corrosion.ConditionResolved
	})
}
