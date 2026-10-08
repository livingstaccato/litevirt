package grpcapi

import (
	"context"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/storage"
)

// NC1: a kernel upgrade on h1 changes the CephFS f_fsid it reports after h2
// had counted both hosts on the old one. h1's replicas made since are still
// matched on h2.
func TestPoolRound9_ACephFSFsidChangeKeepsReplicasPromotable(t *testing.T) {
	fsid := map[string]string{"h1": "00000000aaaaaaaa", "h2": "00000000aaaaaaaa"}
	cur := "h1"
	t.Cleanup(storage.OverrideStatfsForTest(func(string) (uint32, string, error) { return 0x00c36400, fsid[cur], nil }))
	h1, h2, ms := twoHostsOnMount(t, func(host, dir string) string {
		cur = host
		return fmt.Sprintf("41 1 0:61 / %s rw,nosuid,nodev,noexec,relatime - ceph 10.0.0.1:6789:/vols/shared rw,name=admin", dir)
	}, nil)
	ms.as("h2")
	if _, ok := h2.storeRecordsEpoch(context.Background(), sharedStoreOf(ms.dir).ID); !ok {
		t.Fatal("no epoch before the upgrade")
	}
	fsid["h1"] = "00000001aaaaaaaa"
	ms.as("h1")
	h1.MarkPoolRecords(context.Background())
	time.Sleep(10 * time.Millisecond)
	replicateOnH1(t, h1, ms)
	reps := stampedReplicas(t, ms.dir, "cvm-root")
	setFor(t, &poolRecordsEpochNegTTL, 0)
	setFor(t, &poolRecordsEpochTTL, 0)
	ms.as("h2")
	k := replicaKey{VM: "cvm", Disk: "root", Project: "bravo"}
	if got := h2.replicaNames(context.Background(), "shared", "", k, "", false); len(reps) != 1 || !slices.Equal(got, reps) {
		t.Errorf("h2 sees cvm's replicas %v, want h1's %v", got, reps)
	}
}
