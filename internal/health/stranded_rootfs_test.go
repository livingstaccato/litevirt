package health

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/lxc"
)

// A host that comes back after a relocation moved its container away names
// the rootfs it still holds, touching nothing, and clears the record once
// no container of that name is there.
//
// Mutations: skip the path fill-in — the record never names the rootfs and
// the test is red; never clear — the record stays open once the container is
// gone and the test is red.
func TestTendStrandedRootfs_NamesTheRootfsThenClearsWhenGone(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	if _, err := RecordStrandedRootfs(ctx, db, "coord", "web", "node-a", "node-b", "image-recreate", time.Now()); err != nil {
		t.Fatal(err)
	}
	rt := newFakeCtRuntime()
	rt.states["web"] = lxc.StateStopped
	cc := NewContainerChecker("node-a", db, rt)
	cc.SetContainersRoot(t.TempDir())
	cc.SetContainerLxcpath("/srv/lxc")

	cc.tendStrandedRootfs(ctx, map[string]bool{"web": true})
	got, err := StrandedRootfsOf(ctx, db, "web")
	if err != nil || len(got) != 1 || got[0].Path != lxc.RootfsPath("/srv/lxc", "web") || !strings.Contains(got[0].Detail, got[0].Path) {
		t.Fatalf("records = %+v (err %v), want the rootfs path named", got, err)
	}
	if rt.states["web"] != lxc.StateStopped {
		t.Fatal("the tend touched the container")
	}

	cc.tendStrandedRootfs(ctx, map[string]bool{})
	if got, _ := StrandedRootfsOf(ctx, db, "web"); len(got) != 0 {
		t.Fatalf("records after the container is gone = %+v, want none open", got)
	}
}
