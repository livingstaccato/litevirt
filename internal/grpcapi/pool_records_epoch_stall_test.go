package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/storage"
)

// Round 2 R1-I1: one pool whose store does not answer leaves the records
// epoch unknown only for the store it was recorded on. Every other store
// keeps its epoch, so an unrecorded file made there after it is still not
// taken as a replica by its name.
//
// Mutation "any unjudged pool makes every epoch unknown" (round 1) — the
// healthy store's epoch is unknown and the planted file is taken: red.
func TestStoreRecordsEpoch_AStalledPoolLeavesOtherStoresChecked(t *testing.T) {
	ctx := context.Background()
	healthy, mnt := t.TempDir(), t.TempDir()
	stalled := filepath.Join(mnt, "pool")
	if err := os.MkdirAll(stalled, 0o755); err != nil {
		t.Fatal(err)
	}
	overrideMounts(t, nfsMountLine(healthy, "nas:/shared"), nfsMountLine(mnt, "nas2:/a"))
	var dead atomic.Bool
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	t.Cleanup(storage.OverridePathResolverForTest(func(p string) string {
		if dead.Load() && pathWithin(stalled, p) {
			<-release
		}
		return p
	}))
	setFor(t, &poolRecordsEpochTTL, 0)
	setFor(t, &poolRecordsEpochNegTTL, 0)

	h1 := newPoolTestServer(t)
	h1.hostName = "h1"
	h2 := &Server{hostName: "h2", dataDir: t.TempDir(), db: h1.db, virt: libvirtfake.New(), events: events.NewBus()}
	h2.images = image.NewStore(h2.dataDir)
	h1.db.SetClusterPolicyGate(func() bool { return true })
	for _, h := range []string{"h1", "h2"} {
		if err := corrosion.InsertHost(ctx, h1.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
		upsertPool(t, h1, corrosion.StoragePoolRecord{HostName: h, Name: "shared", Driver: "dir", Target: healthy,
			Options: map[string]string{"nfs_export": "nas:/shared"}})
	}
	upsertPool(t, h1, corrosion.StoragePoolRecord{HostName: "h1", Name: "stalled", Driver: "dir", Target: stalled,
		Options: map[string]string{"nfs_export": "nas2:/a/pool"}})
	h1.SweepStaleStaging(ctx)
	h2.SweepStaleStaging(ctx)

	idHealthy, idStalled := sharedStoreOf(healthy).ID, sharedStoreOf(stalled).ID
	if _, ok := h1.storeRecordsEpoch(ctx, idHealthy); !ok {
		t.Fatal("setup: no records epoch for the healthy store")
	}

	dead.Store(true) // the stalled pool's server stops answering
	if _, ok := h1.storeRecordsEpoch(ctx, idHealthy); !ok {
		t.Fatal("a stall on another pool left the healthy store's records epoch unknown")
	}
	if _, ok := h1.storeRecordsEpoch(ctx, idStalled); ok {
		t.Fatal("the stalled pool's own store kept an epoch while which pools are on it cannot be told")
	}
	p := filepath.Join(healthy, "cvm-root-"+stampAgo(0)+".qcow2")
	writeQcow2(t, p)
	if h1.isLegacyUnrecorded(ctx, p) {
		t.Fatal("an unrecorded file on the healthy store, made after its epoch, was taken by its name during another pool's stall")
	}
}
