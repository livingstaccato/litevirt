package grpcapi

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func setFor[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// m3: on a new cluster the replicated rows are not writable when the hosts
// first start (failover_scope_v1 latches later). The marks dropped then are
// written once they are, so the records epoch forms without a restart.
func TestPoolRound8_ANewClusterFormsTheRecordsEpoch(t *testing.T) {
	dir := t.TempDir()
	overrideMounts(t, nfsMountLine(dir, "nas:/shared"))
	setFor(t, &poolRecordsMarkInterval, 10*time.Millisecond)
	setFor(t, &poolRecordsEpochNegTTL, 0)
	h1 := newPoolTestServer(t)
	h1.hostName = "h1"
	h2 := &Server{hostName: "h2", dataDir: t.TempDir(), db: h1.db, virt: libvirtfake.New(), events: events.NewBus()}
	h2.images = image.NewStore(h2.dataDir)
	var latched atomic.Bool
	h1.db.SetClusterPolicyGate(latched.Load)
	for _, h := range []string{"h1", "h2"} {
		if err := corrosion.InsertHost(context.Background(), h1.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
		upsertPool(t, h1, corrosion.StoragePoolRecord{HostName: h, Name: "shared", Driver: "dir", Target: dir,
			Options: map[string]string{"nfs_export": "nas:/shared"}})
	}
	ctx, cancel := context.WithCancel(context.Background())
	var markers sync.WaitGroup
	t.Cleanup(func() { cancel(); markers.Wait() }) // before the overrides are undone
	for _, h := range []*Server{h1, h2} {
		h.SweepStaleStaging(ctx) // first start: nothing can be marked yet
		markers.Go(func() { h.RunPoolRecordsMarker(ctx) })
	}
	id := sharedStoreOf(dir).ID
	if _, ok := h1.storeRecordsEpoch(ctx, id); ok {
		t.Fatal("an epoch formed before the rows were writable")
	}
	latched.Store(true)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ok := h2.storeRecordsEpoch(ctx, id); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the records epoch never formed after failover_scope_v1 latched")
		}
		time.Sleep(20 * time.Millisecond)
	}
	p := filepath.Join(dir, "cvm-root-"+stampAgo(0)+".qcow2")
	writeQcow2(t, p)
	if h2.isLegacyUnrecorded(ctx, p) {
		t.Errorf("an unrecorded file made after the epoch is taken by its name")
	}
}

// m4: a host does not keep its own computation of the epoch forever; it
// converges on the replicated row every host reads.
func TestPoolRound8_HostsConvergeOnTheEpochRow(t *testing.T) {
	h1, _, dir := twoHostsOnOneExport(t)
	id := sharedStoreOf(dir).ID
	first, ok := h1.storeRecordsEpoch(context.Background(), id)
	if !ok {
		t.Fatal("no epoch")
	}
	later := first.Add(time.Hour).UTC()
	if err := corrosion.SetPoolRecord(context.Background(), h1.db, "pool_records_epoch", later.Format(time.RFC3339Nano), "h2"); err != nil {
		t.Fatal(err)
	}
	setFor(t, &poolRecordsEpochTTL, 0)
	if got, _ := h1.storeRecordsEpoch(context.Background(), id); !got.Equal(later) {
		t.Errorf("h1's epoch = %s after the row became %s", got, later)
	}
}
