package grpcapi

// Round 1 I-2: a shared store that does not answer is not "no identity" to a
// writer of pool file records: the record or marker fails (so the caller
// removes the file), and the host-stores row keeps its entry, Since and all.

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// deadStore is a dir pool below an NFS mount whose path resolution blocks
// while dead is set, as on a server that has stopped answering.
type deadStore struct {
	pool    string
	dead    atomic.Bool
	mu      sync.Mutex
	release chan struct{}
}

func installDeadStore(t *testing.T, s *Server) *deadStore {
	t.Helper()
	mnt := t.TempDir()
	d := &deadStore{pool: filepath.Join(mnt, "pool"), release: make(chan struct{})}
	if err := os.MkdirAll(d.pool, 0o755); err != nil {
		t.Fatal(err)
	}
	overrideMounts(t, nfsMountLine(mnt, "nas:/shared"))
	t.Cleanup(func() { d.answer() })
	t.Cleanup(storage.OverrideFSCallBoundForTest(300 * time.Millisecond))
	t.Cleanup(storage.OverridePathResolverForTest(func(p string) string {
		d.mu.Lock()
		rel := d.release
		d.mu.Unlock()
		if d.dead.Load() && pathWithin(d.pool, p) {
			<-rel
		}
		return p
	}))
	s.db.SetClusterPolicyGate(func() bool { return true })
	upsertPool(t, s, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "shared", Driver: "dir", Target: d.pool})
	return d
}

// answer lets every blocked resolution return and clears the mount's latch.
func (d *deadStore) answer() {
	d.dead.Store(false)
	d.mu.Lock()
	select {
	case <-d.release:
	default:
		close(d.release)
	}
	d.mu.Unlock()
}

func waitAnswering(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := storage.SharedStoreOfErr(dir); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s still does not answer", dir)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Mutation "shareRecord reads a timeout as no identity" — the record is
// skipped and the call succeeds: red.
func TestShareRecord_AStoreThatDoesNotAnswerFailsTheRecord(t *testing.T) {
	s := newPoolTestServer(t)
	d := installDeadStore(t, s)
	d.dead.Store(true)
	err := within(t, 10*time.Second, "shareRecord", func() error {
		return s.shareRecord(context.Background(), filepath.Join(d.pool, "web-root-x.qcow2"), poolUpload{Pool: "shared", Project: "p1"})
	})
	if err == nil || !storage.IsFSNoAnswer(err) || !strings.Contains(err.Error(), "cannot tell which shared store") {
		t.Fatalf("a record on a store that does not answer = %v; want a failure saying why", err)
	}
}

// Mutation "markUpload reads a timeout as no identity" — the upload goes
// ahead unmarked: red.
func TestMarkUpload_AStoreThatDoesNotAnswerFailsTheMark(t *testing.T) {
	s := newPoolTestServer(t)
	d := installDeadStore(t, s)
	d.dead.Store(true)
	err := within(t, 10*time.Second, "markUpload", func() error {
		return markUpload(filepath.Join(d.pool, "disk.iso"))
	})
	if err == nil || !storage.IsFSNoAnswer(err) {
		t.Fatalf("a marker on a store that does not answer = %v; want a failure", err)
	}
	if _, serr := os.Stat(filepath.Join(d.pool, uploadMarkerDir)); !os.IsNotExist(serr) {
		t.Fatalf("a marker directory was made on a store that did not answer: %v", serr)
	}
}

// Mutation "a pool that could not be judged is on no store" — the entry is
// rewritten empty and then again with a new Since, moving the records epoch:
// red.
func TestRefreshHostStores_AStallKeepsTheEntryAndItsSince(t *testing.T) {
	s := newPoolTestServer(t)
	d := installDeadStore(t, s)
	ctx := context.Background()
	entry := func() hostStoreEntry {
		t.Helper()
		v, _, err := corrosion.GetPoolRecord(ctx, s.db, hostStoresKey(s.hostName))
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]hostStoreEntry{}
		_ = json.Unmarshal([]byte(v), &m)
		return m["shared"]
	}
	if err := s.refreshHostStores(ctx); err != nil {
		t.Fatal(err)
	}
	before := entry()
	if len(before.IDs) != 1 || before.Since.IsZero() {
		t.Fatalf("entry before the stall: %+v; want the pool's store", before)
	}
	time.Sleep(20 * time.Millisecond)
	d.dead.Store(true)
	if err := within(t, 10*time.Second, "refreshHostStores", func() error { return s.refreshHostStores(ctx) }); err != nil {
		t.Fatal(err)
	}
	if got := entry(); !got.Since.Equal(before.Since) || len(got.IDs) != 1 || got.IDs[0] != before.IDs[0] {
		t.Fatalf("entry during the stall: %+v; want %+v kept", got, before)
	}
	d.answer()
	waitAnswering(t, d.pool)
	if err := s.refreshHostStores(ctx); err != nil {
		t.Fatal(err)
	}
	if got := entry(); !got.Since.Equal(before.Since) {
		t.Fatalf("entry after the stall: %+v; want Since %v kept (a stall is no move)", got, before.Since)
	}
}
