package grpcapi

import (
	"context"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/storage"
)

// countMountInfoReads counts every read of the mount table, serving read.
func countMountInfoReads(t testing.TB, read func() ([]byte, error)) *atomic.Int64 {
	t.Helper()
	var n atomic.Int64
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) {
		n.Add(1)
		return read()
	}))
	return &n
}

const onceMountInfo = "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n" +
	"23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:2 - proc proc rw\n"

// multiPoolServer is a server whose host has the replica pool "dr" and three
// other directory pools, as a multi-disk VM's host does.
func multiPoolServer(t testing.TB) *Server {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	s := &Server{hostName: "test-host", pkiDir: "/etc/litevirt/pki", db: db, events: events.NewBus()}
	for _, p := range []string{"dr", "p1", "p2", "p3"} {
		if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
			HostName: s.hostName, Name: p, Driver: "dir", Target: t.TempDir(), State: "active",
		}); err != nil {
			t.Fatalf("UpsertStoragePool: %v", err)
		}
	}
	return s
}

// One replica pool resolution, and one pool write check, read the mount
// table once: the dead-NFS bounds judge every path of it against that one
// snapshot, not a fresh read per bounded call.
func TestPoolWriteCheck_ReadsTheMountTableOncePerOperation(t *testing.T) {
	s := multiPoolServer(t)
	n := countMountInfoReads(t, func() ([]byte, error) { return []byte(onceMountInfo), nil })
	ctx := context.Background()

	n.Store(0)
	if _, err := s.replicaPoolDir(ctx, "dr"); err != nil {
		t.Fatalf("replicaPoolDir: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("replicaPoolDir read the mount table %d times, want 1", got)
	}

	ref, ok := s.resolvePool(ctx, "dr")
	if !ok {
		t.Fatal("pool dr not resolved")
	}
	n.Store(0)
	if err := s.checkPoolForWrite(ctx, "dr", ref); err != nil {
		t.Fatalf("checkPoolForWrite: %v", err)
	}
	if got := n.Load(); got != 1 {
		t.Errorf("checkPoolForWrite read the mount table %d times, want 1", got)
	}
}

// The snapshot is one operation's: a mount made, or gone, between two
// operations is what the second one judges by.
func TestPoolWriteCheck_SeesTheMountTableAsItIsAtEachOperation(t *testing.T) {
	s := multiPoolServer(t)
	ctx := context.Background()
	ref, ok := s.resolvePool(ctx, "dr")
	if !ok {
		t.Fatal("pool dr not resolved")
	}
	var cur atomic.Value
	cur.Store(onceMountInfo)
	n := countMountInfoReads(t, func() ([]byte, error) { return []byte(cur.Load().(string)), nil })
	weak := onceMountInfo + "100 22 0:50 / " + ref.Target + " rw,relatime - nfs4 10.0.0.21:/srv/lv rw\n"

	if err := s.checkPoolForWrite(ctx, "dr", ref); err != nil {
		t.Fatalf("with no mount at the pool: %v", err)
	}
	cur.Store(weak)
	if err := s.checkPoolForWrite(ctx, "dr", ref); err == nil || !strings.Contains(err.Error(), "nosuid") {
		t.Errorf("an NFS mount without nosuid made at the pool since the last check = %v, want it refused", err)
	}
	cur.Store(onceMountInfo)
	if err := s.checkPoolForWrite(ctx, "dr", ref); err != nil {
		t.Errorf("with that mount gone again: %v", err)
	}
	if got := n.Load(); got != 3 {
		t.Errorf("three checks read the mount table %d times, want 3", got)
	}
}

// BenchmarkReplicaPoolDir resolves a replica pool on a host with four
// directory pools against this host's real mount table, and reports the
// mount table reads per resolution.
func BenchmarkReplicaPoolDir(b *testing.B) {
	s := multiPoolServer(b)
	n := countMountInfoReads(b, func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") })
	ctx := context.Background()
	b.ResetTimer()
	n.Store(0)
	for range b.N {
		if _, err := s.replicaPoolDir(ctx, "dr"); err != nil {
			b.Fatalf("replicaPoolDir: %v", err)
		}
	}
	b.ReportMetric(float64(n.Load())/float64(b.N), "mountinfo-reads/op")
}
