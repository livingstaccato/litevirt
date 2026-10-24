package fleet

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A replication schedule's bandwidth limit (lv replication schedule add
// --bwlimit) paces every leg that sends a run's data to its target. The schedule is created through the RPC, so the rate
// passes the release gate as an operator's would. The owner's shared
// throttle is wrapped to count what each run is charged; the target counts
// the data bytes it receives on every replica stream. The two must be equal,
// and not zero: charged bytes = bytes sent, not the disk's size.
//
// Mutation: drop the charge from one leg (streamReplicaToPool's or
// applyIncrementRemote's send) — that case charges less than the target
// received.

// byteCounter counts the data bytes a node receives on replica streams.
type byteCounter struct {
	mu sync.Mutex
	n  int64
	by map[string]int64
}

func (b *byteCounter) add(method string, n int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.by == nil {
		b.by = map[string]int64{}
	}
	b.n += int64(n)
	b.by[method] += int64(n)
}

func (b *byteCounter) reset() {
	b.mu.Lock()
	b.n, b.by = 0, nil
	b.mu.Unlock()
}

func (b *byteCounter) total() (int64, map[string]int64) {
	b.mu.Lock()
	defer b.mu.Unlock()
	by := map[string]int64{}
	for k, v := range b.by {
		by[k] = v
	}
	return b.n, by
}

type countingServerStream struct {
	grpc.ServerStream
	method string
	c      *byteCounter
}

func (s *countingServerStream) RecvMsg(m any) error {
	err := s.ServerStream.RecvMsg(m)
	if err != nil {
		return err
	}
	switch v := m.(type) {
	case *pb.PushReplicaRequest:
		s.c.add(s.method, len(v.GetChunk()))
	case *pb.UploadStoragePoolContentRequest:
		s.c.add(s.method, len(v.GetChunk()))
	case *pb.PushReplicaIncrementRequest:
		s.c.add(s.method, len(v.GetData()))
	}
	return nil
}

// countReceived arms n counting hooks on each replica stream method of node.
func countReceived(node *Node, c *byteCounter, n int) {
	for _, m := range []string{"PushReplica", "UploadStoragePoolContent", "PushReplicaIncrement"} {
		for range n {
			node.HookStream(m, func(srv any, ss grpc.ServerStream, handler grpc.StreamHandler) error {
				return handler(srv, &countingServerStream{ServerStream: ss, method: m, c: c})
			})
		}
	}
}

// rateReader is a backup session over data.
type rateReader struct {
	data    []byte
	extents [][2]int64
	incr    bool
}

func (r *rateReader) Size() int64                         { return int64(len(r.data)) }
func (r *rateReader) Incremental() bool                   { return r.incr }
func (r *rateReader) ChangedExtents() ([][2]int64, error) { return r.extents, nil }
func (r *rateReader) Close() error                        { return nil }
func (r *rateReader) ReadAt(p []byte, off int64) (int, error) {
	clear(p)
	if off < int64(len(r.data)) {
		copy(p, r.data[off:])
	}
	return len(p), nil
}

// rateSource opens a full session without a parent checkpoint and an
// incremental one (the first MiB dirty) with one.
type rateSource struct{ full, incr *rateReader }

func (s *rateSource) BeginBackup(_, _, parentCP, _ string) (grpcapi.BackupReader, error) {
	if parentCP != "" {
		return s.incr, nil
	}
	return s.full, nil
}
func (s *rateSource) GCCheckpoints(string, string, []string) error { return nil }
func (s *rateSource) DeleteCheckpoint(string, string) error        { return nil }

func TestReplicationRate_EveryLegChargesTheBytesItSends(t *testing.T) {
	for _, tc := range []struct {
		name        string
		incremental bool
	}{
		{"full", false},
		{"incremental", true},
	} {
		t.Run(tc.name, func(t *testing.T) { replicationRateScenario(t, tc.incremental) })
	}
}

func replicationRateScenario(t *testing.T, incremental bool) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	latchPITOverlay(t, c)
	ctx := context.Background()
	vmHost, replicaHost := c.Node("node-0"), c.Node("node-1")

	pool := filepath.Join(c.tmpRoot, replicaHost.Name, "data", "pools", "dr")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, replicaHost.DB, corrosion.StoragePoolRecord{
		HostName: replicaHost.Name, Name: "dr", Driver: "local", Target: pool, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(c.tmpRoot, vmHost.Name, "web-root-src.qcow2")
	if err := qcow2.Create(src, 4<<20, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(ctx, vmHost.DB, corrosion.VMRecord{
		Name: "web", HostName: vmHost.Name, State: "running", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{
		VMName: "web", DiskName: "root", HostName: vmHost.Name, Path: src, SizeBytes: 4 << 20, StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
	vmHost.Virt.SetState("web", libvirtfake.StateRunning)

	const mib = 1 << 20
	if incremental {
		data := make([]byte, 3*mib+4096)
		_, _ = rand.Read(data)
		clear(data[mib : 2*mib]) // a zero chunk
		vmHost.Server.SetBackupSource(&rateSource{
			full: &rateReader{data: data, extents: [][2]int64{{0, int64(len(data))}}},
			incr: &rateReader{data: data, extents: [][2]int64{{0, mib}}, incr: true},
		})
	}

	// The schedule, with its limit, through the operator's RPC.
	bw := int64(1 << 30)
	if _, err := c.SelfClient(vmHost).CreateReplicationSchedule(ctx, &pb.CreateReplicationScheduleRequest{
		Scope: "vm", VmName: "web", TargetPool: "dr", TargetHost: replicaHost.Name, Cron: "0 * * * *",
		Enabled: true, KeepReplicas: 3, Incremental: incremental, BwlimitBytesPerSec: &bw,
	}); err != nil {
		t.Fatalf("CreateReplicationSchedule with --bwlimit: %v", err)
	}
	var sched corrosion.BackupScheduleRecord
	rows, _ := corrosion.ListBackupSchedules(ctx, vmHost.DB)
	for _, r := range rows {
		if r.VMName == "web" && r.Repo == "dr" {
			sched = r
		}
	}
	if sched.VMName == "" {
		t.Fatal("the schedule was not stored")
	}

	var mu sync.Mutex
	charged := map[*pbsstore.Throttle]int64{}
	vmHost.Server.SetReplicationLimiterWrapForTest(func(_ string, th *pbsstore.Throttle) pbsstore.RateLimiter {
		if th.Rate() != bw {
			t.Errorf("the run's throttle is at %d B/s, want the schedule's %d", th.Rate(), bw)
		}
		return limiterOf(func(ctx context.Context, n int) error {
			mu.Lock()
			charged[th] += int64(n)
			mu.Unlock()
			return th.WaitN(ctx, n)
		})
	})

	// A hook is consumed by the call it serves, so every call of both runs
	// has one: two streams per method per run at most.
	recv := &byteCounter{}
	countReceived(replicaHost, recv, 8)
	runs := []time.Time{time.Now().Add(-10 * time.Minute), time.Now().Add(-5 * time.Minute)}
	for i, at := range runs {
		recv.reset()
		mu.Lock()
		clear(charged)
		mu.Unlock()
		if err := vmHost.Server.RunReplication(ctx, sched, at); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		got, by := recv.total()
		mu.Lock()
		var sum int64
		for _, n := range charged {
			sum += n
		}
		throttles := len(charged)
		mu.Unlock()
		if got == 0 {
			t.Fatalf("run %d: the target received no data (by stream: %v)", i, by)
		}
		if throttles != 1 || sum != got {
			t.Errorf("run %d: charged %d bytes against %d throttle(s); the target received %d (by stream: %v)", i, sum, throttles, got, by)
		}
		if by["UploadStoragePoolContent"] != 0 {
			t.Errorf("run %d: a replica was uploaded to the pool's top level: %v", i, by)
		}
		if incremental {
			// The first run is a full raw push of every extent; the second
			// sends the one dirty MiB.
			want := int64(3*mib + 4096)
			if i == 1 {
				want = mib
			}
			if got != want {
				t.Errorf("incremental run %d: the target received %d, want %d (by stream: %v)", i, got, want, by)
			}
		}
	}
}

type limiterOf func(ctx context.Context, n int) error

func (f limiterOf) WaitN(ctx context.Context, n int) error { return f(ctx, n) }
