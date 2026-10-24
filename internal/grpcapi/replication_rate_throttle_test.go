package grpcapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// countingLimiter counts what it is charged.
type countingLimiter struct {
	mu sync.Mutex
	n  int64
}

func (c *countingLimiter) WaitN(_ context.Context, n int) error {
	c.mu.Lock()
	c.n += int64(n)
	c.mu.Unlock()
	return nil
}

func (c *countingLimiter) charged() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// throttleCounter wraps every limiter a run is handed and counts the bytes
// charged against each shared throttle.
type throttleCounter struct {
	mu   sync.Mutex
	by   map[*pbsstore.Throttle]int64
	runs int
}

func (tc *throttleCounter) wrap(_ string, t *pbsstore.Throttle) pbsstore.RateLimiter {
	tc.mu.Lock()
	tc.runs++
	tc.mu.Unlock()
	return limiterFunc(func(ctx context.Context, n int) error {
		tc.mu.Lock()
		if tc.by == nil {
			tc.by = map[*pbsstore.Throttle]int64{}
		}
		tc.by[t] += int64(n)
		tc.mu.Unlock()
		return nil
	})
}

type limiterFunc func(ctx context.Context, n int) error

func (f limiterFunc) WaitN(ctx context.Context, n int) error { return f(ctx, n) }

func setRate(t *testing.T, s *Server, schedule, repo string, bps int64) {
	t.Helper()
	if err := corrosion.SetReplicationRate(context.Background(), s.db,
		capabilities.GrantForTest(t, capabilities.FeatureReplicationRate), schedule, repo, bps, "test"); err != nil {
		t.Fatal(err)
	}
}

// Every run of one schedule on this host shares ONE throttle: two runs at
// once, and a fan-out's VMs (charged to the schedule row they came from). A
// changed rate replaces it; a cleared one leaves the run unlimited.
//
// Mutation: build a new throttle on every call — the runs get two.
func TestReplicationThrottle_SharedPerScheduleRow(t *testing.T) {
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	ctx := context.Background()
	setRate(t, s, "web1", "dr", 1<<20)
	setRate(t, s, "@pool:fast", "dr", 2<<20)

	get := func(sched corrosion.BackupScheduleRecord) *pbsstore.Throttle {
		l := s.scheduleLimiter(ctx, sched)
		th, _ := l.(*pbsstore.Throttle)
		return th
	}
	vm := corrosion.BackupScheduleRecord{VMName: "web1", Repo: "dr", Type: "replication"}
	var wg sync.WaitGroup
	got := make([]*pbsstore.Throttle, 2)
	for i := range got {
		wg.Add(1)
		go func() { defer wg.Done(); got[i] = get(vm) }()
	}
	wg.Wait()
	if got[0] == nil || got[0] != got[1] || got[0].Rate() != 1<<20 {
		t.Fatalf("two runs of one schedule got %p and %p (rate %d), want one shared 1MiB/s throttle", got[0], got[1], got[0].Rate())
	}
	a := get(corrosion.BackupScheduleRecord{VMName: "vm-a", Origin: "@pool:fast", Repo: "dr"})
	b := get(corrosion.BackupScheduleRecord{VMName: "vm-b", Origin: "@pool:fast", Repo: "dr"})
	if a == nil || a != b || a.Rate() != 2<<20 || a == got[0] {
		t.Fatalf("a fan-out's VMs got %p and %p, want the schedule row's one throttle", a, b)
	}

	setRate(t, s, "web1", "dr", 4<<20)
	if th := get(vm); th == nil || th == got[0] || th.Rate() != 4<<20 {
		t.Fatalf("after a rate change the run got %p rate %d, want a new 4MiB/s throttle", th, th.Rate())
	}
	setRate(t, s, "web1", "dr", 0)
	if l := s.scheduleLimiter(ctx, vm); l != nil {
		t.Fatalf("a cleared rate gave the run limiter %v", l)
	}
}

// A schedule with no rate runs with no limiter at all: the wrap is never
// asked, and the context carries nothing to charge.
func TestReplicationThrottle_NoRateMeansNoLimiter(t *testing.T) {
	s := testServer(t)
	tc := &throttleCounter{}
	s.SetReplicationLimiterWrapForTest(tc.wrap)
	ctx := context.Background()
	if l := s.scheduleLimiter(ctx, corrosion.BackupScheduleRecord{VMName: "web1", Repo: "dr"}); l != nil {
		t.Fatalf("no rate gave limiter %v", l)
	}
	if tc.runs != 0 {
		t.Fatalf("the wrap was asked %d times for an unlimited run", tc.runs)
	}
	if replicationLimiter(withReplicationLimiter(ctx, nil)) != nil {
		t.Fatal("an unlimited run's context carries a limiter")
	}
	if err := chargeReplication(ctx, 1<<20); err != nil {
		t.Fatal(err)
	}
}

// legPeer is a receiver on this build that records the data bytes each
// stream carries.
type legPeer struct {
	pb.LiteVirtClient
	mu   sync.Mutex
	sent int64
}

func (p *legPeer) add(n int) {
	p.mu.Lock()
	p.sent += int64(n)
	p.mu.Unlock()
}

func (p *legPeer) ListReplicas(context.Context, *pb.ListReplicasRequest, ...grpc.CallOption) (*pb.ListReplicasResponse, error) {
	return &pb.ListReplicasResponse{}, nil
}

func (p *legPeer) ListStoragePoolContents(context.Context, *pb.ListStoragePoolContentsRequest, ...grpc.CallOption) (*pb.ListStoragePoolContentsResponse, error) {
	return &pb.ListStoragePoolContentsResponse{}, nil
}

func (p *legPeer) PushReplica(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaRequest, pb.PushReplicaResponse], error) {
	return &answerStream[pb.PushReplicaRequest, pb.PushReplicaResponse]{
		on: func(m *pb.PushReplicaRequest) { p.add(len(m.GetChunk())) }, resp: &pb.PushReplicaResponse{}}, nil
}

func (p *legPeer) PushReplicaIncrement(context.Context, ...grpc.CallOption) (grpc.ClientStreamingClient[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse], error) {
	return &answerStream[pb.PushReplicaIncrementRequest, pb.PushReplicaIncrementResponse]{
		on: func(m *pb.PushReplicaIncrementRequest) { p.add(len(m.GetData())) }, resp: &pb.PushReplicaIncrementResponse{ReplicaRecorded: true}}, nil
}

type answerStream[Req, Resp any] struct {
	grpc.ClientStream
	on   func(*Req)
	resp *Resp
}

func (c *answerStream[Req, Resp]) Send(m *Req) error            { c.on(m); return nil }
func (c *answerStream[Req, Resp]) CloseAndRecv() (*Resp, error) { return c.resp, nil }

// Each of the two legs that send a run's data to a peer — the recorded full
// replica and the incremental push — charges the run's limiter exactly the
// data bytes it sends.
//
// Mutations: remove the charge from any one leg (applyIncrementRemote's
// forEachExtentChunk callback among them) — that leg charges 0.
func TestReplicationLegs_ChargeExactlyTheBytesSent(t *testing.T) {
	f := newPoolFixture(t)
	peer := &legPeer{}
	f.s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }

	const mib = 1 << 20
	data := make([]byte, 3*mib+12345)
	_, _ = rand.Read(data)
	clear(data[mib : 2*mib]) // one all-zero chunk
	file := filepath.Join(t.TempDir(), "scratch")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20260910-000000", "raw")
	extents := [][2]int64{{0, int64(len(data))}}

	legs := []struct {
		name string
		run  func(ctx context.Context) error
	}{
		{"streamReplicaToPool", func(ctx context.Context) error {
			_, err := streamReplicaToPool(ctx, peer, file, "dr", "peer", rec)
			return err
		}},
		{"applyIncrementRemote", func(ctx context.Context) error {
			return f.s.applyIncrementRemote(ctx, "peer", "dr", rec, "", int64(len(data)), bytes.NewReader(data), extents)
		}},
	}
	for _, leg := range legs {
		peer.sent = 0
		lim := &countingLimiter{}
		if err := leg.run(withReplicationLimiter(context.Background(), lim)); err != nil {
			t.Fatalf("%s: %v", leg.name, err)
		}
		if peer.sent == 0 || lim.charged() != peer.sent {
			t.Errorf("%s charged %d for %d data bytes sent", leg.name, lim.charged(), peer.sent)
		}
	}
}

// A limiter's refusal (the run cancelled while it waits) stops the leg before
// the chunk is sent.
func TestReplicationLegs_AChargeThatFailsSendsNothing(t *testing.T) {
	peer := &legPeer{}
	file := filepath.Join(t.TempDir(), "scratch")
	if err := os.WriteFile(file, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	refuse := limiterFunc(func(context.Context, int) error { return status.Error(codes.Canceled, "run cancelled") })
	ctx := withReplicationLimiter(context.Background(), refuse)
	rec := newReplicaRecord("a", "web", "1", "web/dr", "20260910-000000", "raw")
	if _, err := streamReplicaToPool(ctx, peer, file, "dr", "peer", rec); status.Code(err) != codes.Canceled || peer.sent != 0 {
		t.Fatalf("err=%v sent=%d, want the charge's error and nothing sent", err, peer.sent)
	}
}

// A container run's sends are paced by the schedule's shared throttle AND the
// repo's, combined, so the lower rate wins; its archive read by the repo's
// only. Two runs of one schedule charge the same throttle, which is charged
// their sum.
//
// Mutation: build the send limiter with backupRateLimit(ctx, repo, rate) — a
// throttle per run — the schedule's shared throttle is charged nothing.
func TestContainerReplicationLimiters_SharedAndCombined(t *testing.T) {
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	tc := &throttleCounter{}
	s.SetReplicationLimiterWrapForTest(tc.wrap)
	ctx := context.Background()
	sched := corrosion.BackupScheduleRecord{VMName: corrosion.ContainerScheduleKey("_default", "web"), Scope: "container", Repo: "dr", Type: "replication"}
	setRate(t, s, sched.VMName, "dr", 8<<20)

	var wg sync.WaitGroup
	for _, n := range []int{100 << 10, 300 << 10} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, send := s.containerReplicationLimiters(ctx, sched, "dr")
			if send == nil {
				t.Error("a limited schedule's run has no send limiter")
				return
			}
			_ = send.WaitN(ctx, n)
		}()
	}
	wg.Wait()
	if len(tc.by) != 1 {
		t.Fatalf("the runs charged %d throttles, want the schedule's one", len(tc.by))
	}
	for th, n := range tc.by {
		if n != 400<<10 || th.Rate() != 8<<20 {
			t.Fatalf("the schedule's throttle (rate %d) was charged %d, want both runs' 400KiB", th.Rate(), n)
		}
	}

	// The lower rate wins, whichever side it is on: at 64KiB/s, 96KiB takes
	// about 1.5 s; both sides fast, it does not.
	s.SetReplicationLimiterWrapForTest(nil)
	timed := func(schedBps, repoBps int64) time.Duration {
		setRate(t, s, sched.VMName, "dr", schedBps)
		s.SetBackupBandwidthLimits(map[string]int64{"dr": repoBps})
		read, send := s.containerReplicationLimiters(ctx, sched, "dr")
		if read == nil || send == nil {
			t.Fatalf("limiters read=%v send=%v", read, send)
		}
		start := time.Now()
		for range 3 {
			if err := send.WaitN(ctx, 32<<10); err != nil {
				t.Fatal(err)
			}
		}
		return time.Since(start)
	}
	if d := timed(pbsstore.MinRate, 1<<30); d < time.Second {
		t.Errorf("schedule at 64KiB/s under a fast repo: 96KiB took %v", d)
	}
	sched.VMName = corrosion.ContainerScheduleKey("_default", "web2") // a fresh schedule throttle
	if d := timed(1<<30, pbsstore.MinRate); d < time.Second {
		t.Errorf("a fast schedule under a 64KiB/s repo: 96KiB took %v", d)
	}
	sched.VMName = corrosion.ContainerScheduleKey("_default", "web3")
	if d := timed(1<<30, 1<<30); d > 500*time.Millisecond {
		t.Errorf("both fast: 96KiB took %v", d)
	}
}
