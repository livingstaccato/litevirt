package grpcapi

import (
	"context"
	"math"
	"reflect"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func admissionCoordinatorServer(t *testing.T, cpu, memMiB int) *Server {
	t.Helper()
	s := testServer(t)
	s.hostName = "h1"
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "h1", Address: "127.0.0.1", State: "active",
		CPUTotal: cpu, MemTotal: memMiB,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	s.admission = newAdmissionCoordinator(s, func() bool { return true })
	return s
}

func runConcurrentAdmissionClaims(t *testing.T, c *admissionCoordinator, reqs []ReservationRequest) []error {
	t.Helper()
	start := make(chan struct{})
	errs := make([]error, len(reqs))
	var wg sync.WaitGroup
	for i := range reqs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = c.Claim(context.Background(), reqs[i])
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

func TestAdmissionCoordinatorSerializesDistinctCreates(t *testing.T) {
	s := admissionCoordinatorServer(t, 4, 4096)
	reqs := []ReservationRequest{
		{OperationID: "a", RequestHash: "hash-a", Host: "h1", Project: "p", CPU: 2, MemMiB: 3072, ExecutorHost: "h1"},
		{OperationID: "b", RequestHash: "hash-b", Host: "h1", Project: "p", CPU: 2, MemMiB: 3072, ExecutorHost: "h1"},
	}

	errs := runConcurrentAdmissionClaims(t, s.admission, reqs)
	var accepted, exhausted int
	for _, err := range errs {
		switch status.Code(err) {
		case codes.OK:
			accepted++
		case codes.ResourceExhausted:
			exhausted++
		default:
			t.Fatalf("unexpected claim error: %v", err)
		}
	}
	if accepted != 1 || exhausted != 1 {
		t.Fatalf("accepted=%d exhausted=%d errors=%v, want 1/1", accepted, exhausted, errs)
	}
}

func TestAdmissionCoordinatorSerializesIdempotentClaim(t *testing.T) {
	s := admissionCoordinatorServer(t, 8, 8192)
	req := ReservationRequest{
		OperationID: "same", RequestHash: "hash", Host: "h1", Project: "p",
		CPU: 2, MemMiB: 2048, ExecutorHost: "h1",
	}
	first, err := s.admission.Claim(context.Background(), req)
	if err != nil {
		t.Fatalf("first claim: %v", err)
	}
	replay, err := s.admission.Claim(context.Background(), req)
	if err != nil {
		t.Fatalf("replay claim: %v", err)
	}
	if !reflect.DeepEqual(first, replay) {
		t.Fatalf("replay claim differs:\nfirst=%+v\nreplay=%+v", first, replay)
	}

	req.RequestHash = "different"
	if _, err := s.admission.Claim(context.Background(), req); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("mismatched hash error = %v, want AlreadyExists", err)
	}
}

func TestAdmissionCoordinatorSerializesCancellationAndEvictsLocks(t *testing.T) {
	registry := newAdmissionLockRegistry(2)
	unlock, err := registry.lock(context.Background(), "host")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := registry.lock(ctx, "host"); status.Code(err) != codes.Canceled {
		t.Fatalf("cancelled waiter error = %v, want Canceled", err)
	}
	unlock()
	if got := registry.size(); got != 0 {
		t.Fatalf("registry size after release = %d, want 0", got)
	}

	releaseA, err := registry.lock(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	releaseB, err := registry.lock(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	fullCtx, fullCancel := context.WithTimeout(context.Background(), time.Second)
	defer fullCancel()
	if _, err := registry.lock(fullCtx, "c"); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("full registry error = %v, want ResourceExhausted", err)
	}
	releaseA()
	releaseB()
}

func TestDeterministicProjectAuthorityIsOrderIndependentAndExcludesWitness(t *testing.T) {
	hosts := []corrosion.HostRecord{
		{Name: "worker-b", State: "active"},
		{Name: "witness", State: "active", Role: "witness"},
		{Name: "offline", State: "offline"},
		{Name: "worker-a", State: "active"},
	}
	want, err := deterministicProjectAuthority("p", hosts)
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(hosts)-1; i < j; i, j = i+1, j-1 {
		hosts[i], hosts[j] = hosts[j], hosts[i]
	}
	got, err := deterministicProjectAuthority("p", hosts)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("authority after reorder = %q, want %q", got, want)
	}
	if got == "witness" || got == "offline" {
		t.Fatalf("ineligible authority selected: %q", got)
	}
}

func TestClaimProjectReservationValidatesAndBindsImmutableFacts(t *testing.T) {
	s := admissionCoordinatorServer(t, 8, 8192)
	if _, err := corrosion.ClaimInitialProjectAuthority(context.Background(), s.db, "p", "h1"); err != nil {
		t.Fatal(err)
	}
	ctx := peerCtxFor(t, s, "entry")
	got, err := s.ClaimProjectReservation(ctx, &pb.ClaimProjectReservationRequest{
		OperationId: "op", RequestHash: "hash", Project: "p",
		Cpu: 2, MemoryMib: 2048, ExecutorHost: "entry",
		OperationHeader: &pb.Operation{
			Id: "op", Method: "CreateVM", Project: "p", ResourceKind: "vm",
			ResourceId: "vm1", OperationKind: string(corrosion.OpWorkloadCreate),
			RequestHash: "hash", IdempotencyKey: "client-key", DesiredRef: "vm1",
			OwnerEpoch: 1, Principal: "alice",
		},
	})
	if err != nil {
		t.Fatalf("ClaimProjectReservation: %v", err)
	}
	if got.GetId() != "op" || got.GetRequestHash() != "hash" ||
		got.GetProject() != "p" || got.GetAuthorityHost() != "h1" ||
		got.GetAuthorityEpoch() != 1 {
		t.Fatalf("operation facts = %+v", got)
	}
	if got.GetMethod() != "CreateVM" || got.GetResourceKind() != "vm" ||
		got.GetResourceId() != "vm1" || got.GetIdempotencyKey() != "client-key" ||
		got.GetDesiredRef() != "vm1" || got.GetOwnerEpoch() != 1 ||
		got.GetPrincipal() != "alice" {
		t.Fatalf("operation header was not preserved: %+v", got)
	}

	if _, err := s.ClaimProjectReservation(ctx, nil); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("nil request error = %v, want InvalidArgument", err)
	}
	if _, err := s.ClaimProjectReservation(ctx, &pb.ClaimProjectReservationRequest{
		OperationId: "negative", RequestHash: "hash", Project: "p",
		Cpu: -1, ExecutorHost: "entry",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("negative request error = %v, want InvalidArgument", err)
	}
	if _, err := s.ClaimProjectReservation(ctx, &pb.ClaimProjectReservationRequest{
		OperationId: "unknown-host", RequestHash: "hash", Project: "p",
		Cpu: 1, ExecutorHost: "missing",
	}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("unknown executor error = %v, want FailedPrecondition", err)
	}
	if _, err := s.ClaimProjectReservation(ctx, &pb.ClaimProjectReservationRequest{
		OperationId: "bad-header", RequestHash: "hash", Project: "p",
		Cpu: 1, ExecutorHost: "entry",
		OperationHeader: &pb.Operation{
			Id: "bad-header", Method: "CreateVM", Project: "p",
			ResourceKind: "vm", ResourceId: "vm1",
			OperationKind: string(corrosion.OpWorkloadCreate),
			RequestHash:   "hash", ReservationJson: "{}",
		},
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("mismatched header reservation error = %v, want InvalidArgument", err)
	}
}

type admissionPeerClient struct {
	pb.LiteVirtClient
	target *Server
	caller string
	mutate func(*pb.Operation)
}

func (c *admissionPeerClient) ClaimProjectReservation(ctx context.Context, req *pb.ClaimProjectReservationRequest, _ ...grpc.CallOption) (*pb.Operation, error) {
	outgoing, _ := metadata.FromOutgoingContext(ctx)
	incoming := metadata.NewIncomingContext(mtlsAdminCtx(c.caller), outgoing)
	got, err := c.target.ClaimProjectReservation(incoming, req)
	if err == nil && c.mutate != nil {
		c.mutate(got)
	}
	return got, err
}

func wireAdmissionPeer(t *testing.T, entry, authority *Server) *admissionPeerClient {
	t.Helper()
	for _, pair := range []struct {
		s    *Server
		host corrosion.HostRecord
	}{
		{entry, corrosion.HostRecord{Name: authority.hostName, Address: "10.0.0.1", State: "active", CPUTotal: 8, MemTotal: 8192}},
		{authority, corrosion.HostRecord{Name: entry.hostName, Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 8192}},
	} {
		if err := corrosion.InsertHost(context.Background(), pair.s.db, pair.host); err != nil {
			t.Fatalf("InsertHost(%s): %v", pair.host.Name, err)
		}
	}
	for _, s := range []*Server{entry, authority} {
		if _, err := corrosion.ClaimInitialProjectAuthority(context.Background(), s.db, "p", authority.hostName); err != nil {
			t.Fatalf("ClaimInitialProjectAuthority(%s): %v", s.hostName, err)
		}
	}
	client := &admissionPeerClient{target: authority, caller: entry.hostName}
	entry.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return client, func() {}, nil
	}
	return client
}

func separateAdmissionServer(t *testing.T, host string) *Server {
	t.Helper()
	s := testServer(t)
	s.hostName = host
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: host, Address: "127.0.0.1", State: "active", CPUTotal: 8, MemTotal: 8192,
	}); err != nil {
		t.Fatal(err)
	}
	s.admission = newAdmissionCoordinator(s, func() bool { return true })
	return s
}

func TestAdmissionCoordinatorSerializesProjectClaimsFromDistinctEntryNodes(t *testing.T) {
	authority := separateAdmissionServer(t, "authority")
	entryA := separateAdmissionServer(t, "entry-a")
	entryB := separateAdmissionServer(t, "entry-b")
	wireAdmissionPeer(t, entryA, authority)
	wireAdmissionPeer(t, entryB, authority)
	if err := corrosion.UpsertProjectQuota(context.Background(), authority.db, corrosion.ProjectQuotaRecord{
		ProjectName: "p", VCPULimit: 2, MemMiBLimit: 2048,
	}); err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, tc := range []struct {
		server *Server
		host   string
	}{
		{entryA, "entry-a"},
		{entryB, "entry-b"},
	} {
		wg.Add(1)
		go func(i int, tc struct {
			server *Server
			host   string
		}) {
			defer wg.Done()
			<-start
			_, errs[i] = tc.server.admission.Claim(context.Background(), ReservationRequest{
				OperationID: "op-" + tc.host, RequestHash: "hash-" + tc.host,
				Host: tc.host, Project: "p", CPU: 2, MemMiB: 2048, ExecutorHost: tc.host,
			})
		}(i, tc)
	}
	close(start)
	wg.Wait()
	var accepted, exhausted int
	for _, err := range errs {
		if err == nil {
			accepted++
		} else if status.Code(err) == codes.ResourceExhausted {
			exhausted++
		} else {
			t.Fatalf("unexpected remote claim error: %v", err)
		}
	}
	if accepted != 1 || exhausted != 1 {
		t.Fatalf("accepted=%d exhausted=%d errors=%v, want 1/1", accepted, exhausted, errs)
	}
}

func TestAdmissionCoordinatorCompensatesAuthorityWhenExecutorImportConflicts(t *testing.T) {
	authority := separateAdmissionServer(t, "authority")
	entry := separateAdmissionServer(t, "entry")
	client := wireAdmissionPeer(t, entry, authority)
	client.mutate = func(*pb.Operation) {
		client.mutate = nil
		if err := corrosion.InsertOperation(context.Background(), entry.db, corrosion.OperationRecord{
			ID: "op-conflict", Method: "other", Project: "p", ResourceKind: "vm",
			ResourceID: "other", OperationKind: string(corrosion.OpWorkloadCreate),
			RequestHash: "different",
		}); err != nil {
			t.Fatal(err)
		}
	}

	_, err := entry.admission.Claim(context.Background(), ReservationRequest{
		OperationID: "op-conflict", RequestHash: "hash", Host: "entry",
		Project: "p", CPU: 2, MemMiB: 2048, ExecutorHost: "entry",
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("claim error = %v, want AlreadyExists", err)
	}
	cpu, mem, err := corrosion.ProjectReserved(context.Background(), authority.db, "p")
	if err != nil {
		t.Fatal(err)
	}
	if cpu != 0 || mem != 0 {
		t.Fatalf("authority reservation survived import conflict: cpu=%d mem=%d", cpu, mem)
	}
}

func TestAdmissionCoordinatorFailsClosedWhenAuthorityUnreachable(t *testing.T) {
	entry := separateAdmissionServer(t, "entry")
	if err := corrosion.InsertHost(context.Background(), entry.db, corrosion.HostRecord{
		Name: "authority", Address: "10.0.0.1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := corrosion.ClaimInitialProjectAuthority(context.Background(), entry.db, "p", "authority"); err != nil {
		t.Fatal(err)
	}
	entry.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return nil, nil, context.DeadlineExceeded
	}
	_, err := entry.admission.Claim(context.Background(), ReservationRequest{
		OperationID: "op", RequestHash: "hash", Host: "entry", Project: "p",
		CPU: 1, MemMiB: 1, ExecutorHost: "entry",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("unreachable authority error = %v, want Unavailable", err)
	}
}

func TestAdmissionCoordinatorInitialAuthorityForwardAndReplay(t *testing.T) {
	nodeA := separateAdmissionServer(t, "node-a")
	nodeB := separateAdmissionServer(t, "node-b")
	for _, pair := range []struct {
		s    *Server
		host string
	}{
		{nodeA, "node-b"},
		{nodeB, "node-a"},
	} {
		if err := corrosion.InsertHost(context.Background(), pair.s.db, corrosion.HostRecord{
			Name: pair.host, Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 8192,
		}); err != nil {
			t.Fatal(err)
		}
	}
	selected, err := deterministicProjectAuthority("fresh-project", []corrosion.HostRecord{
		{Name: "node-a", State: "active"}, {Name: "node-b", State: "active"},
	})
	if err != nil {
		t.Fatal(err)
	}
	entry, authority := nodeA, nodeB
	if selected == "node-a" {
		entry, authority = nodeB, nodeA
	}
	entry.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &admissionPeerClient{target: authority, caller: entry.hostName}, func() {}, nil
	}
	req := ReservationRequest{
		OperationID: "initial", RequestHash: "hash", Host: entry.hostName,
		Project: "fresh-project", CPU: 1, MemMiB: 1024, ExecutorHost: entry.hostName,
	}
	first, err := entry.admission.Claim(context.Background(), req)
	if err != nil {
		t.Fatalf("initial forwarded claim: %v", err)
	}
	replay, err := entry.admission.Claim(context.Background(), req)
	if err != nil {
		t.Fatalf("initial forwarded replay: %v", err)
	}
	if !reflect.DeepEqual(first, replay) {
		t.Fatalf("forwarded replay differs:\nfirst=%+v\nreplay=%+v", first, replay)
	}
	current, ok, err := corrosion.CurrentProjectAuthority(context.Background(), authority.db, "fresh-project")
	if err != nil || !ok || current.Holder != selected {
		t.Fatalf("authority = %+v ok=%t err=%v, want holder %q", current, ok, err, selected)
	}
}

func TestAdmissionCoordinatorRejectsAuthorityRolloverBeforePersist(t *testing.T) {
	s := admissionCoordinatorServer(t, 8, 8192)
	s.admission.beforeProjectPersist = func() {
		s.admission.beforeProjectPersist = nil
		if _, applied, err := corrosion.TakeoverProjectAuthority(
			context.Background(), s.db, "p", "h2", "planned", "", 1,
		); err != nil || !applied {
			t.Fatalf("TakeoverProjectAuthority: applied=%t err=%v", applied, err)
		}
	}
	_, err := s.admission.Claim(context.Background(), ReservationRequest{
		OperationID: "rollover", RequestHash: "hash", Host: "h1", Project: "p",
		CPU: 1, MemMiB: 1024, ExecutorHost: "h1",
	})
	if status.Code(err) != codes.Aborted {
		t.Fatalf("rollover error = %v, want Aborted", err)
	}
	if op, readErr := corrosion.GetOperation(context.Background(), s.db, "rollover"); readErr != nil || op != nil {
		t.Fatalf("operation persisted across rollover: op=%+v err=%v", op, readErr)
	}
}

func TestAdmissionCoordinatorPreLatchCompatibilityAndPostLatchDurability(t *testing.T) {
	s := admissionCoordinatorServer(t, 8, 8192)
	s.admission = newAdmissionCoordinator(s, func() bool { return false })
	req := ReservationRequest{
		OperationID: "legacy", RequestHash: "hash", Host: "h1",
		CPU: 1, MemMiB: 1024, ExecutorHost: "h1",
	}
	legacy, err := s.admission.Claim(context.Background(), req)
	if err != nil {
		t.Fatalf("pre-latch claim: %v", err)
	}
	if legacy.Durable {
		t.Fatal("pre-latch legacy claim unexpectedly durable")
	}
	if op, err := corrosion.GetOperation(context.Background(), s.db, "legacy"); err != nil || op != nil {
		t.Fatalf("pre-latch operation = %+v err=%v, want absent", op, err)
	}

	s.admission = newAdmissionCoordinator(s, func() bool { return true })
	req.OperationID = "durable"
	durable, err := s.admission.Claim(context.Background(), req)
	if err != nil {
		t.Fatalf("post-latch claim: %v", err)
	}
	if !durable.Durable || durable.Operation.ID != "durable" {
		t.Fatalf("post-latch claim = %+v, want durable operation", durable)
	}

	zero, err := s.admission.Claim(context.Background(), ReservationRequest{
		OperationID: "zero", RequestHash: "hash-zero", Host: "h1",
		ExecutorHost: "h1",
	})
	if err != nil || zero.Durable {
		t.Fatalf("zero-resource claim = %+v err=%v, want safe non-durable no-op", zero, err)
	}
}

func TestClaimProjectReservationEnforcesForwardHopBound(t *testing.T) {
	s := separateAdmissionServer(t, "relay")
	if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{
		Name: "authority", Address: "10.0.0.1", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := corrosion.ClaimInitialProjectAuthority(context.Background(), s.db, "p", "authority"); err != nil {
		t.Fatal(err)
	}
	ctx := peerCtxFor(t, s, "entry")
	ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(projectReservationHopMetadata, "1"))
	dialed := false
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		dialed = true
		return nil, nil, context.DeadlineExceeded
	}
	_, err := s.ClaimProjectReservation(ctx, &pb.ClaimProjectReservationRequest{
		OperationId: "op", RequestHash: "hash", Project: "p",
		Cpu: 1, MemoryMib: 1, ExecutorHost: "entry",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("hop-bound error = %v, want FailedPrecondition", err)
	}
	if dialed {
		t.Fatal("hop-bound request dialed another authority")
	}
}

func TestAdmissionCoordinatorRejectsOverflow(t *testing.T) {
	if _, err := normalizeReservationRequest(ReservationRequest{
		OperationID: "op", RequestHash: "hash", Host: "h", Project: "p",
		CPU: math.MaxInt32 + 1, ExecutorHost: "h",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("overflow error = %v, want InvalidArgument", err)
	}
}
