package corrosion

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/emptypb"
)

// fakePeer is a real mTLS gRPC peer. A hanging one accepts the connection, the
// handshake and the call, and then never answers — the failure mode that no
// timeout on the DIAL can catch, because the dial succeeded.
type fakePeer struct {
	pb.UnimplementedLiteVirtServer
	hang        bool
	digestCalls atomic.Int32
}

func (p *fakePeer) GetStateDigest(ctx context.Context, _ *emptypb.Empty) (*pb.StateDigestResponse, error) {
	p.digestCalls.Add(1)
	if p.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &pb.StateDigestResponse{}, nil
}

func (p *fakePeer) PushMutations(ctx context.Context, _ *pb.ReplicateRequest) (*pb.ReplicateResponse, error) {
	if p.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return &pb.ReplicateResponse{}, nil
}

// startFakePeer serves p over mTLS on 127.0.0.1 and registers it in c's hosts
// table under name, so the production dial path resolves and reaches it.
func startFakePeer(t *testing.T, c *Client, pkiDir, name string, p *fakePeer) {
	t.Helper()
	tlsCfg, err := pki.ServerTLSConfig(pkiDir)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	pb.RegisterLiteVirtServer(srv, p)
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)

	if err := InsertHost(context.Background(), c, HostRecord{
		Name: name, Address: "127.0.0.1", SSHUser: "root", State: "active",
		GRPCPort: ln.Addr().(*net.TCPAddr).Port,
	}); err != nil {
		t.Fatalf("InsertHost %s: %v", name, err)
	}
}

// shrink sets *v for the duration of the test.
func shrink(t *testing.T, v *time.Duration, d time.Duration) {
	t.Helper()
	old := *v
	*v = d
	t.Cleanup(func() { *v = old })
}

// A push to a peer that accepts the call and never answers returns on its own
// deadline, not whenever the caller happens to give up.
//
// The push ran on the loop's root context. A hung peer therefore held its push
// loop inside PushMutations forever: no error came back, so no backoff ran and
// notePushFailure never fired — and the prune, which stops counting a peer only
// once it has been RECORDED as failing, kept that peer's frozen watermark
// pinning the whole log.
func TestReplicateOnce_AHungPeerReturnsOnItsOwnDeadline(t *testing.T) {
	shrink(t, &pushRPCTimeout, 200*time.Millisecond)
	pkiDir := testPKI(t, "hung-peer")
	c := newPruneTestClient(t)
	insertLogRow(t, c, tsAgo(time.Minute))
	startFakePeer(t, c, pkiDir, "hung-peer", &fakePeer{hang: true})
	r := NewReplicator(c, pkiDir, RelayConfig{})
	r.SetProofReplicaGate(func(context.Context, string) bool { return true })

	outer, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := r.replicateOnce(outer, "hung-peer")

	if err == nil {
		t.Fatal("replicateOnce returned nil against a peer that never answered")
	}
	if outer.Err() != nil {
		t.Fatalf("replicateOnce returned only because the CALLER's context expired (%v); "+
			"with no deadline of its own it would have hung for as long as the loop runs", err)
	}
}

// One hung peer must not stall anti-entropy for every other peer.
//
// checkPeers visits peers one at a time on the daemon's root context, so a peer
// that accepted the connection and then sat on GetStateDigest held the pass
// there indefinitely. Every peer after it in the member list was never checked
// again, and whatever divergence anti-entropy exists to heal stayed unhealed.
func TestCheckPeers_AHungPeerDoesNotStallTheRest(t *testing.T) {
	shrink(t, &antiEntropyPeerTimeout, 200*time.Millisecond)
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	hung := &fakePeer{hang: true}
	healthy := &fakePeer{}
	startFakePeer(t, c, pkiDir, "hung-peer", hung)
	startFakePeer(t, c, pkiDir, "healthy-peer", healthy)
	// Hung first, so the healthy peer is only reached if the hung one lets go.
	c.SetMembersForTests(func() []PeerInfo {
		return []PeerInfo{{Name: "hung-peer"}, {Name: "healthy-peer"}}
	})
	ae := NewAntiEntropy(c, pkiDir, time.Minute)

	outer, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ae.checkPeers(outer)

	if outer.Err() != nil {
		t.Fatal("checkPeers returned only because the caller's context expired; " +
			"the hung peer held the pass for its whole duration")
	}
	if hung.digestCalls.Load() == 0 {
		t.Fatal("precondition: the hung peer was never contacted, so this proves nothing")
	}
	if healthy.digestCalls.Load() == 0 {
		t.Error("the healthy peer was never checked — one hung peer stalled anti-entropy for the rest")
	}
}
