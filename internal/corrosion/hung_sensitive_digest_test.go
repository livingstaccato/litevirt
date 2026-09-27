package corrosion

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/protobuf/types/known/emptypb"
)

// sensitiveHangPeer answers the public digest at once — so the exchange gets
// past it — and then accepts GetSensitiveStateDigest and never answers.
type sensitiveHangPeer struct {
	fakePeer
	sensitiveCalls atomic.Int32
}

func (p *sensitiveHangPeer) GetStateDigest(context.Context, *emptypb.Empty) (*pb.StateDigestResponse, error) {
	p.digestCalls.Add(1)
	return &pb.StateDigestResponse{}, nil
}

func (p *sensitiveHangPeer) GetSensitiveStateDigest(ctx context.Context, _ *pb.SensitiveStateRequest) (*pb.StateDigestResponse, error) {
	p.sensitiveCalls.Add(1)
	<-ctx.Done()
	return nil, ctx.Err()
}

// A hung SENSITIVE digest gives up on the digest budget too, not the exchange's.
//
// The sensitive digest is the second digest RPC of every exchange and is just as
// small as the public one; on the per-peer budget alone, a peer that answered
// the public digest and then sat on this one held the serial pass for the whole
// exchange budget. TestCheckPeers_AHungDigestGivesUpOnTheDigestBudget covers
// only the public call — this is its twin for the sensitive one.
func TestCheckPeers_AHungSensitiveDigestGivesUpOnTheDigestBudget(t *testing.T) {
	shrink(t, &antiEntropyPeerTimeout, time.Minute) // the exchange budget stays long
	shrink(t, &antiEntropyDigestTimeout, 200*time.Millisecond)
	pkiDir := testPKI(t, "self")
	c := newPruneTestClient(t)
	hung := &sensitiveHangPeer{}
	startFakePeer(t, c, pkiDir, "hung-peer", hung)
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "hung-peer"}} })
	ae := NewAntiEntropy(c, pkiDir, time.Minute)

	start := time.Now()
	ae.checkPeers(context.Background())
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("a hung sensitive digest held the pass %v; it must give up on the digest budget, not the %v exchange budget",
			d, antiEntropyPeerTimeout)
	}
	if hung.sensitiveCalls.Load() == 0 {
		t.Fatal("precondition: the sensitive digest was never requested, so this proves nothing")
	}
}
