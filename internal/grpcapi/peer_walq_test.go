package grpcapi

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// N1/N3 of the switch re-review: the recovery-time read of who may not take
// a VM asks every peer at once under one shared deadline, so ten dead peers
// cost one deadline, not ten; a peer that does not answer is excluded (it may
// be mid-rollback) and that is remembered briefly, so the next recovery in the
// cycle does not wait on it again; a quarantined answer is excluded; a
// cached "not quarantined" answer is never trusted (it may predate the
// rollback).
//
// Mutations "ask serially", "unreachable eligible", "no-answer not cached"
// and "a cached not-quarantined trusted" — red.
func TestPeerRecoveryExclusions_ParallelBoundedAndFailClosed(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	var mu sync.Mutex
	dials := map[string]int{}
	s.peerClientOverride = func(ctx context.Context, host string) (pb.LiteVirtClient, func(), error) {
		mu.Lock()
		dials[host]++
		mu.Unlock()
		switch host {
		case "live":
			return pingOnlyClient{resp: &pb.PingResponse{}}, func() {}, nil
		case "rolled-back":
			return pingOnlyClient{resp: &pb.PingResponse{WalQuarantined: true}}, func() {}, nil
		}
		<-ctx.Done() // a dead peer: the dial hangs until the deadline
		return nil, nil, ctx.Err()
	}
	var dead []string
	for i := 0; i < 10; i++ {
		dead = append(dead, fmt.Sprintf("dead-%d", i))
	}
	peers := append([]string{"live", "rolled-back", s.hostName}, dead...)

	start := time.Now()
	out := s.PeerRecoveryExclusions(ctx, peers)
	if took := time.Since(start); took > peerWALQAskTimeout+time.Second {
		t.Fatalf("ten dead peers took %v: asked one after another, not under one deadline", took)
	}
	if _, ok := out["live"]; ok {
		t.Fatalf("a live, unquarantined peer was excluded: %v", out)
	}
	if out["rolled-back"] != peerExcludedQuarantined {
		t.Fatalf("rolled-back: %q, want excluded as quarantined", out["rolled-back"])
	}
	for _, d := range dead {
		if out[d] != peerExcludedNoAnswer {
			t.Fatalf("%s: %q, want excluded for not answering", d, out[d])
		}
	}
	if _, ok := out[s.hostName]; ok {
		t.Fatal("this host excluded itself")
	}

	// The same cycle's next recovery: the dead peers are not waited on again.
	start = time.Now()
	out = s.PeerRecoveryExclusions(ctx, dead)
	if took := time.Since(start); took > 200*time.Millisecond || len(out) != len(dead) {
		t.Fatalf("second round over the dead peers took %v (%d excluded): the no-answer was not remembered", took, len(out))
	}
	mu.Lock()
	if dials["dead-0"] != 1 {
		t.Fatalf("dead-0 dialled %d times, want once", dials["dead-0"])
	}
	mu.Unlock()

	// A "not quarantined" answer from before a rollback is asked again.
	s.notePeerWALQuarantined("rolled-back", false)
	if out := s.PeerRecoveryExclusions(ctx, []string{"rolled-back"}); out["rolled-back"] != peerExcludedQuarantined {
		t.Fatalf("a cached not-quarantined answer was trusted: %v", out)
	}
}

// m4 of the switch review: the not-point-in-time notice is per VM
// incarnation, so a VM re-created under the same name is news at once.
//
// Mutation "key by name only" — red.
func TestNotPITKey_ARecreatedVMIsAnotherKey(t *testing.T) {
	s := testServer(t)
	d := &corrosion.DiskRecord{DiskName: "root"}
	a := &corrosion.VMRecord{Name: "web", Spec: `{"name":"web","uuid":"u-1"}`}
	b := &corrosion.VMRecord{Name: "web", Spec: `{"name":"web","uuid":"u-2"}`}
	if s.notPITKey(a, d) == s.notPITKey(b, d) {
		t.Fatal("two incarnations of web share a not-point-in-time notice key")
	}
}
