package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/health"
)

// TestResolveGateValid_RegionScopeNeedsClusterQuorum: resolving a dual-run
// condition proves ABSENCE cluster-wide. Under region scope the execution gate
// passes on a region's quorum alone, which cannot promise the rest of the
// cluster is clean, so resolution also needs the cluster-wide QuorumProof.
func TestResolveGateValid_RegionScopeNeedsClusterQuorum(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()

	// Cluster scope: the execution gate alone decides, as before.
	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumNo})
	if !s.resolveGateValid(ctx) {
		t.Fatalf("cluster scope: resolution must follow the execution gate alone")
	}

	setRegionScope(t, s)
	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumNo, live: 2, needed: 3})
	if s.resolveGateValid(ctx) {
		t.Fatalf("region scope: a node with only its region's quorum resolved a cluster-wide absence")
	}
	s.SetGate(fakeServerGate{execOK: true, quorum: health.QuorumYes, live: 3, needed: 3})
	if !s.resolveGateValid(ctx) {
		t.Fatalf("region scope with cluster-wide quorum: resolution must be valid")
	}
}
