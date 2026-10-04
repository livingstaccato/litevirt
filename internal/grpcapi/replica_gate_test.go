package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Every gated name must be a real RPC. A typo would leave that mutation
// silently ungated, and nothing else would notice.
func TestStaleReplicaGated_NamesRealRPCs(t *testing.T) {
	real := map[string]bool{}
	for _, m := range pb.LiteVirt_ServiceDesc.Methods {
		real["/"+pb.LiteVirt_ServiceDesc.ServiceName+"/"+m.MethodName] = true
	}
	for _, st := range pb.LiteVirt_ServiceDesc.Streams {
		real["/"+pb.LiteVirt_ServiceDesc.ServiceName+"/"+st.StreamName] = true
	}
	for m := range staleReplicaGated {
		if !real[m] {
			t.Errorf("staleReplicaGated names %q, which is not an RPC of the service", m)
		}
	}
	for _, must := range []string{"DeleteVM", "DeleteStack", "StartVM", "StopVM", "MigrateVM", "DeleteContainer"} {
		if !staleReplicaGated["/litevirt.v1.LiteVirt/"+must] {
			t.Errorf("%s must be gated", must)
		}
	}
	// A rejoining node needs these to catch up and to rejoin at all.
	for _, never := range []string{"Ping", "Ready", "PushMutations", "GetStateDigest", "StreamStateDump",
		"TriggerAntiEntropy", "PrepareRecoveryClaim", "AcceptRecoveryClaim", "ListVMs", "InspectVM"} {
		if staleReplicaGated["/litevirt.v1.LiteVirt/"+never] {
			t.Errorf("%s must not be gated", never)
		}
	}
}

// The gate refuses a gated RPC while this node's replica has not caught up and
// another host exists, lets it through once caught up, and never gates an
// ungated one. (The interceptor wiring is covered end to end by
// tests/fleet/stale_replica_delete_test.go.)
func TestStaleReplicaGate_RefusesUntilCaughtUp(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, h := range []string{s.hostName, "peer-host"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	deleteVM := "/litevirt.v1.LiteVirt/DeleteVM"

	s.db.MarkReplicaStale("test: restarted")
	if err := s.gateStaleReplica(ctx, deleteVM); status.Code(err) != codes.Unavailable {
		t.Fatalf("stale replica, two hosts: DeleteVM must be refused Unavailable, got %v", err)
	}
	if err := s.gateStaleReplica(ctx, "/litevirt.v1.LiteVirt/ListVMs"); err != nil {
		t.Fatalf("an ungated read must pass while stale: %v", err)
	}

	s.db.MarkReplicaCaughtUpForTests("peer-host")
	if err := s.gateStaleReplica(ctx, deleteVM); err != nil {
		t.Fatalf("caught up: DeleteVM must pass the gate: %v", err)
	}
}

// A cluster of one has no peer to catch up with and no other owner: trusted.
func TestStaleReplicaGate_SingleNodeTrusted(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	s.db.MarkReplicaStale("test: restarted")
	if err := s.requireReplicaCaughtUp(ctx, "DeleteVM"); err != nil {
		t.Fatalf("a single-node cluster must not be gated: %v", err)
	}
}
