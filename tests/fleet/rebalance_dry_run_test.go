// Fleet scenario: `lv rebalance run --dry-run` approves nothing.
//
// The CLI and the UI's Dry-run button both send RunRebalanceRequest{DryRun:
// true}, and both promise every proposal is recorded as pending whatever each
// VM's rebalance mode is. RunRebalance used to ignore the flag, so a VM in
// mode=auto was auto-approved and the leader's rebalance executor then
// live-migrated it — a dry run moved workloads.
//
// This drives the real path: the RPC over mTLS gRPC, the proposals replicated
// to a peer through the CRDT, and the real executor (no migrate override) given
// its chance to act on them.

package fleet

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

const rebalanceAutoSpec = `{"placement":{"policy":"balance","rebalance":{"mode":"auto","budget":{"max_concurrent":4,"max_per_hour":10}}}}`

// seedRebalanceAutoImbalance sizes both hosts small and piles auto-mode VMs on
// the first, so a cycle has auto-mode moves to propose. The cluster must run
// IndependentReplicas so every write here travels over the real replicator.
func seedRebalanceAutoImbalance(t *testing.T, c *Cluster) []string {
	t.Helper()
	ctx := context.Background()
	loaded, empty := c.Nodes[0], c.Nodes[1]
	// Each node sizes its own host row through the replicated writer the
	// daemon uses, so the shrink travels like any other write; the fleet
	// default (64 CPU) is too roomy for four VMs to read as imbalanced.
	for _, n := range []*Node{loaded, empty} {
		if err := corrosion.UpdateHostResources(ctx, n.DB, n.Name, 8, 16384, 0); err != nil {
			t.Fatalf("size %s: %v", n.Name, err)
		}
	}
	eventually(t, 5*time.Second, "host sizes to replicate", func() bool {
		for _, n := range c.Nodes {
			for _, h := range []*Node{loaded, empty} {
				rec, err := corrosion.GetHost(ctx, n.DB, h.Name)
				if err != nil || rec == nil || rec.CPUTotal != 8 {
					return false
				}
			}
		}
		return true
	})
	names := make([]string, 4)
	for i := range names {
		names[i] = fmt.Sprintf("auto-vm-%d", i)
		if err := corrosion.InsertVM(ctx, loaded.DB, corrosion.VMRecord{
			Name: names[i], HostName: loaded.Name, State: "running",
			CPUActual: 2, MemActual: 4096, Spec: rebalanceAutoSpec,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", names[i], err)
		}
	}
	return names
}

func proposalStatusCounts(t *testing.T, db *corrosion.Client) map[string]int {
	t.Helper()
	rows, err := db.Query(context.Background(),
		`SELECT status, COUNT(*) AS c FROM rebalance_proposals GROUP BY status`)
	if err != nil {
		t.Fatalf("count proposals: %v", err)
	}
	out := map[string]int{}
	for _, r := range rows {
		out[r.String("status")] = r.Int("c")
	}
	return out
}

func TestFleet_RebalanceDryRunApprovesNothing(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	loaded, peer := c.Nodes[0], c.Nodes[1]
	names := seedRebalanceAutoImbalance(t, c)

	resp, err := c.SelfClient(loaded).RunRebalance(ctx, &pb.RunRebalanceRequest{DryRun: true})
	if err != nil {
		t.Fatalf("RunRebalance(dry_run): %v", err)
	}
	emitted := int(resp.GetProposalsEmitted())
	if emitted == 0 {
		t.Fatal("dry run emitted no proposals on an imbalanced cluster; the scenario proves nothing")
	}

	// The peer sees exactly what the dry run promised: every proposal pending.
	eventually(t, 5*time.Second, "dry-run proposals to replicate to the peer", func() bool {
		return proposalStatusCounts(t, peer.DB)["pending"] == emitted
	})
	for _, n := range c.Nodes {
		if got := proposalStatusCounts(t, n.DB); got["approved"] != 0 {
			t.Fatalf("%s: proposal statuses %v after a dry run; want none approved", n.Name, got)
		}
	}

	// The real executor on the lease holder finds nothing to move.
	grpcapi.NewRebalanceExecutor(loaded.Server, loaded.Name, loaded.DB).RunOnce(ctx)
	time.Sleep(100 * time.Millisecond)
	if got := proposalStatusCounts(t, loaded.DB); got["pending"] != emitted || len(got) != 1 {
		t.Fatalf("proposal statuses %v after the executor ran; want all %d still pending", got, emitted)
	}
	for _, name := range names {
		vm, err := corrosion.GetVM(ctx, loaded.DB, name)
		if err != nil || vm == nil {
			t.Fatalf("GetVM %s: vm=%v err=%v", name, vm, err)
		}
		if vm.HostName != loaded.Name {
			t.Errorf("%s moved to %q during a dry run", name, vm.HostName)
		}
	}
}

// The same cluster shape without --dry-run: auto-mode proposals are approved.
// Behaviour outside a dry run is unchanged. Asserted on the node that ran the
// cycle, which is where the executor reads them.
func TestFleet_RebalanceRealRunStillAutoApproves(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	loaded := c.Nodes[0]
	seedRebalanceAutoImbalance(t, c)

	resp, err := c.SelfClient(loaded).RunRebalance(ctx, &pb.RunRebalanceRequest{})
	if err != nil {
		t.Fatalf("RunRebalance: %v", err)
	}
	emitted := int(resp.GetProposalsEmitted())
	if emitted == 0 {
		t.Fatal("no proposals emitted on an imbalanced cluster")
	}
	if got := proposalStatusCounts(t, loaded.DB); got["approved"] != emitted {
		t.Fatalf("proposal statuses %v; want all %d auto-mode proposals approved", got, emitted)
	}
}
