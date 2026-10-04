// A rejoined host must not serve a delete from a replica it has not caught up.
//
// Observed on the kvm003-f3 lab, 2026-09-30: claimvm ran on node-1; node-1's
// qemu was killed and failover rescheduled the VM to node-4 (owner epoch 2 on
// every replica). node-1 booted back and, 60s later and three seconds before
// its first anti-entropy exchange completed, served `lv compose down` run on
// node-1 itself. Its replica still said "claimvm is mine, epoch 1", so it
// destroyed its own shut-off leftover and tombstoned the row with
// host_name=node-1. That tombstone was the newest full row anywhere, so
// anti-entropy carried it over the owner's row on every node: the VM kept
// running on node-4 with no row naming it — an orphan nothing reaps.
//
// These scenarios run the real spine (separate per-node DBs, real gRPC + mTLS,
// the real auth interceptor, and a REAL anti-entropy pass for both the
// catch-up and the spread), with owner-epoch enforcement OFF — the default
// configuration the lab ran.
package fleet

import (
	"context"
	"errors"
	"io"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const staleDeleteStack = "claimtest"

// staleDeleteScenario is the lab's state at the moment of the delete: `stale`
// created claimvm and was then away while the VM was rescheduled to `owner`,
// where it runs; `stale` is back with a shut-off leftover and a replica that
// has not caught up. It returns the owner epoch the reschedule minted.
func staleDeleteScenario(t *testing.T) (c *Cluster, owner, bystander, stale *Node, epoch int64) {
	t.Helper()
	c = New(t, Options{Nodes: 3})
	owner, bystander, stale = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	ctx := context.Background()

	if err := corrosion.InsertVM(ctx, stale.DB, corrosion.VMRecord{
		Name: "claimvm", StackName: staleDeleteStack, HostName: stale.Name, State: "running",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.UpsertStack(ctx, stale.DB, corrosion.StackRecord{
		Name: staleDeleteStack, State: "running",
	}); err != nil {
		t.Fatalf("UpsertStack: %v", err)
	}
	pumpMutations(t, c, stale, owner)
	pumpMutations(t, c, stale, bystander)

	// `stale` goes away; failover reschedules claimvm to `owner` (the
	// production transfer primitive), where it starts. The bystander learns,
	// `stale` does not.
	if err := corrosion.TransferVMOwnerFresh(ctx, owner.DB, "claimvm", owner.Name, "running"); err != nil {
		t.Fatalf("reschedule: %v", err)
	}
	if err := owner.Virt.DefineDomain(`<domain><name>claimvm</name></domain>`); err != nil {
		t.Fatal(err)
	}
	owner.Virt.SetState("claimvm", libvirtfake.StateRunning)
	pumpMutations(t, c, owner, bystander)
	vm, _ := corrosion.GetVM(ctx, owner.DB, "claimvm")
	if vm == nil || vm.HostName != owner.Name {
		t.Fatalf("reschedule did not land on the owner: %+v", vm)
	}
	epoch = vm.OwnerEpoch

	// `stale` boots back: its leftover is defined and shut off (the kill
	// took qemu down), and its process has a fresh replica-freshness state —
	// no anti-entropy exchange has completed since it started.
	if err := stale.Virt.DefineDomain(`<domain><name>claimvm</name></domain>`); err != nil {
		t.Fatal(err)
	}
	stale.Virt.SetState("claimvm", libvirtfake.StateShutdown)
	stale.Virt.SetStateReason("claimvm", "destroyed")
	stale.DB.MarkReplicaStale("process restarted (fleet: modelled reboot)")
	if ok, _ := stale.DB.ReplicaCaughtUp(); ok {
		t.Fatal("setup: the rebooted node's replica must start out not caught up")
	}
	if got, _ := corrosion.GetVM(ctx, stale.DB, "claimvm"); got == nil || got.HostName != stale.Name {
		t.Fatalf("setup: the rebooted node must still believe it owns claimvm: %+v", got)
	}
	return c, owner, bystander, stale, epoch
}

// spreadFrom delivers everything `from` published to the other nodes, down
// both channels production has: the push path, and the full-row anti-entropy
// merge that carried the lab's tombstone over the owner's row.
func spreadFrom(t *testing.T, c *Cluster, from *Node) {
	t.Helper()
	ctx := context.Background()
	for _, n := range c.Nodes {
		if n == from {
			continue
		}
		pumpMutations(t, c, from, n)
		if !corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx) {
			t.Fatalf("anti-entropy pass on %s did not run", n.Name)
		}
	}
}

// vmRowAnyState reads claimvm's row on n, tombstoned or not.
func vmRowAnyState(t *testing.T, n *Node) (host string, epoch int64, deleted bool) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT host_name, vm_owner_epoch, deleted_at FROM vms WHERE name = 'claimvm'`)
	if err != nil {
		t.Fatalf("%s: read claimvm row: %v", n.Name, err)
	}
	if len(rows) != 1 {
		t.Fatalf("%s: want exactly one claimvm row, have %d", n.Name, len(rows))
	}
	return rows[0].String("host_name"), rows[0].Int64("vm_owner_epoch"), rows[0].String("deleted_at") != ""
}

// deleteViaCompose runs `lv compose down` for the stack against n and returns
// the stream's terminal error (nil on success).
func deleteViaCompose(ctx context.Context, client pb.LiteVirtClient) error {
	stream, err := client.DeleteStack(ctx, &pb.DeleteStackRequest{Name: staleDeleteStack})
	if err != nil {
		return err
	}
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if msg.GetError() != "" {
			return status.Error(codes.Unknown, msg.GetError())
		}
	}
}

func TestFleet_StaleReplica_RejoinedNodeDoesNotServeADelete(t *testing.T) {
	for _, tc := range []struct {
		name string
		del  func(ctx context.Context, client pb.LiteVirtClient) error
	}{
		{"DeleteVM", func(ctx context.Context, client pb.LiteVirtClient) error {
			_, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "claimvm"})
			return err
		}},
		{"compose-down", deleteViaCompose},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, owner, bystander, stale, epoch := staleDeleteScenario(t)
			ctx := context.Background()

			// (1) The operator's delete lands on the rebooted node before its
			// replica has caught up. It must be refused, retryably…
			err := tc.del(ctx, c.SelfClient(stale))
			if status.Code(err) != codes.Unavailable {
				t.Errorf("a node whose replica has not caught up served the delete: want Unavailable, got %v", err)
			}
			// …and must have touched nothing: not its leftover, not its row.
			if !stale.Virt.DomainExists("claimvm") {
				t.Error("the refused delete destroyed the rebooted node's leftover domain")
			}
			if host, _, deleted := vmRowAnyState(t, stale); deleted || host != stale.Name {
				t.Errorf("the refused delete wrote the rebooted node's row: host=%s deleted=%v", host, deleted)
			}

			// Whatever it did publish reaches everyone; the owner's row and
			// its running VM must survive it.
			spreadFrom(t, c, stale)
			for _, n := range []*Node{owner, bystander} {
				host, gotEpoch, deleted := vmRowAnyState(t, n)
				if deleted || host != owner.Name || gotEpoch != epoch {
					t.Errorf("%s: the stale delete regressed the owner's row: host=%s epoch=%d deleted=%v (want host=%s epoch=%d live)",
						n.Name, host, gotEpoch, deleted, owner.Name, epoch)
				}
			}
			if st, _ := owner.Virt.DomainState("claimvm"); st != "running" {
				t.Errorf("the owner's VM must still be running, is %q", st)
			}
			if t.Failed() {
				return
			}

			// (2) A real anti-entropy pass catches the rebooted node up.
			if !corrosion.NewAntiEntropy(stale.DB, stale.PKIDir, 0).RunOnce(ctx) {
				t.Fatal("anti-entropy pass did not run")
			}
			if ok, why := stale.DB.ReplicaCaughtUp(); !ok {
				t.Fatalf("a completed anti-entropy pass must mark the replica caught up (%s)", why)
			}

			// (3) The same delete is now served, and routed to the real owner:
			// the owner's domain goes, and the tombstone names the owner at its
			// own epoch on every replica.
			if err := tc.del(ctx, c.SelfClient(stale)); err != nil {
				t.Fatalf("once caught up, the delete must succeed: %v", err)
			}
			if owner.Virt.DomainExists("claimvm") {
				t.Error("the delete did not remove the owner's domain — it is orphaned")
			}
			spreadFrom(t, c, owner)
			spreadFrom(t, c, stale)
			for _, n := range c.Nodes {
				host, gotEpoch, deleted := vmRowAnyState(t, n)
				if !deleted || host != owner.Name || gotEpoch != epoch {
					t.Errorf("%s: tombstone host=%s epoch=%d deleted=%v; want the owner's (host=%s epoch=%d)",
						n.Name, host, gotEpoch, deleted, owner.Name, epoch)
				}
			}
		})
	}
}
