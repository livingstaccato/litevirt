// Fleet scenario for re-review 4 of fix/iscsi-one-disk-per-lun (I-1): a
// rebuild or recreate whose delete is refused — the VM intact, no create
// attempted — must not leave behind the hold it took on the VM's LUN. That
// hold could never be released while the VM lives (its rows answer for the
// LUN on every host), so every later recreate of the VM would be refused.
//
// It runs on independent replicas; every wait is on another node's replica.

package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// activeOpOn reports the journaled operation n's replica shows holding vm.
func activeOpOn(t *testing.T, n *Node, vm string) string {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, vm)
	if err != nil || rec == nil {
		return "?"
	}
	return rec.ActiveOperationID
}

// Re-review 4, I-1. web runs on node-1; a journaled operation (a backup, say)
// holds its mutation barrier. A compose update from node-0 that re-creates
// web on node-3 moves web's claim, then its delete is refused: an operation
// is in progress. web is untouched. Once the operation finishes, the update
// is run again — and must go through: the refused one left no hold.
//
// Mutation: keep the hold when no create was attempted (round 4) — node-0's
// hold answers for web forever, the second update is refused Aborted, and
// this goes red.
func TestFleet_ISCSI_ARecreateRefusedAtItsDeleteLeavesNoHold(t *testing.T) {
	for _, tc := range []struct{ name, update string }{
		{"rolling", "    update:\n      strategy: rolling\n"},
		{"inline", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, web, stack := lunWebStack(t, tc.update)
			n0, n1, n2, n3 := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
			ctx := context.Background()
			key := fleetLUNKey(0)

			rec, err := corrosion.GetVM(ctx, n1.DB, web)
			if err != nil || rec == nil {
				t.Fatalf("web on node-1: %v", err)
			}
			op := corrosion.OperationRecord{ID: "op-backup", Method: "BackupSnapshot", Principal: "admin@local",
				Project: "_default", ResourceKind: "vm", ResourceID: web,
				OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h"}
			if ok, err := n1.DB.BeginVMOperation(ctx, op, rec.Spec, rec.OwnerEpoch, rec.SpecGeneration); err != nil || !ok {
				t.Fatalf("begin an operation on web: applied=%v err=%v", ok, err)
			}
			eventually(t, convergeTimeout, "the operation to reach node-0", func() bool { return activeOpOn(t, n0, web) == "op-backup" })

			msgs, _ := deployResult(ctx, c.SelfClient(n0), stack(n3.Name, "      scratch: 1G\n"))
			p := errorPhaseFor(msgs, web)
			if p == nil || !strings.Contains(p.Error, "operation is in progress") {
				t.Fatalf("the update while an operation holds web: got %v, want its delete refused for the operation", msgs)
			}
			if !n1.Virt.DomainExists(web) || n3.Virt.DomainExists(web) {
				t.Fatal("web was touched by an update whose delete was refused")
			}
			if hs := lunHoldersAt(t, c, n2, n0, key); heldInFlight(hs, web) {
				t.Fatalf("node-0 kept a hold for a re-create that never ran: %v", hs)
			}

			if ok, err := n1.DB.CompleteVMOperation(ctx, web, "op-backup", rec.OwnerEpoch, rec.SpecGeneration+1); err != nil || !ok {
				t.Fatalf("finish the operation: applied=%v err=%v", ok, err)
			}
			eventually(t, convergeTimeout, "the operation's end to reach node-0", func() bool { return activeOpOn(t, n0, web) == "" })
			waitVMAgreed(t, c, web)

			msgs, err = deployResult(ctx, c.SelfClient(n0), stack(n3.Name, "      scratch: 1G\n"))
			if p := errorPhaseFor(msgs, web); p != nil || err != nil {
				t.Fatalf("the update run again once the operation finished: %v %v", err, describePhase(p))
			}
			// The re-created incarnation runs where its row says.
			eventually(t, convergeTimeout, "web to be re-created (the update said "+describeAll(msgs)+")", func() bool {
				now, err := corrosion.GetVM(ctx, n0.DB, web)
				if err != nil || now == nil || now.CreatedAt == rec.CreatedAt {
					return false
				}
				for _, n := range c.Nodes {
					if n.Name == now.HostName {
						return n.Virt.DomainExists(web)
					}
				}
				return false
			})
		})
	}
}

func describePhase(p *pb.DeployProgress) string {
	if p == nil {
		return ""
	}
	return p.Phase + ": " + p.Error
}

func describeAll(msgs []*pb.DeployProgress) string {
	var out []string
	for _, m := range msgs {
		out = append(out, m.Phase+"/"+m.VmName+": "+m.Detail+m.Error)
	}
	return strings.Join(out, " | ")
}
