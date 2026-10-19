// A stack delete with keep_disks (REST or gRPC) whose teardown the stack
// reconciler finishes.
// The reconciler never set KeepDisks: when a member's delete failed (or the
// coordinator crashed after marking the stack "deleting"), the reconciler
// deleted the member with its disks, the disks the operator asked to keep.
// The real teardown, the real reconciler and the real VM delete over the
// in-process libvirt fake, with the disk files on disk.
package fleet

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// downHB runs DeleteStack hb and returns the progress.
func downHB(t *testing.T, client pb.LiteVirtClient, keepDisks bool) []*pb.DeleteProgress {
	t.Helper()
	stream, err := client.DeleteStack(context.Background(), &pb.DeleteStackRequest{Name: "hb", KeepDisks: keepDisks})
	if err != nil {
		t.Fatalf("DeleteStack: %v", err)
	}
	var out []*pb.DeleteProgress
	for {
		msg, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("DeleteStack stream: %v", err)
		}
		out = append(out, msg)
	}
}

// The "unproven" case is a teardown that recorded no disk choice
// (cluster_policies not writable yet): the reconciler keeps the disks and
// names them by disk_leftover (re-review m-A).
//
// Mutations: drop KeepDisks from the reconciler's delete — the keep-disks
// case loses its disks, red. Always keep — the plain case keeps them, red.
// Never name the disks kept for want of proof — the unproven case, red.
func TestFleet_ComposeDown_TheReconcilerKeepsTheDisksAKeepDisksTeardownKept(t *testing.T) {
	for _, tc := range []struct {
		name            string
		keepDisks, gate bool
		kept, named     bool
	}{
		{"keep-disks", true, true, true, false},
		{"plain", false, true, false, false},
		{"unproven", false, false, true, true},
	} {
		keepDisks := tc.keepDisks
		t.Run(tc.name, func(t *testing.T) {
			_, node, client := newComposeFailNode(t)
			node.DB.SetClusterPolicyGate(func() bool { return tc.gate })
			ctx := context.Background()
			disks := deployOneVM(t, ctx, node, client)

			// The teardown's own delete of hb-1 is refused (an operation holds
			// the VM), so the stack is left "deleting" for the reconciler.
			if err := localExec(ctx, node.DB, `UPDATE vms SET active_operation_id = 'op-held' WHERE name = 'hb-1'`); err != nil {
				t.Fatal(err)
			}
			downHB(t, client, keepDisks)
			if st, _ := corrosion.GetStack(ctx, node.DB, "hb"); st == nil || st.State != "deleting" {
				t.Fatalf("setup: stack hb = %+v, want it left \"deleting\"", st)
			}
			for _, p := range disks {
				if _, err := os.Stat(p); err != nil {
					t.Fatalf("setup: disk %s went with the failed delete: %v", p, err)
				}
			}
			if err := localExec(ctx, node.DB, `UPDATE vms SET active_operation_id = '' WHERE name = 'hb-1'`); err != nil {
				t.Fatal(err)
			}

			r := health.NewStackReconciler(node.Name, node.DB)
			r.SetCleaner(node.Server)
			r.SetClock(func() time.Time { return time.Now().Add(2 * time.Minute) }) // past the in-flight grace
			r.ReconcileOnce(ctx)

			if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
				t.Fatalf("the reconciler did not delete hb-1: %+v", vm)
			}
			if st, _ := corrosion.GetStack(ctx, node.DB, "hb"); st != nil {
				t.Errorf("the reconciler did not finish the teardown: %+v", st)
			}
			for _, p := range disks {
				_, err := os.Stat(p)
				switch {
				case tc.kept && err != nil:
					t.Errorf("disk %s was deleted by the reconciler (%s teardown): %v", p, tc.name, err)
				case !tc.kept && err == nil:
					t.Errorf("disk %s of a plain teardown was kept", p)
				}
			}

			// Named by disk_leftover on the reconciler's host, or not at all.
			node.Server.JudgeKeptDisksForTest(ctx)
			row, found, err := corrosion.GetHealthCondition(ctx, node.DB, "vm_delete", "disk_leftover", "host", node.Name)
			if err != nil {
				t.Fatal(err)
			}
			open := found && row.Lifecycle != corrosion.ConditionResolved
			if open != tc.named {
				t.Fatalf("disk_leftover open = %v, want %v: %+v", open, tc.named, row)
			}
			if tc.named {
				for _, p := range disks {
					if !strings.Contains(row.Evidence, p) || !strings.Contains(row.Evidence, `stack \"hb\"`) {
						t.Errorf("disk_leftover evidence does not name %s with stack hb: %s", p, row.Evidence)
					}
				}
			}
		})
	}
}
