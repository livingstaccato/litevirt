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

// Mutation: drop KeepDisks from the reconciler's delete — the keep-disks
// case loses its disks, red. Always keep — the plain case keeps them, red.
func TestFleet_ComposeDown_TheReconcilerKeepsTheDisksAKeepDisksTeardownKept(t *testing.T) {
	for _, keepDisks := range []bool{true, false} {
		name := "plain"
		if keepDisks {
			name = "keep-disks"
		}
		t.Run(name, func(t *testing.T) {
			_, node, client := newComposeFailNode(t)
			node.DB.SetClusterPolicyGate(func() bool { return true })
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
				case keepDisks && err != nil:
					t.Errorf("disk %s of a keep_disks teardown was deleted by the reconciler: %v", p, err)
				case !keepDisks && err == nil:
					t.Errorf("disk %s of a plain teardown was kept", p)
				}
			}
		})
	}
}
