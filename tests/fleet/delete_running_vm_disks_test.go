package fleet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// F-5 (lab 2): `lv rm` of a running VM, without --force, printed "deleted"
// and left the VM's disk file behind; a stopped VM's delete removed it. The
// outcome of the two is the same: the row, the domain and the disks go.
func TestFleet_DeleteVMOfARunningVMRemovesItsDisks(t *testing.T) {
	for _, state := range []string{"running", "stopped"} {
		t.Run(state, func(t *testing.T) {
			_, node, client := newComposeFailNode(t)
			ctx := context.Background()
			disks := deployOneVM(t, ctx, node, client)
			if state == "stopped" {
				if _, err := client.StopVM(ctx, &pb.StopVMRequest{Name: "hb-1", Force: true}); err != nil {
					t.Fatalf("stop: %v", err)
				}
			} else if st, _ := node.Virt.DomainState("hb-1"); st != "running" {
				t.Fatalf("hb-1 is %q before the delete, want running", st)
			}

			if _, err := client.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "hb-1"}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm != nil {
				t.Error("hb-1's row survived the delete")
			}
			if node.Virt.DomainExists("hb-1") {
				t.Error("hb-1's domain survived the delete")
			}
			for _, p := range disks {
				if _, err := os.Stat(p); err == nil {
					t.Errorf("the delete reported success and left disk %s behind", p)
				}
			}
		})
	}
}

// A delete whose host has no domain probes its peers; a peer that has the
// domain and refuses its delete (here: its record says a backup is running)
// answered with an error
// the probing host treated as "not here", and it then removed the record as
// stale — leaving the VM running on the peer with nothing that names it. The
// refusal is passed on, and the record stays.
//
// Mutation: treat a FailedPrecondition probe answer as "not here" again —
// the record is removed: red.
func TestFleet_DeleteVMAProbedPeerThatRefusesKeepsTheRecord(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	ctx := context.Background()
	n0, n1 := c.Nodes[0], c.Nodes[1]
	importImageOn(t, c, n1, "ubuntu")
	if _, err := c.SelfClient(n1).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, n0.Name+" to see web", func() bool {
		vm, err := corrosion.GetVM(ctx, n0.DB, "web")
		return err == nil && vm != nil
	})
	// n0's copy of the record says web is n0's (a stale record); n1, where
	// its domain is, refuses to delete it.
	if err := localExec(ctx, n0.DB, `UPDATE vms SET host_name = ? WHERE name = 'web'`, n0.Name); err != nil {
		t.Fatal(err)
	}
	if err := localExec(ctx, n1.DB, `UPDATE vms SET state = 'backing-up' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}

	_, err := c.SelfClient(n0).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("DeleteVM: %v, want the peer's FailedPrecondition", err)
	}
	if vm, _ := corrosion.GetVM(ctx, n0.DB, "web"); vm == nil {
		t.Error("the record was removed as stale while the VM runs on the peer that refused its delete")
	}
	if !n1.Virt.DomainExists("web") {
		t.Error("the refusing peer's domain is gone")
	}
}

// m-9: a probed peer that has the domain and refuses its delete with a code
// other than FailedPrecondition — here its removal of the VM's disk fails
// after its teardown (Internal) — marks the refusal, and the probing host
// passes it on with its code and keeps the record, never removing it as
// stale.
//
// Mutation: pass on FailedPrecondition only (ignore the trailer) — the
// record is removed: red.
func TestFleet_DeleteVMAProbedPeersMarkedRefusalKeepsTheRecord(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	ctx := context.Background()
	n0, n1 := c.Nodes[0], c.Nodes[1]
	importImageOn(t, c, n1, "ubuntu")
	if _, err := c.SelfClient(n1).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}}); err != nil {
		t.Fatal(err)
	}
	eventually(t, 15*time.Second, n0.Name+" to see web", func() bool {
		vm, err := corrosion.GetVM(ctx, n0.DB, "web")
		return err == nil && vm != nil
	})
	disks, err := corrosion.GetVMDisks(ctx, n1.DB, "web")
	if err != nil || len(disks) == 0 {
		t.Fatalf("web's disks on %s: %v %v", n1.Name, disks, err)
	}
	// Its disk's unlink fails on n1: a non-empty directory in its place.
	p := disks[0].Path
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(p, "busy"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := localExec(ctx, n0.DB, `UPDATE vms SET host_name = ? WHERE name = 'web'`, n0.Name); err != nil {
		t.Fatal(err)
	}

	_, err = c.SelfClient(n0).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "web"})
	if err == nil || status.Code(err) == codes.FailedPrecondition || status.Code(err) == codes.NotFound {
		t.Fatalf("DeleteVM: %v, want the peer's own refusal passed on", err)
	}
	if vm, _ := corrosion.GetVM(ctx, n0.DB, "web"); vm == nil {
		t.Error("the record was removed as stale while the peer that has the VM refused its delete")
	}
}
