package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// lv image rm while a rebuild or a rolling recreate is between its teardown
// and its create: the VM's disks and rows are gone, and nothing but the
// operation itself says the create is about to need the image's file.

// rmDuringTearDown arms on: in its next rebuild or rolling recreate, once the
// old VM is torn down, `lv image rm ubuntu` runs through via (after wait, if
// set), and its answer is returned through the pointers.
func rmDuringTearDown(t *testing.T, c *Cluster, on, via *Node, wait func(), resp **pb.RemoveImageResponse, rmErr *error) {
	t.Helper()
	on.Server.SetRecreateTornDownHookForTest(func(string) {
		if wait != nil {
			wait()
		}
		*resp, *rmErr = c.SelfClient(via).RemoveImage(context.Background(), &pb.RemoveImageRequest{Name: "ubuntu"})
	})
	t.Cleanup(func() { on.Server.SetRecreateTornDownHookForTest(nil) })
}

func keptReason(resp *pb.RemoveImageResponse, host, file string) string {
	if h := hostResult(resp, host); h != nil {
		for _, k := range h.Kept {
			if k.Path == file {
				return k.Reason
			}
		}
	}
	return ""
}

// On the VM's own host: the rebuild holds the image across its teardown and
// its create, so the file the create needs stays and the rebuild completes.
// The deleted row's grace is turned off: the hold alone keeps it.
func TestFleet_ImageRm_DuringARebuildKeepsTheImageForItsCreate(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0 := c.Nodes[0]
	f := importImageOn(t, c, n0, "ubuntu")
	seedVM(t, c, n0, &pb.VMSpec{Name: "web", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n0.Name}})
	n0.Server.SetImageRecreateGraceForTest(-1)
	var resp *pb.RemoveImageResponse
	var rmErr error
	rmDuringTearDown(t, c, n0, n0, nil, &resp, &rmErr)

	if _, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild while lv image rm ran: %v; %s", err, whereIs(c, "web"))
	}
	if rmErr != nil {
		t.Fatal(rmErr)
	}
	if r := keptReason(resp, n0.Name, f); !strings.Contains(r, "in flight") {
		t.Errorf("%s reported %v; want its file kept for the rebuild in flight", n0.Name, hostResult(resp, n0.Name))
	}
	if !fileThere(f) {
		t.Error("the image file the rebuilt VM is built on is gone")
	}
}

// The same for a rolling recreate run on the VM's host.
func TestFleet_ImageRm_DuringARollingRecreateKeepsTheImageForItsCreate(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0 := c.Nodes[0]
	f := importImageOn(t, c, n0, "ubuntu")
	seedVM(t, c, n0, &pb.VMSpec{Name: "web", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n0.Name}})
	n0.Server.SetImageRecreateGraceForTest(-1)
	var resp *pb.RemoveImageResponse
	var rmErr error
	rmDuringTearDown(t, c, n0, n0, nil, &resp, &rmErr)

	desired := &pb.VMSpec{Name: "web", Image: "ubuntu", Cpu: 2, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n0.Name}}
	if err := recreateOn(t, n0, c.SelfClient(n0), "web", desired); err != nil {
		t.Fatalf("rolling recreate while lv image rm ran: %v; %s", err, whereIs(c, "web"))
	}
	if rmErr != nil {
		t.Fatal(rmErr)
	}
	if r := keptReason(resp, n0.Name, f); !strings.Contains(r, "in flight") {
		t.Errorf("%s reported %v; want its file kept for the recreate in flight", n0.Name, hostResult(resp, n0.Name))
	}
	if !fileThere(f) {
		t.Error("the image file the re-created VM is built on is gone")
	}
}

// Across hosts: a rebuild on node-0 of a VM pinned to node-1 creates it on
// node-1. Between node-0's tombstone reaching node-1 and node-1's create
// taking its hold, only the deleted row's grace keeps node-1's copy.
func TestFleet_ImageRm_DuringARebuildOntoAnotherHostKeepsThatHostsCopy(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	c.WaitConverged(t, convergeTimeout)
	imageRmFleet(c)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	importImageOn(t, c, n0, "ubuntu")
	f1 := importImageOn(t, c, n1, "ubuntu")
	seedVM(t, c, n0, &pb.VMSpec{Name: "web", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}})
	var resp *pb.RemoveImageResponse
	var rmErr error
	tombstoned := func() {
		eventually(t, 15*time.Second, "node-1 to apply web's tombstone", func() bool {
			vm, err := corrosion.GetVM(context.Background(), n1.DB, "web")
			return err == nil && vm == nil
		})
	}
	rmDuringTearDown(t, c, n0, n1, tombstoned, &resp, &rmErr)

	vm, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"})
	if err != nil {
		t.Fatalf("rebuild onto %s while lv image rm ran there: %v; %s", n1.Name, err, whereIs(c, "web"))
	}
	if vm.GetHostName() != n1.Name {
		t.Fatalf("rebuilt on %s, want %s", vm.GetHostName(), n1.Name)
	}
	if rmErr != nil {
		t.Fatal(rmErr)
	}
	if r := keptReason(resp, n1.Name, f1); !strings.Contains(r, "deleted at") {
		t.Errorf("%s reported %v; want its copy kept for the VM deleted moments ago", n1.Name, hostResult(resp, n1.Name))
	}
	if !fileThere(f1) {
		t.Error("the copy the rebuilt VM is built on is gone")
	}
}
