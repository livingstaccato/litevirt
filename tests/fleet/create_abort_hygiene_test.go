// Fleet scenarios for what a failed create leaves of a deleted VM of its
// name (lab 2, 2026-10-16, createfail-cddb81e9 O2, O3).

package fleet

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// TestFleet_AFailedCreateLeavesWhatADeleteKeptInPlace: `lv rm --keep-disks
// rv`, then a create of rv on the same host whose domain fails to start. The
// kept root disk is back at the path the deleted rv recorded, with its bytes,
// and so is its cloud-init seed; a later create that succeeds moves both to
// .kept- names, as before.
//
// Mutations: drop the restore of a failed create — the disk is at its .kept-
// name, not its path; remove the seed at the name's path as before — the
// seed is gone.
func TestFleet_AFailedCreateLeavesWhatADeleteKeptInPlace(t *testing.T) {
	stageFakeGenisoimage(t)
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	n := c.Nodes[0]
	dataDir := n.Server.DataDir()
	importImageOn(t, c, n, "ubuntu")
	create := func() error {
		_, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: "rv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}})
		return err
	}
	if err := create(); err != nil {
		t.Fatalf("create rv: %v", err)
	}
	disks, err := corrosion.GetVMDisks(ctx, n.DB, "rv")
	if err != nil || len(disks) != 1 {
		t.Fatalf("rv's disks = %+v, %v", disks, err)
	}
	path := disks[0].Path
	appendTo(t, path, "what the operator kept")
	keptDisk := readFileT(t, path)
	seed := lv.CloudInitISOPath(dataDir, "rv")
	keptSeed := readFileT(t, seed)
	if _, err := c.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "rv", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks rv: %v", err)
	}

	n.Virt.FailStartDomain = func(string) error { return errors.New("qemu: cannot allocate memory") }
	if err := create(); err == nil || !strings.Contains(err.Error(), "cannot allocate memory") {
		t.Fatalf("create rv = %v; want the start failure", err)
	}
	if !bytes.Equal(readFileT(t, path), keptDisk) {
		t.Error("the kept disk is not at the path the deleted rv recorded after the failed create")
	}
	if k := globT(t, path+".kept-*"); len(k) != 0 {
		t.Errorf("the kept disk is still set aside after the failed create: %v", k)
	}
	if !present(seed) || !bytes.Equal(readFileT(t, seed), keptSeed) {
		t.Error("the failed create removed the kept VM's cloud-init seed")
	}

	n.Virt.FailStartDomain = nil
	if err := create(); err != nil {
		t.Fatalf("create rv: %v", err)
	}
	if k := globT(t, path+".kept-*"); len(k) != 1 || !bytes.Equal(readFileT(t, k[0]), keptDisk) {
		t.Errorf("kept disks after a create that succeeded = %v; want the one the operator kept", k)
	}
	var seeds []string
	for _, p := range globT(t, seed+".kept-*") {
		if !strings.HasSuffix(p, ".owner") {
			seeds = append(seeds, p)
		}
	}
	if len(seeds) != 1 || !bytes.Equal(readFileT(t, seeds[0]), keptSeed) {
		t.Errorf("kept seeds after a create that succeeded = %v; want the kept VM's", seeds)
	}
}
