package fleet

import (
	"bytes"
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_RmKeepDisks_VMWithSnapshots: `lv rm --keep-disks` of a VM that
// has a snapshot. libvirt refuses to undefine a shut-off domain that still
// holds snapshot metadata unless SNAPSHOTS_METADATA is passed ("cannot
// delete inactive domain with 1 snapshots", lab, rc1 4b13deaf1), and the
// keep-state undefine passed only KEEP_NVRAM|KEEP_TPM, so the delete failed
// with the VM kept. The delete now drops libvirt's snapshot metadata with
// the domain and keeps everything else: the disk the snapshot was taken of
// and its overlay, byte for byte, and the VM's snapshot records.
//
// Mutation: the keep-disks delete undefines with UndefineDomainPreservingState
// again: red (the delete fails with the fake's libvirt refusal).
func TestFleet_RmKeepDisks_VMWithSnapshots(t *testing.T) {
	stageFakeGenisoimage(t)
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	n := c.Nodes[0]
	importImageOn(t, c, n, "ubuntu")
	cl := c.SelfClient(n)
	if _, err := cl.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}}); err != nil {
		t.Fatalf("create sv: %v", err)
	}
	before, err := corrosion.GetVMDisks(ctx, n.DB, "sv")
	if err != nil || len(before) != 1 {
		t.Fatalf("sv's disks = %+v, %v", before, err)
	}
	appendTo(t, before[0].Path, "what the operator kept")
	if _, err := cl.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "sv", Name: "s1"}); err != nil {
		t.Fatalf("snapshot s1: %v", err)
	}
	after, err := corrosion.GetVMDisks(ctx, n.DB, "sv")
	if err != nil || len(after) != 1 {
		t.Fatalf("sv's disks after the snapshot = %+v, %v", after, err)
	}
	kept := map[string][]byte{}
	for _, p := range []string{before[0].Path, after[0].Path} {
		if present(p) {
			kept[p] = readFileT(t, p)
		}
	}
	if len(kept) == 0 {
		t.Fatal("no disk file of sv exists before the delete")
	}

	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks sv (with a snapshot): %v", err)
	}

	if n.Virt.DomainExists("sv") {
		t.Error("sv's domain is still defined after the delete")
	}
	if vm, err := corrosion.GetVM(ctx, n.DB, "sv"); err != nil || vm != nil {
		t.Errorf("sv's record after the delete = %+v, %v; want none", vm, err)
	}
	for p, b := range kept {
		if !present(p) {
			t.Errorf("--keep-disks removed %s", p)
		} else if !bytes.Equal(readFileT(t, p), b) {
			t.Errorf("--keep-disks changed %s", p)
		}
	}
	snaps, err := corrosion.ListSnapshots(ctx, n.DB, "sv")
	if err != nil || len(snaps) != 1 || snaps[0].Name != "s1" {
		t.Errorf("sv's snapshot records after --keep-disks = %+v, %v; want s1 kept", snaps, err)
	}
}
