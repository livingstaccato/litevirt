package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// seedTunableVM puts a stopped VM `far` on owner: spec, a root disk row and a
// defined domain, replicated to every node.
func seedTunableVM(t *testing.T, c *Cluster, owner *Node) {
	t.Helper()
	spec, _ := json.Marshal(&pb.VMSpec{Name: "far", Cpu: 2, MemoryMib: 512,
		Disks: []*pb.DiskSpec{{Name: "root", Bus: "virtio"}}})
	if err := corrosion.InsertVM(context.Background(), owner.DB, corrosion.VMRecord{
		Name: "far", HostName: owner.Name, State: "stopped", Spec: string(spec), CPUActual: 2, MemActual: 512,
	}, nil, []corrosion.DiskRecord{{VMName: "far", DiskName: "root", HostName: owner.Name,
		Path: "/var/lib/litevirt/disks/far-root.qcow2", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda", Bus: "virtio"}}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	x, err := lv.GenerateDomainXML(lv.VMConfig{Name: "far", CPU: 2, MemoryMiB: 512,
		Disks: []lv.DiskConfig{{Name: "root", Path: "/var/lib/litevirt/disks/far-root.qcow2", Bus: "virtio"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Virt.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
}

// A discard change entering on a node that does NOT own the VM is applied by the
// owner, which writes its spec only after the domain has the setting. The entry
// node writes nothing itself, so a slow replication link cannot let an old spec
// overwrite the new one, and a failed redefine leaves the spec saying what the
// domain has.
//
// Mutations: have the entry node write the spec before forwarding — the
// failed-define spec check goes red; have the owner write the spec before the
// define — the same check goes red; drop the tuning merge in UpdateVM — the XML
// check goes red.
func TestFleet_IndependentReplicas_TuningReconfigureFromANonOwnerIsAppliedByTheOwner(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true, FaultSeed: 71})
	owner, entry := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	seedTunableVM(t, c, owner)
	latchIOFeature(t, c)
	c.SetLinkFaultBoth(owner, entry, LinkFault{Delay: 300 * time.Millisecond})
	req := &pb.UpdateVMRequest{Name: "far", DiskTuning: []*pb.DiskTuningUpdate{{Name: "root", Discard: "unmap"}}}

	// The owner cannot redefine: the call fails, and no node's spec claims discard.
	owner.Virt.FailDefineDomain = func(string) error { return status.Error(codes.Internal, "define refused") }
	if _, err := c.SelfClient(entry).UpdateVM(ctx, req); err == nil {
		t.Fatal("a failed redefine was reported as success")
	}
	owner.Virt.FailDefineDomain = nil
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := specOn(t, n, "far").Disks[0].Discard; got != "" {
			t.Fatalf("%s's spec claims discard %q though the domain was never redefined", n.Name, got)
		}
	}

	// A retry applies it, on the owner, and it replicates.
	if _, err := c.SelfClient(entry).UpdateVM(ctx, req); err != nil {
		t.Fatalf("UpdateVM from the non-owner: %v", err)
	}
	if x := owner.Virt.DefinedXML("far"); !strings.Contains(x, "discard='unmap'") && !strings.Contains(x, `discard="unmap"`) {
		t.Errorf("the owner's domain lacks discard:\n%s", x)
	}
	if entry.Virt.DomainExists("far") {
		t.Error("the entry node defined a domain for a VM it does not own")
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := specOn(t, n, "far").Disks[0].Discard; got != "unmap" {
			t.Errorf("%s's spec discard = %q, want unmap", n.Name, got)
		}
	}
}
