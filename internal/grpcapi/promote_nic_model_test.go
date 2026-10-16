package grpcapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A takeover promotion defines the VM's domain from its live NICs and takes
// each one's model the way every other builder does (compose.NICModels): the
// spec NIC with its MAC first. A VM created before v42 with an e1000 NIC has
// a backfilled vm_nics row that says virtio; the takeover rendered that row's
// model, and a guest without virtio-net drivers came up with no network on
// the host it was promoted to.
//
// Mutation: render the merged row's model in the takeover loop — red.
func TestPromote_ATakeoverKeepsTheSpecsNICModel(t *testing.T) {
	const mac = "52:54:00:aa:00:51"
	s := testServer(t)
	s.virt = libvirtfake.New()
	s.bridgeEnsure = func(string) error { return nil }
	poolDir := t.TempDir()
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"dr": {Driver: "local", Target: poolDir}})
	spec, _ := json.Marshal(&pb.VMSpec{Name: "db", Cpu: 1, MemoryMib: 256,
		Network: []*pb.NetworkAttachment{{Name: "lan", Model: "e1000", Mac: mac}}})
	ctx := context.Background()
	if err := corrosion.InsertVMWithHardware(ctx, s.db, corrosion.VMRecord{
		Name: "db", HostName: "dead-host", State: "running", Spec: string(spec),
	}, []corrosion.InterfaceRecord{{VMName: "db", NetworkName: "lan", Ordinal: 0, MAC: mac}},
		[]corrosion.DiskRecord{{VMName: "db", DiskName: "root", HostName: "dead-host", Path: "/dead/db-root.qcow2",
			SizeBytes: 1 << 20, StorageType: "local", TargetDev: "vda", Bus: "virtio"}},
		// The v42 backfill: a vm_nics row with the default model.
		[]corrosion.NICRecord{{VMName: "db", ID: corrosion.DeterministicNICID("db", mac),
			NetworkName: "lan", Model: "virtio", MAC: mac, Ordinal: 0}}, nil, false); err != nil {
		t.Fatalf("insert VM: %v", err)
	}
	seedReplica(t, poolDir, "", "db", "root", stamp(10*time.Minute), "raw", 1<<20)
	recordOwnerFence(t, s, "ipmi1", "ipmi", "fenced", time.Minute)

	promoteSet(t, s, &pb.PromoteReplicaRequest{VmName: "db", TargetPool: "dr", Force: true, NoLocalize: true})

	x, err := s.virt.DumpXMLInactive("db")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	if got := nicModelsByMAC(t, x)[mac]; got != "e1000" {
		t.Fatalf("the promoted NIC renders %q, want e1000:\n%s", got, x)
	}
}
