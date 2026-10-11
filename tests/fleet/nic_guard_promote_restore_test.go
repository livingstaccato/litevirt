package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// requireGuardedAndRendered fails unless every NIC of vm has a guard record
// that is on, and the firewall plan of n renders a guard for it.
func requireGuardedAndRendered(t *testing.T, n *Node, vm string) {
	t.Helper()
	ctx := context.Background()
	ifaces, err := corrosion.GetVMInterfaces(ctx, n.DB, vm)
	if err != nil || len(ifaces) == 0 {
		t.Fatalf("%s's NICs: %+v, %v", vm, ifaces, err)
	}
	for _, f := range ifaces {
		rec, err := corrosion.GetNICGuard(ctx, n.DB, vm, f.MAC)
		if err != nil || rec == nil || !rec.Guarded() {
			t.Errorf("%s's NIC %s has no guard on: %+v, %v", vm, f.MAC, rec, err)
		}
	}
	rendered := 0
	for _, b := range planOn(t, n).NICs {
		if b.VMName == vm && b.Guard != nil {
			rendered++
		}
	}
	if rendered != len(ifaces) {
		t.Errorf("%s: %d of %d NICs render a guard", vm, rendered, len(ifaces))
	}
}

// A renamed promotion and a restore under a new name each make a second VM
// whose NICs are new (fresh MACs). Like a create's and a clone's, each gets
// the default guard through the nic_guards gate (M8), and the firewall
// renders it — so the copy cannot spoof the original's, or anyone's, address.
//
// Mutations: drop the guard write from the renamed promotion, or from the
// renamed restore — that VM's case goes red.
func TestFleet_NICGuard_RenamedPromotionAndRestoreAreGuarded(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	openNICGuards(t, n)
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	setHostCapacity(t, c, n.Name, 64, 65536)
	nets := []*pb.NetworkAttachment{{Name: "lan", Model: "virtio"}}

	// A restore under a new name.
	repo, ts := seedVMBackupWithSpec(t, &pb.VMSpec{Name: "bk", Cpu: 1, MemoryMib: 256, Network: nets})
	if err := restoreLiveAt(t, c, n, repo, "bk", ts, "bk-copy"); err != nil {
		t.Fatalf("restore as bk-copy: %v", err)
	}
	requireGuardedAndRendered(t, n, "bk-copy")

	// A renamed promotion of a replica in a pool on this node.
	dr := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, n.DB, corrosion.StoragePoolRecord{
		HostName: n.Name, Name: "dr", Driver: "dir", Target: dr, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	live := filepath.Join(t.TempDir(), "web-root.qcow2")
	for _, p := range []string{live, filepath.Join(dr, "web-root-20261001-000000.qcow2")} {
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256, Network: nets})
	if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
		Name: "web", HostName: n.Name, State: "stopped", Spec: string(spec),
	}, nil, []corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: n.Name, Path: live, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	st, err := c.SelfClient(n).PromoteReplica(ctx, &pb.PromoteReplicaRequest{
		VmName: "web", TargetPool: "dr", Replica: "web-root-20261001-000000.qcow2", NewName: "web-dr", NoLocalize: true,
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if err != io.EOF {
		t.Fatalf("promote web as web-dr: %v", err)
	}
	requireGuardedAndRendered(t, n, "web-dr")
	_ = os.Remove
}
