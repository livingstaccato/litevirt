package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A network deleted while a workload on some host still uses it — `lv network
// delete --force`, a stack delete whose workload deletes failed — reaches every
// host as a tombstone. A host tears the network down only once nothing on it
// uses the network: no live VM NIC (vm_interfaces or vm_nics) or container NIC
// row of a workload on THIS host names it, and its bridge carries no guest
// port. Until then the tombstone is retried every pass, not marked done.
func TestFleet_NetworkReconcileKeepsADeletedNetworkLocalWorkloadsUse(t *testing.T) {
	type user struct {
		name string
		// add makes the network in use on n1; remove ends that.
		add, remove func(t *testing.T, n *Node)
	}
	ctx := context.Background()
	bridge := network.IsolatedBridgeName("hc")
	users := []user{{
		name: "a VM NIC row (vm_interfaces)",
		add: func(t *testing.T, n *Node) {
			if err := corrosion.InsertVM(ctx, n.DB,
				corrosion.VMRecord{Name: "web", HostName: n.Name, State: "running", Spec: "{}"},
				[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "hc", MAC: "52:54:00:00:00:01"}}, nil); err != nil {
				t.Fatal(err)
			}
		},
		remove: func(t *testing.T, n *Node) {
			if err := corrosion.DeleteVM(ctx, n.DB, "web"); err != nil {
				t.Fatal(err)
			}
		},
	}, {
		name: "a VM NIC row (vm_nics)",
		add: func(t *testing.T, n *Node) {
			if err := corrosion.InsertVMWithHardware(ctx, n.DB,
				corrosion.VMRecord{Name: "web2", HostName: n.Name, State: "running", Spec: "{}"}, nil, nil,
				[]corrosion.NICRecord{{VMName: "web2", ID: "nic0", NetworkName: "hc", Model: "virtio", MAC: "52:54:00:00:00:02"}},
				nil, false); err != nil {
				t.Fatal(err)
			}
		},
		remove: func(t *testing.T, n *Node) {
			if err := corrosion.DeleteVM(ctx, n.DB, "web2"); err != nil {
				t.Fatal(err)
			}
		},
	}, {
		name: "a container NIC row",
		add: func(t *testing.T, n *Node) {
			if err := corrosion.UpsertContainerInterface(ctx, n.DB, corrosion.ContainerInterfaceRecord{
				HostName: n.Name, CtName: "ct1", NetworkName: "hc", MAC: "52:54:00:00:00:03",
			}); err != nil {
				t.Fatal(err)
			}
		},
		remove: func(t *testing.T, n *Node) {
			if err := corrosion.DeleteContainerInterfaces(ctx, n.DB, n.Name, "ct1"); err != nil {
				t.Fatal(err)
			}
		},
	}, {
		name:   "a guest port on the bridge",
		add:    func(_ *testing.T, n *Node) { n.Net.SetGuestPorts(bridge, "vnet7") },
		remove: func(_ *testing.T, n *Node) { n.Net.SetGuestPorts(bridge) },
	}}

	for _, u := range users {
		t.Run(u.name, func(t *testing.T) {
			c := New(t, Options{Nodes: 2})
			n0, n1 := c.Nodes[0], c.Nodes[1]
			if _, err := c.SelfClient(n0).CreateNetwork(ctx, &pb.CreateNetworkRequest{
				Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
			}); err != nil {
				t.Fatalf("CreateNetwork: %v", err)
			}
			n1.DB.MergeStateBytesLWW(pullDump(t, c, n0))
			reconcileNetworks(t, n1)
			if _, ok := n1.Net.Up("hc"); !ok {
				t.Fatal("setup: hc not provisioned on n1")
			}
			u.add(t, n1)

			if _, err := c.SelfClient(n0).DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "hc", Force: true}); err != nil {
				t.Fatalf("DeleteNetwork --force: %v", err)
			}
			n1.DB.MergeStateBytesLWW(pullDump(t, c, n0))
			reconcileNetworks(t, n1)
			reconcileNetworks(t, n1)
			if got := n1.Net.Deprovisions("hc"); got != 0 {
				t.Fatalf("n1 tore hc down %d times while %s on n1 uses it", got, u.name)
			}
			if _, ok := n1.Net.Up("hc"); !ok {
				t.Fatal("hc is no longer up on n1 while a workload there uses it")
			}

			// Once nothing on n1 uses it, the retried tombstone tears it down.
			u.remove(t, n1)
			reconcileNetworks(t, n1)
			if got := n1.Net.Deprovisions("hc"); got != 1 {
				t.Fatalf("n1 tore hc down %d times once nothing used it, want 1", got)
			}
		})
	}
}

// Only THIS host's workloads hold a teardown here: a VM on another host, or a
// deleted one, does not.
func TestFleet_NetworkReconcileIgnoresOtherHostsWorkloads(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	n0, n1 := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	if _, err := c.SelfClient(n0).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	n1.DB.MergeStateBytesLWW(pullDump(t, c, n0))
	reconcileNetworks(t, n1)
	if err := corrosion.InsertVM(ctx, n1.DB,
		corrosion.VMRecord{Name: "far", HostName: "elsewhere", State: "running", Spec: "{}"},
		[]corrosion.InterfaceRecord{{VMName: "far", NetworkName: "hc", MAC: "52:54:00:00:00:09"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, n1.DB, corrosion.ContainerInterfaceRecord{
		HostName: "elsewhere", CtName: "ct9", NetworkName: "hc", MAC: "52:54:00:00:00:0a",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(n0).DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "hc", Force: true}); err != nil {
		t.Fatalf("DeleteNetwork --force: %v", err)
	}
	n1.DB.MergeStateBytesLWW(pullDump(t, c, n0))
	reconcileNetworks(t, n1)
	if got := n1.Net.Deprovisions("hc"); got != 1 {
		t.Fatalf("n1 tore hc down %d times; workloads on another host must not hold it here", got)
	}
}

// DeleteNetwork's in-use guard counts a container NIC, not only a VM's.
func TestFleet_DeleteNetworkRefusesANetworkAContainerUses(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	if _, err := c.SelfClient(n).CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: "hc", Type: "isolated", Subnet: "172.16.50.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	if err := corrosion.UpsertContainerInterface(ctx, n.DB, corrosion.ContainerInterfaceRecord{
		HostName: n.Name, CtName: "ct1", NetworkName: "hc", MAC: "52:54:00:00:00:03",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := c.SelfClient(n).DeleteNetwork(ctx, &pb.DeleteNetworkRequest{Name: "hc"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "container") {
		t.Fatalf("DeleteNetwork of a network a container uses = %v, want FailedPrecondition naming the container", err)
	}
	if nr, _ := corrosion.GetNetwork(ctx, n.DB, "hc"); nr == nil {
		t.Fatal("the network was deleted")
	}
	if got := n.Net.Deprovisions("hc"); got != 0 {
		t.Fatalf("hc torn down %d times by a refused delete", got)
	}
}

// DeleteStack whose VM delete fails keeps the stack in "deleting", and must
// not tombstone its networks meanwhile: the tombstone would reach every host
// and pull the network out from under the VM that is still there.
func TestFleet_DeleteStackKeepsNetworksWhileAWorkloadDeleteFails(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	msgs := deployCollect(t, ctx, client, composeFailOne)
	if p := errorPhaseFor(msgs, "hb-1"); p != nil {
		t.Fatalf("setup deploy failed: %s", p.Error)
	}
	if err := corrosion.UpsertNetwork(ctx, node.DB, corrosion.NetworkRecord{
		Name: "hb_back", StackName: "hb", Type: "bridge", Config: `{"type":"bridge"}`,
	}); err != nil {
		t.Fatalf("seed stack network: %v", err)
	}
	if err := node.DB.Execute(ctx, `CREATE TRIGGER test_hb1_undeletable BEFORE UPDATE OF deleted_at ON vms
		WHEN OLD.name = 'hb-1' AND NEW.deleted_at IS NOT NULL
		BEGIN SELECT RAISE(ABORT, 'injected: vm row locked'); END`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}

	got := deleteStackCollect(t, ctx, client, "hb")
	if st := stackState(t, ctx, node.DB, "hb"); st != "deleting" {
		t.Fatalf("stack state = %q, want deleting (the injection did not hold); stream %v", st, got)
	}
	if vm, _ := corrosion.GetVM(ctx, node.DB, "hb-1"); vm == nil {
		t.Fatal("setup: hb-1 was deleted despite the injection")
	}
	if nr, _ := corrosion.GetNetwork(ctx, node.DB, "hb_back"); nr == nil {
		t.Error("the stack's network was tombstoned while its VM delete failed")
	}
	if n := node.Net.Deprovisions("hb_back"); n != 0 {
		t.Errorf("the stack's network was torn down %d times while its VM delete failed", n)
	}
}
