package fleet

// A generated MAC is one no NIC of the cluster records, and two hosts that
// drew one MAC at the same moment are named by a mac_duplicate condition on
// each, with neither guest's MAC rewritten.
//
// Mutations, each turning the named test red:
//   - CreateVM draws with lv.GenerateMAC again (AvoidsAndConcurrentRaises:
//     mc gets the taken MAC);
//   - attachNICOwner draws with lv.GenerateMAC again (AttachAvoids);
//   - ReconcileMACCollisions raises nothing (AvoidsAndConcurrentRaises).

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// forcedMACs makes every node's MAC draw return seq in order, then repeat
// its last entry.
func forcedMACs(t *testing.T, seq ...string) {
	t.Helper()
	var mu sync.Mutex
	i := 0
	t.Cleanup(grpcapi.SetMACDrawForTests(func() string {
		mu.Lock()
		defer mu.Unlock()
		m := seq[min(i, len(seq)-1)]
		i++
		return m
	}))
}

func createOneNIC(t *testing.T, c *Cluster, n *Node, name, net string) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 128,
		Placement: &pb.PlacementSpec{Host: n.Name},
		Network:   []*pb.NetworkAttachment{{Name: net}},
	}}); err != nil {
		t.Fatalf("CreateVM %s on %s: %v", name, n.Name, err)
	}
}

func nicMACsOf(t *testing.T, n *Node, vm string) []string {
	t.Helper()
	nics, err := corrosion.MergedVMNICs(context.Background(), n.DB, vm)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, x := range nics {
		out = append(out, strings.ToLower(x.MAC))
	}
	return out
}

func TestFleet_MAC_AvoidsAndConcurrentRaises(t *testing.T) {
	const dup, next = "52:54:00:7a:00:01", "52:54:00:7a:00:02"
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	a, b := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}

	// Two hosts, each before seeing the other's row, draw one MAC.
	c.Partition(a, b)
	forcedMACs(t, dup)
	createOneNIC(t, c, a, "ma", "lan")
	createOneNIC(t, c, b, "mb", "lan")
	c.Heal(a, b)
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, b, a)

	for _, n := range c.Nodes {
		n.Server.ReconcileMACCollisions(ctx)
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, grpcapi.NICIdentityEvaluator, grpcapi.CondMACDuplicate, "host", n.Name)
		if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
			t.Fatalf("%s: condition %+v ok=%v err=%v; want it open", n.Name, row, ok, err)
		}
		for _, want := range []string{dup, "VM ma", "host " + a.Name, "VM mb", "host " + b.Name} {
			if !strings.Contains(row.Evidence, want) {
				t.Errorf("%s: evidence %q does not name %q", n.Name, row.Evidence, want)
			}
		}
	}
	// Neither guest's MAC was rewritten, in its domain or its rows.
	for _, x := range []struct {
		n  *Node
		vm string
	}{{a, "ma"}, {b, "mb"}} {
		xml, err := x.n.Virt.DumpXML(x.vm)
		if err != nil || !strings.Contains(strings.ToLower(xml), dup) {
			t.Errorf("%s's domain on %s no longer has MAC %s (err %v)", x.vm, x.n.Name, dup, err)
		}
		if got := nicMACsOf(t, x.n, x.vm); len(got) != 1 || got[0] != dup {
			t.Errorf("%s's NIC rows on %s = %v, want [%s]", x.vm, x.n.Name, got, dup)
		}
	}

	// A host that sees the MAC draws again.
	forcedMACs(t, dup, next)
	createOneNIC(t, c, a, "mc", "lan")
	if got := nicMACsOf(t, a, "mc"); len(got) != 1 || got[0] != next {
		t.Fatalf("mc's MAC = %v, want [%s]: a MAC the cluster records was handed out", got, next)
	}

	// Once one of the two is gone, the condition resolves on both hosts.
	if _, err := c.SelfClient(b).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "mb"}); err != nil {
		t.Fatalf("DeleteVM mb: %v", err)
	}
	pumpMutations(t, c, b, a)
	for _, n := range c.Nodes {
		n.Server.ReconcileMACCollisions(ctx)
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, grpcapi.NICIdentityEvaluator, grpcapi.CondMACDuplicate, "host", n.Name)
		if err != nil || !ok || row.Lifecycle != corrosion.ConditionResolved {
			t.Fatalf("%s after mb is deleted: condition %+v ok=%v err=%v; want resolved", n.Name, row, ok, err)
		}
	}
}

func TestFleet_MAC_AttachAvoids(t *testing.T) {
	const free = "52:54:00:7a:01:01"
	c, _ := mergedNICsCluster(t, false)
	home := c.Nodes[0]
	ctx := context.Background()
	for vm, mac := range map[string]string{"av1": mnA, "av2": mnB} {
		if _, err := c.SelfClient(home).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: vm, Cpu: 1, MemoryMib: 128,
			Placement: &pb.PlacementSpec{Host: home.Name},
			Network:   []*pb.NetworkAttachment{{Name: "na", Mac: mac}},
		}}); err != nil {
			t.Fatalf("CreateVM %s: %v", vm, err)
		}
	}
	forcedMACs(t, mnA, free)
	nic := mustAttachNIC(t, c, home, "av2", "nc")
	if got := strings.ToLower(nic.MAC); got != free {
		t.Fatalf("attached NIC's MAC = %s, want %s: av1's MAC was handed to av2", got, free)
	}
}

// A clone's NICs get MACs no NIC of the cluster records.
func TestFleet_MAC_CloneAvoids(t *testing.T) {
	const tplMAC, taken, free = "52:54:00:7a:02:01", "52:54:00:7a:02:02", "52:54:00:7a:02:03"
	f := newCloneFleet(t)
	ctx := context.Background()
	for _, n := range f.c.Nodes {
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	if err := corrosion.InsertVM(ctx, f.entry.DB, corrosion.VMRecord{Name: "holder", HostName: f.dst.Name, State: "running"},
		[]corrosion.InterfaceRecord{{VMName: "holder", NetworkName: "lan", MAC: taken}}, nil); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "tpl", Cpu: 1, MemoryMib: 256,
		Network: []*pb.NetworkAttachment{{Name: "lan", Mac: tplMAC}}})
	if err := f.entry.DB.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'tpl'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	forcedMACs(t, taken, free)
	if _, err := f.clone(t, &pb.CloneVMRequest{Target: "cl1", DestinationHost: f.dst.Name}); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if got := nicMACsOf(t, f.entry, "cl1"); len(got) != 1 || got[0] != free {
		t.Fatalf("the clone's MACs = %v, want [%s]: holder's MAC was handed to the clone", got, free)
	}
}
