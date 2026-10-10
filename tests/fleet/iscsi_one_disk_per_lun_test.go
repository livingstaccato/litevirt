// Fleet scenarios for "one iSCSI LUN, one disk" across hosts.
//
// An iscsi pool is one LUN, and every disk created on it is that LUN. Two VMs
// on two hosts with a disk on it write one block device and corrupt it. A
// host's replica cannot rule that out alone — two creates on two hosts each
// read a replica holding neither — so a create asks the other hosts
// (LUNHolders, peer-only, over real mTLS) what they hold, committed or in
// flight. These scenarios run with no replication between the nodes, so
// every refusal below comes from that question and not from a replicated row.

package fleet

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

const fleetLUNTarget = "iqn.2020-01.com.example:fleet"

// newLUNFleet is two nodes with their own databases and nothing replicating
// between them; iscsiadm is a no-op.
func newLUNFleet(t *testing.T) *Cluster {
	t.Helper()
	t.Cleanup(storage.OverrideISCSICommandForTest(func(context.Context, string, ...string) ([]byte, error) {
		return nil, nil
	}))
	c := New(t, Options{Nodes: 2})
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 32, 65536, nil)
	}
	return c
}

// addLUNPool gives every node a pool `name` on LUN lun of the fleet target.
// Pools are host-scoped: each node's row is written to its own database.
func addLUNPool(t *testing.T, c *Cluster, name string, lun int) {
	t.Helper()
	for _, n := range c.Nodes {
		if err := corrosion.UpsertStoragePool(context.Background(), n.DB, corrosion.StoragePoolRecord{
			HostName: n.Name, Name: name, Driver: "iscsi", Source: fleetLUNTarget, State: "active",
			Options: map[string]string{"portal": "10.9.9.9", "lun": fmt.Sprint(lun)},
		}); err != nil {
			t.Fatalf("pool %s on %s: %v", name, n.Name, err)
		}
	}
}

// createOnLUN asks node n to create VM name on n with one disk on pool.
func createOnLUN(c *Cluster, n *Node, name, pool string) error {
	_, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name},
		Disks: []*pb.DiskSpec{{Name: "root", Size: "1G", Storage: pool}},
	}})
	return err
}

func lunVMOn(t *testing.T, n *Node, name string) bool {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil {
		t.Fatalf("GetVM %s on %s: %v", name, n.Name, err)
	}
	return rec != nil
}

// A LUN another host's VM already is refuses the create, naming that VM —
// although this host's replica has never heard of it.
//
// Mutation: skip asking the peers in claimLUNs — b is created on a's LUN and
// this goes red.
func TestFleet_ISCSI_ALUNTakenOnAnotherHostIsRefused(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0)

	if err := createOnLUN(c, n0, "a", "san"); err != nil {
		t.Fatalf("create a on %s: %v", n0.Name, err)
	}
	if lunVMOn(t, n1, "a") {
		t.Fatal("a replicated to the second node; the scenario needs it not to")
	}
	err := createOnLUN(c, n1, "b", "san")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "a"`) {
		t.Fatalf("create b on a's LUN on %s: got %v, want FailedPrecondition naming VM \"a\"", n1.Name, err)
	}
	if lunVMOn(t, n1, "b") {
		t.Error("the refused VM b was persisted")
	}
	// Another LUN of the same target is free.
	addLUNPool(t, c, "san1", 1)
	if err := createOnLUN(c, n1, "b", "san1"); err != nil {
		t.Fatalf("create b on another LUN: %v", err)
	}
}

// Two creates of one LUN on two hosts at the same moment cannot both win.
// Each host's answer is held until BOTH have been asked, so both creates have
// registered before either hears back: each sees the other in flight, and
// both are refused (retryably) rather than both taking the LUN. The retry
// then goes through on one host and is refused, by name, on the other.
//
// Mutation: drop the in-flight half of the answer (lunHoldersHere) — both
// creates win and this goes red.
func TestFleet_ISCSI_ConcurrentCreatesOnTwoHostsCannotBothWin(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0)

	var arrived sync.WaitGroup
	arrived.Add(2)
	both := make(chan struct{})
	go func() { arrived.Wait(); close(both) }()
	hold := func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		arrived.Done()
		select {
		case <-both:
		case <-time.After(3 * time.Second):
		}
		return h(ctx, req)
	}
	n0.HookUnary("LUNHolders", hold)
	n1.HookUnary("LUNHolders", hold)

	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i, n := range []*Node{n0, n1} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = createOnLUN(c, n, []string{"a", "b"}[i], "san")
		}()
	}
	wg.Wait()
	if errs[0] == nil && errs[1] == nil {
		t.Fatal("both creates took one LUN")
	}
	for i, other := range []string{"b", "a"} {
		if status.Code(errs[i]) != codes.Aborted || !strings.Contains(errs[i].Error(), fmt.Sprintf("VM %q", other)) {
			t.Errorf("create %d: got %v, want Aborted naming the racing VM %q", i, errs[i], other)
		}
	}
	if lunVMOn(t, n0, "a") || lunVMOn(t, n1, "b") {
		t.Error("a refused create was persisted")
	}

	if err := createOnLUN(c, n0, "a", "san"); err != nil {
		t.Fatalf("retry a on %s: %v", n0.Name, err)
	}
	err := createOnLUN(c, n1, "b", "san")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), `VM "a"`) {
		t.Fatalf("retry b once a holds the LUN: got %v, want FailedPrecondition naming VM \"a\"", err)
	}
}

// Free-running races, one LUN per round: whatever the interleaving, at most
// one of two concurrent creates on two hosts takes the LUN, and a loser is
// told why.
func TestFleet_ISCSI_RacingCreatesAtMostOneWins(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	for round := 0; round < 8; round++ {
		pool := fmt.Sprintf("san%d", round)
		addLUNPool(t, c, pool, round)
		names := []string{fmt.Sprintf("a%d", round), fmt.Sprintf("b%d", round)}
		errs := make([]error, 2)
		var wg sync.WaitGroup
		for i, n := range []*Node{n0, n1} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs[i] = createOnLUN(c, n, names[i], pool)
			}()
		}
		wg.Wait()
		won := 0
		for i, err := range errs {
			switch status.Code(err) {
			case codes.OK:
				won++
			case codes.Aborted, codes.FailedPrecondition:
				if !strings.Contains(err.Error(), fmt.Sprintf("VM %q", names[1-i])) {
					t.Errorf("round %d create %s refused without naming %s: %v", round, names[i], names[1-i], err)
				}
			default:
				t.Errorf("round %d create %s: %v", round, names[i], err)
			}
		}
		if won > 1 {
			t.Fatalf("round %d: both creates took LUN %d", round, round)
		}
	}
}

// A host on an older build does not know the question. Its committed disks
// reach the asker by replication, so the create goes ahead, as on main.
func TestFleet_ISCSI_AnOlderPeerDoesNotBlockTheCreate(t *testing.T) {
	c := newLUNFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	addLUNPool(t, c, "san", 0)
	defer n1.DoNotImplement("LUNHolders")()
	if err := createOnLUN(c, n0, "a", "san"); err != nil {
		t.Fatalf("create with a peer on an older build: %v", err)
	}
}
