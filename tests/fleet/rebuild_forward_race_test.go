// Fleet scenarios: a rebuild or a rolling recreate whose create lands on a
// host that has not yet applied the tombstone of the VM it replaces.
//
// Observed on the lab, 2026-10-08 (lab-recheck-5.log): `lv rebuild
// rc5-isohome`, on node-2 with a spec pin to node-3, tore the VM down on
// node-2, tombstoned its row and forwarded the create to node-3 two
// milliseconds later. node-3 had not applied the tombstone, so its own
// existence check still saw the VM and refused the create AlreadyExists. The
// VM was gone: no row, no disks, no domain anywhere.
//
// Main (3e4ba50b) had the same loss: RebuildVM tombstones and then calls
// CreateVM, whose placement forwards to the pinned or chosen host, whose
// createVM refuses on its own stale row (vm.go:3138 and :3145, then :212,
// :310 and :146-149, at 3e4ba50b). A rolling recreate run from a node other
// than the VM's host has it too, even when the create stays on the entry
// node: DeleteVM is forwarded to the owner, and the entry's own row is the
// stale one (stacks_rolling.go:40 and :45 at 3e4ba50b). The four lag
// scenarios below fail the same way against 3e4ba50b and 1c105363.
//
// Only independent replicas reach this: a shared database applies the
// tombstone everywhere at once. Replication from the deleting host is
// delayed, as it is on a real network for the few milliseconds the forward
// takes, and every scenario then lets it through and checks that the late
// tombstone does not take the new VM with it anywhere.
package fleet

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// raceLag is how long a push from the deleting host is held before the
// receiver applies it: long enough that the create always gets there first.
const raceLag = 3 * time.Second

func newRebuildRaceFleet(t *testing.T) *Cluster {
	t.Helper()
	return New(t, Options{Nodes: 3, IndependentReplicas: true})
}

// seedVM puts VM name, stopped, on host on with spec, and waits until every
// replica has it — the state the lab's VM was in before the rebuild.
func seedVM(t *testing.T, c *Cluster, on *Node, spec *pb.VMSpec) *corrosion.VMRecord {
	t.Helper()
	ctx := context.Background()
	spec.Uuid = "0b9a3c1e-7d2f-4c55-9a1b-5e6f7a8b9c0d"
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, on.DB, corrosion.VMRecord{
		Name: spec.Name, HostName: on.Name, State: "stopped", Spec: string(b),
		CPUActual: int(spec.Cpu), MemActual: int(spec.MemoryMib),
	}, nil, nil); err != nil {
		t.Fatalf("seed %s on %s: %v", spec.Name, on.Name, err)
	}
	if err := on.Virt.DefineDomain(`<domain><name>` + spec.Name + `</name></domain>`); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, 20*time.Second)
	rec, err := corrosion.GetVM(ctx, on.DB, spec.Name)
	if err != nil || rec == nil {
		t.Fatalf("seeded %s is not on %s: %v", spec.Name, on.Name, err)
	}
	return rec
}

// labelHost gives host the label k=v cluster-wide.
func labelHost(t *testing.T, c *Cluster, host *Node, k, v string) {
	t.Helper()
	if err := corrosion.SetHostLabel(context.Background(), host.DB, host.Name, k, v); err != nil {
		t.Fatalf("label %s %s=%s: %v", host.Name, k, v, err)
	}
	c.WaitConverged(t, 20*time.Second)
}

// lagFrom holds every push from `from` to each of `to` for raceLag.
func lagFrom(c *Cluster, from *Node, to ...*Node) {
	for _, n := range to {
		c.SetLinkFault(from, n, LinkFault{Delay: raceLag})
	}
}

// assertReCreated checks, once replication has caught up, that name is live
// on every replica as a new incarnation on want, and that its domain is on
// want and nowhere else.
func assertReCreated(t *testing.T, c *Cluster, name string, before *corrosion.VMRecord, want *Node) {
	t.Helper()
	c.ClearLinkFaults()
	waitHistoryApplied(t, c, 30*time.Second)
	ctx := context.Background()
	for _, n := range c.Nodes {
		rec, err := corrosion.GetVM(ctx, n.DB, name)
		if err != nil || rec == nil {
			t.Fatalf("%s is gone on %s after replication caught up (%v)", name, n.Name, err)
		}
		if rec.HostName != want.Name {
			t.Errorf("%s on %s's replica: host %s, want %s", name, n.Name, rec.HostName, want.Name)
		}
		if rec.CreatedAt == before.CreatedAt {
			t.Errorf("%s on %s's replica is still the old incarnation (created_at %s)", name, n.Name, rec.CreatedAt)
		}
		if mine, _ := corrosion.GetVM(ctx, want.DB, name); mine == nil || rec.CreatedAt != mine.CreatedAt || rec.Spec != mine.Spec {
			t.Errorf("%s on %s's replica is not the row its host %s holds", name, n.Name, want.Name)
		}
	}
	for _, n := range c.Nodes {
		if got := n.Virt.DomainExists(name); got != (n == want) {
			t.Errorf("%s's domain on %s: exists=%v, want %v", name, n.Name, got, n == want)
		}
	}
}

// assertOnlyDeleterTombstoned checks that no host but deleter wrote a
// tombstone of a vms row: the host the VM was re-created on waited for the
// tombstone to arrive, and did not retire its stale copy itself.
func assertOnlyDeleterTombstoned(t *testing.T, c *Cluster, deleter *Node) {
	t.Helper()
	for _, n := range c.Nodes {
		if n == deleter {
			continue
		}
		rows, err := n.DB.Query(context.Background(),
			`SELECT hlc FROM mutation_log WHERE origin = ? AND stmts LIKE '%UPDATE vms SET deleted_at%'`, n.Name)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) > 0 {
			t.Errorf("%s tombstoned a VM itself (%d writes); only %s deletes in this scenario", n.Name, len(rows), deleter.Name)
		}
	}
}

// waitHistoryApplied waits until every node has applied every replicated
// write every other node has made so far — the late tombstone included — and
// every table but vms agrees. vms is compared by the caller: a create's
// hardware_adoption_state stays apart between the creating host and its
// peers on this build whatever the create (the adoption UPDATE carries the
// insert's own updated_at, which the receivers' LWW gate drops), which is not
// what these scenarios are about.
func waitHistoryApplied(t *testing.T, c *Cluster, timeout time.Duration) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(timeout)
	for _, origin := range c.Nodes {
		rows, err := origin.DB.Query(ctx, `SELECT hlc FROM mutation_log WHERE origin = ?`, origin.Name)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range c.Nodes {
			if n == origin {
				continue
			}
			for _, r := range rows {
				for {
					seen, err := n.DB.Query(ctx, `SELECT 1 FROM mutation_seen WHERE origin = ? AND hlc = ?`, origin.Name, r.String("hlc"))
					if err != nil {
						t.Fatal(err)
					}
					if len(seen) > 0 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatalf("%s has not applied %s's write %s within %s", n.Name, origin.Name, r.String("hlc"), timeout)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
		}
	}
	c.WaitConvergedExcept(t, time.Until(deadline), []string{"vms"})
}

// whereIs says what is left of VM name once replication has caught up: its
// row on each replica and its domain on each host.
func whereIs(c *Cluster, name string) string {
	c.ClearLinkFaults()
	time.Sleep(2 * raceLag)
	ctx := context.Background()
	out := "after replication caught up:"
	for _, n := range c.Nodes {
		row := "no row"
		if rec, err := corrosion.GetVM(ctx, n.DB, name); err != nil {
			row = "row unreadable: " + err.Error()
		} else if rec != nil {
			row = "row on " + rec.HostName
		}
		dom := "no domain"
		if n.Virt.DomainExists(name) {
			dom = "domain"
		}
		out += " " + n.Name + ": " + row + ", " + dom + ";"
	}
	return out
}

// The lab's case: the VM is on node-0 (moved there after it was created),
// and its spec still pins node-1. The rebuild re-creates it on node-1, which
// has not applied the tombstone yet.
//
// Red against 1c105363 and 3e4ba50b: AlreadyExists from node-1, and the VM is
// gone.
func TestFleet_ARebuildForwardedToAPinnedHostBehindOnTheTombstoneKeepsTheVM(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	before := seedVM(t, c, n0, &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name},
	})
	lagFrom(c, n0, c.Nodes[1:]...)

	vm, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"})
	if err != nil {
		t.Fatalf("rebuild of a VM pinned to a host behind on the tombstone: %v; %s", err, whereIs(c, "web"))
	}
	if vm.GetHostName() != n1.Name {
		t.Errorf("rebuilt on %s, want %s", vm.GetHostName(), n1.Name)
	}
	assertReCreated(t, c, "web", before, n1)
	assertOnlyDeleterTombstoned(t, c, n0)
}

// Placement, not a pin, puts the rebuilt VM on another host: the one host
// carrying the label its spec requires.
func TestFleet_ARebuildPlacedOnAnotherHostBehindOnTheTombstoneKeepsTheVM(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	labelHost(t, c, n1, "rack", "b")
	before := seedVM(t, c, n0, &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Require: map[string]string{"rack": "b"}},
	})
	lagFrom(c, n0, c.Nodes[1:]...)

	vm, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"})
	if err != nil {
		t.Fatalf("rebuild placed on a host behind on the tombstone: %v; %s", err, whereIs(c, "web"))
	}
	if vm.GetHostName() != n1.Name {
		t.Errorf("rebuilt on %s, want %s", vm.GetHostName(), n1.Name)
	}
	assertReCreated(t, c, "web", before, n1)
	assertOnlyDeleterTombstoned(t, c, n0)
}

// A rolling recreate run from node-2 of a VM on node-0, whose desired spec
// pins node-1: the delete runs on node-0, the create on node-1, and neither
// node-2 nor node-1 has the tombstone yet.
func TestFleet_ARollingRecreatePinnedToAnotherHostBehindOnTheTombstoneKeepsTheVM(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	before := seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	lagFrom(c, n0, n1, n2)

	desired := &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}
	if err := recreateOn(t, n2, c.SelfClient(n2), "web", desired); err != nil {
		t.Fatalf("rolling recreate onto a host behind on the tombstone: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
	assertOnlyDeleterTombstoned(t, c, n0)
}

// A rolling recreate whose create stays on the node running the rollout: the
// stale row is the entry node's own.
func TestFleet_ARollingRecreatePlacedOnTheEntryBehindOnTheTombstoneKeepsTheVM(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n2 := c.Nodes[0], c.Nodes[2]
	labelHost(t, c, n2, "rack", "c")
	before := seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	lagFrom(c, n0, c.Nodes[1:]...)

	desired := &pb.VMSpec{
		Name: "web", Cpu: 2, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Require: map[string]string{"rack": "c"}},
	}
	if err := recreateOn(t, n2, c.SelfClient(n2), "web", desired); err != nil {
		t.Fatalf("rolling recreate placed on its own entry node, behind on the tombstone: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n2)
	assertOnlyDeleterTombstoned(t, c, n0)
}

// The host the rebuild lands on cannot receive replication at all, while the
// forwarded create still reaches it. It waits, bounded,
// for the tombstone, then retires its stale copy itself and creates the VM;
// when the link heals, the late tombstone kills nothing.
//
// Mutation: refuse instead of retiring once the wait runs out — red.
func TestFleet_ARebuildOntoAHostCutOffFromTheTombstoneRetiresItsStaleCopy(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	before := seedVM(t, c, n0, &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name},
	})
	n1.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	n0.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	// Nothing reaches node-1, directly or relayed through node-2.
	c.SetLinkFault(n0, n1, LinkFault{Block: true})
	c.SetLinkFault(c.Nodes[2], n1, LinkFault{Block: true})

	if _, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild onto a host cut off from the tombstone: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
}

// The host the rebuild lands on is on an older build: it ignores the identity
// of the VM being replaced and refuses AlreadyExists until its replica has the
// tombstone. The entry asks again until then.
//
// Mutation: drop the AlreadyExists retry in forwardCreateVM — red.
func TestFleet_ARebuildOntoAnOlderHostBehindOnTheTombstoneKeepsTheVM(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1 := c.Nodes[0], c.Nodes[1]
	before := seedVM(t, c, n0, &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name},
	})
	// An older build never reads the replaced VM's identity: drop it from
	// every create n1 serves.
	older := func(ctx context.Context, req any, handler grpc.UnaryHandler) (any, error) {
		md, _ := metadata.FromIncomingContext(ctx)
		md = md.Copy()
		md.Delete("x-litevirt-recreate-replaces")
		return handler(metadata.NewIncomingContext(ctx, md), req)
	}
	for i := 0; i < 200; i++ {
		n1.HookUnary("CreateVM", older)
		n1.HookUnary("ExecuteCreateVM", older)
	}
	// node-0's tombstone reaches node-1 neither directly nor relayed through
	// node-2 for a second, so only the entry's retry can carry the create.
	c.SetLinkFault(n0, n1, LinkFault{Delay: time.Second})
	c.SetLinkFault(c.Nodes[2], n1, LinkFault{Delay: time.Second})

	if _, err := c.SelfClient(n0).RebuildVM(context.Background(), &pb.RebuildVMRequest{Name: "web"}); err != nil {
		t.Fatalf("rebuild onto an older host behind on the tombstone: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
}

// The deleter acts on a stale view: a failover moved the VM to node-1, where
// it runs, and node-0 has not heard. A rebuild run on node-0 tears down
// node-0's leftover and forwards the create to node-1 (the spec pin). node-0's
// tombstone is guarded by its own view and does not kill node-1's row; node-1
// must not retire it either, nor touch the running domain. The rebuild is
// refused there, as on main, and the VM on node-1 survives.
//
// Red against 709113aa: node-1 retired its row after the wait and the create
// destroyed and redefined its running domain.
func TestFleet_AStaleRebuildNeverTakesTheVMAFailoverMovedToTheTarget(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	seedVM(t, c, n0, &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name},
	})
	n1.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	n0.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	// node-0 hears nothing from here on.
	c.SetLinkFault(n1, n0, LinkFault{Block: true})
	c.SetLinkFault(n2, n0, LinkFault{Block: true})
	ctx := context.Background()
	if err := corrosion.TransferVMOwnerFresh(ctx, n1.DB, "web", n1.Name, "running"); err != nil {
		t.Fatalf("failover to %s: %v", n1.Name, err)
	}
	xml := `<domain><name>web</name><uuid>5d1c4b2a-0e9f-4a7b-8c6d-1f2e3a4b5c6d</uuid></domain>`
	if err := n1.Virt.DefineDomain(xml); err != nil {
		t.Fatal(err)
	}
	n1.Virt.SetState("web", libvirtfake.StateRunning)
	moved, _ := corrosion.GetVM(ctx, n1.DB, "web")

	_, err := c.SelfClient(n0).RebuildVM(ctx, &pb.RebuildVMRequest{Name: "web"})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("stale rebuild onto the host a failover moved the VM to: got %v, want AlreadyExists", err)
	}
	if got := n1.Virt.DefinedXML("web"); got != xml {
		t.Fatalf("the running VM on %s was replaced: domain now %s", n1.Name, got)
	}
	if st, _ := n1.Virt.RawState("web"); st != libvirtfake.StateRunning {
		t.Fatalf("the VM on %s is no longer running: %v", n1.Name, st)
	}
	c.SetLinkFault(n0, n1, LinkFault{})
	time.Sleep(2 * time.Second)
	rec, err := corrosion.GetVM(ctx, n1.DB, "web")
	if err != nil || rec == nil || rec.CreatedAt != moved.CreatedAt || rec.HostName != n1.Name || rec.OwnerEpoch != moved.OwnerEpoch {
		t.Fatalf("the failed-over VM's row on %s: %+v (%v); want it as the failover left it: %+v", n1.Name, rec, err, moved)
	}
}

// A rolling recreate whose delete finds the VM already gone (someone else
// deleted it; this node's replica has not heard) deleted nothing. It names no
// replaced VM, so the stale row here is refused as on main — nothing is
// re-created on this node's stale word — and the error claims no teardown.
//
// Red against 709113aa: the create named the VM as replaced, retired the
// stale row and re-created a VM someone had deleted.
func TestFleet_ARecreateWhoseDeleteFoundNothingNamesNoReplacedVM(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	n2.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	c.SetLinkFault(n0, n2, LinkFault{Block: true})
	c.SetLinkFault(n1, n2, LinkFault{Block: true})
	ctx := context.Background()
	if err := corrosion.DeleteVM(ctx, n0.DB, "web"); err != nil {
		t.Fatal(err)
	}
	if err := n0.Virt.UndefineDomain("web", false); err != nil {
		t.Fatal(err)
	}

	err := recreateOn(t, n2, c.SelfClient(n2), "web", &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 256,
		Placement: &pb.PlacementSpec{Host: n2.Name}})
	if status.Code(err) != codes.AlreadyExists || strings.Contains(err.Error(), "torn down") {
		t.Fatalf("recreate whose delete found the VM gone: got %v, want AlreadyExists claiming no teardown", err)
	}
	if n2.Virt.DomainExists("web") {
		t.Fatalf("a VM someone deleted was re-created on %s", n2.Name)
	}
}

// A rolling recreate run from node-2, whose replica is one write behind the
// VM's owner node-0: an ownership write on node-0 (owner epoch +1) reached
// node-1 but not node-2. The delete runs on node-0, against node-0's row; the
// create goes to node-1, which holds that same row and has not applied the
// tombstone yet. The VM the create replaces must be the row the owner
// actually deleted, not node-2's stale copy of it: node-1's row is ahead of
// node-2's copy, and refusing it for that loses the VM.
//
// Red against 0fdfb8ac: recreateAs sent node-2's view; node-1 refused
// AlreadyExists and the VM was gone.
func TestFleet_ARollingRecreateFromAReplicaBehindTheOwnerKeepsTheVM(t *testing.T) {
	c := newRebuildRaceFleet(t)
	n0, n1, n2 := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	before := seedVM(t, c, n0, &pb.VMSpec{Name: "web", Cpu: 1, MemoryMib: 256})
	n2.Server.SetReplacedTombstoneWaitForTest(500 * time.Millisecond)
	// node-2 hears nothing from here on.
	c.SetLinkFault(n0, n2, LinkFault{Block: true})
	c.SetLinkFault(n1, n2, LinkFault{Block: true})
	ctx := context.Background()
	if err := corrosion.TransferVMOwnerFresh(ctx, n0.DB, "web", n0.Name, "stopped"); err != nil {
		t.Fatalf("ownership write on %s: %v", n0.Name, err)
	}
	owner, _ := corrosion.GetVM(ctx, n0.DB, "web")
	deadline := time.Now().Add(20 * time.Second)
	for {
		if rec, _ := corrosion.GetVM(ctx, n1.DB, "web"); rec != nil && rec.OwnerEpoch == owner.OwnerEpoch {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never applied %s's ownership write", n1.Name, n0.Name)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stale, _ := corrosion.GetVM(ctx, n2.DB, "web"); stale == nil || stale.OwnerEpoch >= owner.OwnerEpoch {
		t.Fatalf("%s is not behind the owner: %+v, owner epoch %d", n2.Name, stale, owner.OwnerEpoch)
	}
	// From here node-0's tombstone takes a while to reach node-1.
	c.SetLinkFault(n0, n1, LinkFault{Delay: raceLag})

	desired := &pb.VMSpec{Name: "web", Cpu: 2, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n1.Name}}
	if err := recreateOn(t, n2, c.SelfClient(n2), "web", desired); err != nil {
		t.Fatalf("rolling recreate from a replica behind the owner: %v; %s", err, whereIs(c, "web"))
	}
	assertReCreated(t, c, "web", before, n1)
}
