package fleet

// The stub ledger's record of a move must end with that move, whatever kind of
// move it was and whichever host committed the next one (round-12 review C1).
// A live move commits without bumping the owner epoch, so A→B→A made the
// first move's owner#epoch mark current again on B; the record is now bound
// to the VM's placement mark (owner, epoch and placement generation), and B
// also ends its records of a VM when it starts sending that VM elsewhere.
// The reviewer's probe, TestR12Rev_LiveStorageStubRecordDoesNotOutliveItsMove,
// is the live A→B→A→B case with the cluster-policy gate closed; the cold one
// is TestFleet_AStubRecordDoesNotOutliveItsMove.

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// liveStubABA is a two-node cluster with "pp1" running on node 0 and one
// host-local disk in a dir pool at the same path on both nodes.
type liveStubABA struct {
	c    *Cluster
	a, b *Node
	p    string
}

func newLiveStubABA(t *testing.T, gateOpen bool) *liveStubABA {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	sc := &liveStubABA{c: c, a: c.Nodes[0], b: c.Nodes[1]}
	pool := filepath.Join(c.tmpRoot, "pool")
	if err := os.MkdirAll(pool, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"local-dir": {Driver: "dir", Target: pool}})
		if gateOpen {
			n.DB.SetClusterPolicyGate(func() bool { return true })
		}
	}
	sc.p = filepath.Join(pool, "pp1-root.qcow2")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "pp1", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), sc.a.DB, corrosion.VMRecord{
		Name: "pp1", HostName: sc.a.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{{
		VMName: "pp1", DiskName: "root", HostName: sc.a.Name, Path: sc.p,
		SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatal(err)
	}
	sc.a.Virt.SetState("pp1", "running")
	return sc
}

func (sc *liveStubABA) host(t *testing.T) string {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), sc.a.DB, "pp1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM pp1: %v %v", vm, err)
	}
	return vm.HostName
}

// thirdMoveIsRefused puts a stray file at the disk's path on B (the nodes
// share a filesystem; in production B's file is B's) and moves pp1 A→B
// with its storage: the move is refused naming the file, and the file is
// left exactly as it was.
func (sc *liveStubABA) thirdMoveIsRefused(t *testing.T) {
	t.Helper()
	_ = os.Remove(sc.p)
	before := writeDisk(t, sc.p, 1<<30) // the same virtual size: a reuse would mirror over it
	err := migrateWithStorageAt(t, sc.c, sc.a, "pp1", sc.b.Name)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "this migration did not create it") {
		t.Fatalf("move over a stray file on %s = %v, want FailedPrecondition naming the file", sc.b.Name, err)
	}
	if after, rerr := os.ReadFile(sc.p); rerr != nil || string(after) != string(before) {
		t.Fatalf("the stray file on %s changed (err %v)", sc.b.Name, rerr)
	}
	if h := sc.host(t); h != sc.a.Name {
		t.Fatalf("pp1 after the refused move is on %s, want %s", h, sc.a.Name)
	}
}

// Live --with-storage A→B→A→B with the cluster-policy gate open, so the
// placement generation is kept as well.
//
// Mutations: both of the move-binding (the mark without its generation) and
// the source-side end (endMoveRecords a no-op) — red; either alone — green,
// since each closes this case on its own (the generation-only case is
// TestFleet_AStubRecordEndsWhenAFailoverMovesTheVMBack, the source-side end
// is the reviewer's probe, with the gate closed).
func TestFleet_ALiveStorageStubRecordDoesNotOutliveItsMove(t *testing.T) {
	sc := newLiveStubABA(t, true)
	if err := migrateWithStorageAt(t, sc.c, sc.a, "pp1", sc.b.Name); err != nil {
		t.Fatalf("A->B: %v", err)
	}
	_ = os.Remove(sc.p)
	sc.b.Virt.SetState("pp1", "running")
	if err := migrateWithStorageAt(t, sc.c, sc.b, "pp1", sc.a.Name); err != nil {
		t.Fatalf("B->A: %v", err)
	}
	if h := sc.host(t); h != sc.a.Name {
		t.Fatalf("pp1 after the move back is on %s, want %s", h, sc.a.Name)
	}
	sc.a.Virt.SetState("pp1", "running")
	sc.thirdMoveIsRefused(t)
}

// A VM moved A→B live with its storage, then put back on A by a move B did
// not drive — failover's reschedule, which neither bumps the owner epoch nor
// runs anything on B. The placement generation that reschedule advanced ends
// B's record of the first move.
//
// Mutation: the mark without its generation (owner#epoch, as in round 12) —
// the move over the stray is not refused, red.
func TestFleet_AStubRecordEndsWhenAFailoverMovesTheVMBack(t *testing.T) {
	sc := newLiveStubABA(t, true)
	ctx := context.Background()
	if err := migrateWithStorageAt(t, sc.c, sc.a, "pp1", sc.b.Name); err != nil {
		t.Fatalf("A->B: %v", err)
	}
	// B is lost; failover restarts pp1 on A. (The fake defines no domain on
	// B for the move, so there is none to take down there.)
	if err := corrosion.RescheduleVMHost(ctx, sc.a.DB, "pp1", sc.a.Name, "running"); err != nil {
		t.Fatalf("reschedule pp1 to %s: %v", sc.a.Name, err)
	}
	if h := sc.host(t); h != sc.a.Name {
		t.Fatalf("pp1 after the reschedule is on %s, want %s", h, sc.a.Name)
	}
	sc.a.Virt.SetState("pp1", "running")
	sc.thirdMoveIsRefused(t)
}

// drainNode drains n and returns every progress frame by VM name, plus the
// stream's final error.
func drainNode(t *testing.T, c *Cluster, n *Node) (map[string]*pb.DrainProgress, error) {
	t.Helper()
	st, err := c.SelfClient(n).DrainHost(context.Background(), &pb.DrainHostRequest{Name: n.Name})
	if err != nil {
		return nil, err
	}
	got := map[string]*pb.DrainProgress{}
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return got, nil
		}
		if rerr != nil {
			return got, rerr
		}
		got[p.VmName] = p
	}
}

// A VM drained A→B and B→A, and then drained to B again over a stray file
// at its disk path there: the third drain's move is refused naming the file,
// the file is untouched, and the VM stays on A.
//
// Mutation: bind the record to the owner alone (no epoch, no generation) and
// make the source-side end a no-op — red. A drain's commit bumps the owner
// epoch, so the epoch alone also ends the record here: the test pins that the
// binding still covers the drain's moves.
func TestFleet_ADrainStubRecordDoesNotOutliveItsMove(t *testing.T) {
	sc := newColdStoppedScenario(t)
	a, b := sc.src, sc.dst
	ctx := context.Background()
	for _, n := range []*Node{a, b} {
		n.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"local-dir": {Driver: "dir", Target: filepath.Dir(sc.disk)}})
	}
	undrain := func(n *Node) {
		t.Helper()
		if _, err := sc.c.SelfClient(n).UndrainHost(ctx, &pb.UndrainHostRequest{Name: n.Name}); err != nil {
			t.Fatalf("undrain %s: %v", n.Name, err)
		}
	}
	if _, err := drainNode(t, sc.c, a); err != nil {
		t.Fatalf("drain %s: %v", a.Name, err)
	}
	if vm := sc.vm(t); vm.HostName != b.Name {
		t.Fatalf("os1 after the first drain is on %s, want %s", vm.HostName, b.Name)
	}
	undrain(a)
	if _, err := drainNode(t, sc.c, b); err != nil {
		t.Fatalf("drain %s: %v", b.Name, err)
	}
	if vm := sc.vm(t); vm.HostName != a.Name {
		t.Fatalf("os1 after the second drain is on %s, want %s", vm.HostName, a.Name)
	}
	undrain(b)
	stray := sc.file(b, sc.disk)
	if _, err := os.Lstat(stray); !os.IsNotExist(err) {
		t.Fatalf("fixture: %s still holds os1's disk after it moved back (stat: %v)", b.Name, err)
	}
	if err := os.WriteFile(stray, []byte("a stray copy on the target"), 0o600); err != nil {
		t.Fatal(err)
	}

	progress, err := drainNode(t, sc.c, a)
	if err == nil {
		t.Fatalf("the third drain over a stray file ended complete (%v)", progress["os1"])
	}
	all := err.Error()
	if p := progress["os1"]; p != nil {
		all += " " + p.Error
	}
	if !strings.Contains(all, "this migration did not create it") {
		t.Fatalf("the third drain = %v (os1: %v), want os1's move refused naming the file", err, progress["os1"])
	}
	if got, rerr := os.ReadFile(stray); rerr != nil || string(got) != "a stray copy on the target" {
		t.Fatalf("the stray file on %s changed (err %v, %q)", b.Name, rerr, got)
	}
	if vm := sc.vm(t); vm.HostName != a.Name {
		t.Fatalf("os1 after the refused drain is on %s, want %s", vm.HostName, a.Name)
	}
}
