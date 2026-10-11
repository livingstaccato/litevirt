// Fleet scenarios for failback after maintenance, on INDEPENDENT replicas: every
// node has its own database and the production push loop carries the drain
// record, the spend of it and every ownership change between them, so a node's
// decision can be made on a replica that lags a peer's. SharedCRDT, which has
// one database and so no lag, cannot reach any of the races below.
package fleet

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

type fbScenario struct {
	c       *Cluster
	a, b, x *Node // a is drained and returns; b receives its VMs; x is a third host (nil with two nodes)
}

// newFB starts nodes independent replicas, wired as the daemon wires the
// release-feature gate. With latch, the upgrade has finished: the cluster-policy
// gate (failover_scope_v1) and the release token, whose drain_failback feature
// failback is, have latched on every node. Without it neither has, and nothing
// may be recorded or failed back.
func newFB(t *testing.T, nodes int, latch bool) *fbScenario {
	t.Helper()
	f, gates := startFB(t, nodes)
	if latch {
		latchFailoverScope(t, f.c, gates)
		latchReleaseToken(t, f.c, gates)
	}
	return f
}

func startFB(t *testing.T, nodes int) (*fbScenario, map[string]*health.Checker) {
	t.Helper()
	c := New(t, Options{Nodes: nodes, IndependentReplicas: true})
	t.Cleanup(c.Stop)
	gates := enforceGate(t, c)
	wireReleaseFeatures(t, c, gates)
	t.Cleanup(grpcapi.SetFailbackPauseForTest(time.Millisecond))
	c.WaitConverged(t, convergeTimeout)
	f := &fbScenario{c: c, a: c.Nodes[0], b: c.Nodes[1]}
	if nodes > 2 {
		f.x = c.Nodes[2]
	}
	return f, gates
}

func latchFailoverScope(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(context.Background(), capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch on a uniform fleet", n.Name)
		}
	}
}

// latchReleaseToken latches the release token on every node, the HA monitor's
// job in production.
func latchReleaseToken(t *testing.T, c *Cluster, gates map[string]*health.Checker) {
	t.Helper()
	for _, n := range c.Nodes {
		n := n
		eventually(t, 10*time.Second, n.Name+" to latch the release token", func() bool {
			return gates[n.Name].Enforced(context.Background(), capabilities.ReleaseToken) &&
				gates[n.Name].DurablyLatched(capabilities.ReleaseToken)
		})
	}
}

// fbGrant is the drain_failback grant a test hands a writer it calls directly
// to stage a scenario.
func fbGrant(t *testing.T) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeatureDrainFailback)
}

// addVM adds a running VM on n whose only disk is on shared storage, so a drain
// live-migrates it and a failback may. The row is written on n and travels.
func (f *fbScenario) addVM(t *testing.T, name string, n *Node, place *pb.PlacementSpec) {
	t.Helper()
	spec, err := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256, Placement: place})
	if err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(f.c.tmpRoot, "nfs", name+"-root.qcow2")
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: n.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: name, DiskName: "root", HostName: n.Name, Path: disk, SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vda"},
	}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	if err := n.Virt.DefineDomain(`<domain type='kvm'><name>` + name + `</name><uuid>` + uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String() +
		`</uuid><devices><disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + disk + `'/><target dev='vda'/></disk></devices></domain>`); err != nil {
		t.Fatalf("define %s: %v", name, err)
	}
	if err := n.Virt.StartDomain(name); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	f.c.WaitConverged(t, convergeTimeout)
}

// fillA puts a VM on a that takes all the memory the placement engine will
// give it, so no other VM fits there. The row is written on a and travels.
func (f *fbScenario) fillA(t *testing.T) {
	t.Helper()
	h, err := corrosion.GetHost(context.Background(), f.a.DB, f.a.Name)
	if err != nil || h == nil {
		t.Fatalf("GetHost: %v %v", h, err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "hog", Cpu: 1, MemoryMib: int32(h.MemTotal)})
	if err := corrosion.InsertVM(context.Background(), f.a.DB, corrosion.VMRecord{
		Name: "hog", HostName: f.a.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: int(h.MemTotal),
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM hog: %v", err)
	}
	f.a.Virt.SetState("hog", "running")
	f.c.WaitConverged(t, convergeTimeout)
}

func (f *fbScenario) vmAt(t *testing.T, n *Node, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s on %s: %v %v", name, n.Name, vm, err)
	}
	return vm
}

// drain drains a, whose VMs land on dst (libvirt's move emulated a -> dst), and
// lets the records travel.
func (f *fbScenario) drain(t *testing.T, dst *Node) {
	t.Helper()
	emulateLibvirtMove(f.a, dst)
	st, err := f.c.SelfClient(f.a).DrainHost(context.Background(), &pb.DrainHostRequest{Name: f.a.Name})
	if err != nil {
		t.Fatalf("DrainHost: %v", err)
	}
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("drain: %v", rerr)
		}
		if p.Error != "" {
			t.Fatalf("drain of %s: %s", p.VmName, p.Error)
		}
	}
	// The records are written after the drain's frames, off its result path.
	f.a.Server.WaitDrainRecordsForTest()
	f.c.WaitConverged(t, convergeTimeout)
}

// undrain undrains a at node at. Host state is written on one node and travels,
// like everything else here; the other replicas hear of it shortly, and a move
// whose owner is still behind waits for that (failbackNotActiveWait).
func (f *fbScenario) undrain(t *testing.T, at *Node) *pb.Host {
	t.Helper()
	h, err := f.c.SelfClient(at).UndrainHost(context.Background(), &pb.UndrainHostRequest{Name: f.a.Name})
	if err != nil {
		t.Fatalf("UndrainHost: %v", err)
	}
	return h
}

// undrainSettled is undrain, then lets every replica hear it, for a scenario that
// serves the failback from another node.
func (f *fbScenario) undrainSettled(t *testing.T, at *Node) {
	t.Helper()
	f.undrain(t, at)
	f.c.WaitConverged(t, convergeTimeout)
}

// xOut takes the third host out of placement for the drain, and xIn puts it
// back, each as a write on one node that travels (a per-node write would leave
// the replicas apart for good).
func (f *fbScenario) xOut(t *testing.T) {
	t.Helper()
	if err := corrosion.UpdateHostState(context.Background(), f.a.DB, f.x.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	f.c.WaitConverged(t, convergeTimeout)
}

func (f *fbScenario) xIn(t *testing.T) {
	t.Helper()
	if err := corrosion.UpdateHostState(context.Background(), f.a.DB, f.x.Name, "active"); err != nil {
		t.Fatal(err)
	}
	f.c.WaitConverged(t, convergeTimeout)
}

func collect(t *testing.T, st interface {
	Recv() (*pb.FailbackProgress, error)
}) (map[string]*pb.FailbackProgress, error) {
	t.Helper()
	got := map[string]*pb.FailbackProgress{}
	for {
		p, err := st.Recv()
		if err == io.EOF {
			return got, nil
		}
		if err != nil {
			return got, err
		}
		got[p.VmName] = p
	}
}

// failback runs FailbackHost for a on the daemon at, and returns each VM's frame.
func (f *fbScenario) failback(t *testing.T, at *Node, req *pb.FailbackHostRequest) (map[string]*pb.FailbackProgress, error) {
	t.Helper()
	req.Name = f.a.Name
	st, err := f.c.SelfClient(at).FailbackHost(context.Background(), req)
	if err != nil {
		return nil, err
	}
	return collect(t, st)
}

func (f *fbScenario) origins(t *testing.T, n *Node) []corrosion.DrainOrigin {
	t.Helper()
	o, err := corrosion.ListDrainOrigins(context.Background(), n.DB, f.a.Name)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func waitHostOf(t *testing.T, f *fbScenario, vm, host string) {
	t.Helper()
	eventually(t, 10*time.Second, vm+" on "+host, func() bool { return f.vmAt(t, f.a, vm).HostName == host })
}

// A drain records what it moved, the record reaches the other nodes, and a
// failback served by a node that is neither the returning host nor the VM's
// host moves it back live, through the owner.
//
// Mutation: skip recordDrainOrigin in DrainHost - nothing to fail back.
func TestFleet_Failback_MovesADrainedVMBack(t *testing.T) {
	f := newFB(t, 3, true)
	f.addVM(t, "web", f.a, nil)
	f.xOut(t) // the drain can only choose b
	f.drain(t, f.b)
	if vm := f.vmAt(t, f.x, "web"); vm.HostName != f.b.Name {
		t.Fatalf("x sees web on %s, want %s", vm.HostName, f.b.Name)
	}
	for _, n := range f.c.Nodes {
		if o := f.origins(t, n); len(o) != 1 || o[0].VM != "web" || o[0].To != f.b.Name {
			t.Fatalf("%s holds drain records %+v, want one for web -> %s", n.Name, o, f.b.Name)
		}
	}
	f.xIn(t)
	f.undrainSettled(t, f.a)

	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, f.x, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatalf("failback: %v", err)
	}
	if p := got["web"]; p == nil || p.Status != "moved" {
		t.Fatalf("failback result for web = %+v, want moved", p)
	}
	waitHostOf(t, f, "web", f.a.Name)
	if n := migrateCalls(f.b); n != 1 {
		t.Errorf("b started %d libvirt migrations, want the one live move back", n)
	}
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range f.c.Nodes {
		if o := f.origins(t, n); len(o) != 0 {
			t.Errorf("%s still holds a spent record: %+v", n.Name, o)
		}
	}
}

// The race that mattered: the node that serves the failback has not yet heard
// that an operator moved the VM. Its replica still shows the VM where the drain
// put it, with a live record. The move must not happen: the OWNER re-checks,
// under the VM's lock, on its own replica.
//
// Two operator moves, each a different way to look untouched to a lagging node:
// "hand" moved on to the third host, "again" moved there and back (its owner
// epoch unchanged, only the spend of its record says so).
//
// Mutation: drop the checkDrainExpectation call in migrateOwnedVM - hand is
// live-migrated from x to a, again from b to a.
func TestFleet_Failback_AServingNodeThatLagsNeverMovesAVMAnOperatorMoved(t *testing.T) {
	f := newFB(t, 3, true)
	f.addVM(t, "hand", f.a, nil)
	f.addVM(t, "again", f.a, nil)
	f.xOut(t)
	f.drain(t, f.b)
	f.xIn(t)
	f.undrainSettled(t, f.a)

	// a hears nothing more from b or x until the end.
	f.c.SetLinkFault(f.b, f.a, LinkFault{Block: true})
	f.c.SetLinkFault(f.x, f.a, LinkFault{Block: true})

	emulateLibvirtMove(f.b, f.x)
	if err := migrateAt(t, f.c, f.b, "hand", f.x.Name); err != nil {
		t.Fatalf("operator migrate: %v", err)
	}
	if err := migrateAt(t, f.c, f.b, "again", f.x.Name); err != nil {
		t.Fatalf("operator migrate: %v", err)
	}
	emulateLibvirtMove(f.x, f.b)
	if err := migrateAt(t, f.c, f.x, "again", f.b.Name); err != nil {
		t.Fatalf("operator migrate back: %v", err)
	}
	f.c.WaitConverged(t, convergeTimeout, f.b, f.x)
	for _, vm := range []string{"hand", "again"} {
		if h := f.vmAt(t, f.a, vm).HostName; h != f.b.Name {
			t.Fatalf("a already knows %s moved (on %s): the scenario needs a lagging replica", vm, h)
		}
	}
	if o := f.origins(t, f.a); len(o) != 2 {
		t.Fatalf("a's replica should still hold both live records, holds %+v", o)
	}

	emulateLibvirtMove(f.b, f.a)
	emulateLibvirtMove(f.x, f.a)
	got, err := f.failback(t, f.a, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatalf("failback: %v", err)
	}
	for _, vm := range []string{"hand", "again"} {
		if p := got[vm]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "since the drain") {
			t.Errorf("%s = %+v, want skipped: since the drain", vm, p)
		}
	}
	f.c.ClearLinkFaults()
	f.c.WaitConverged(t, convergeTimeout)
	if h := f.vmAt(t, f.a, "hand").HostName; h != f.x.Name {
		t.Errorf("hand is on %s, want it left on %s", h, f.x.Name)
	}
	if h := f.vmAt(t, f.a, "again").HostName; h != f.b.Name {
		t.Errorf("again is on %s, want it left on %s", h, f.b.Name)
	}
}

// A VM whose ownership was transferred by something that is not a migration (a
// failover re-homes it) no longer matches its record's owner epoch.
//
// Mutation: drop the owner-epoch comparison in checkDrainExpectation and in
// failbackOne.
func TestFleet_Failback_LeavesAVMWhoseOwnershipChanged(t *testing.T) {
	f := newFB(t, 2, true)
	f.addVM(t, "failedover", f.a, nil)
	f.drain(t, f.b)
	f.undrainSettled(t, f.a)
	if err := corrosion.TransferVMOwnerFresh(context.Background(), f.b.DB, "failedover", f.b.Name, "running"); err != nil {
		t.Fatal(err)
	}
	f.c.WaitConverged(t, convergeTimeout)
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, f.b, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["failedover"]; p != nil && p.Status == "moved" {
		t.Fatalf("failedover = %+v, want it left", p)
	}
	if h := f.vmAt(t, f.b, "failedover").HostName; h != f.b.Name {
		t.Errorf("failedover is on %s, want %s", h, f.b.Name)
	}
}

// Opt-in: an undrain moves back only the VMs that opted in (their own flag, or
// the cluster policy), in the background, and says so.
//
// Mutation: drop the opt-in test in failbackOne - the control VM moves too.
func TestFleet_Failback_IsOptIn(t *testing.T) {
	f := newFB(t, 2, true)
	f.addVM(t, "plain", f.a, nil)
	f.addVM(t, "optin", f.a, &pb.PlacementSpec{Failback: true})
	f.drain(t, f.b)

	emulateLibvirtMove(f.b, f.a)
	h := f.undrain(t, f.a)
	if !h.FailbackStarted || !strings.Contains(h.FailbackNote, "started in the background") || !strings.Contains(h.FailbackNote, "restarts") {
		t.Fatalf("undrain reply = started %v note %q; want it to say a run started and that a restart ends it", h.FailbackStarted, h.FailbackNote)
	}
	waitHostOf(t, f, "optin", f.a.Name)
	time.Sleep(100 * time.Millisecond)
	if f.vmAt(t, f.a, "plain").HostName != f.b.Name {
		t.Fatal("undrain moved back a VM that did not opt in")
	}
	got, err := f.failback(t, f.a, &pb.FailbackHostRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["plain"]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "not opted in") {
		t.Fatalf("plain = %+v, want skipped: not opted in", p)
	}

	// The cluster policy opts every VM in.
	if err := corrosion.SetFailbackPolicy(context.Background(), f.a.DB, fbGrant(t), true, "test"); err != nil {
		t.Fatal(err)
	}
	f.c.WaitConverged(t, convergeTimeout)
	got, err = f.failback(t, f.a, &pb.FailbackHostRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["plain"]; p == nil || p.Status != "moved" {
		t.Fatalf("plain with the policy on = %+v, want moved", p)
	}
}

// `lv host undrain --failback` is one run: the command follows the run the
// undrain started instead of starting a second, never errors for it, and never
// moves a VM that did not opt in. A second, non-following request while the run
// is going is refused with the way to follow it.
//
// Mutation: make FailbackHost start a run without looking at the running one -
// the command races its own run and one of the two is refused at random.
func TestFleet_Failback_UndrainFollowsItsOwnRun(t *testing.T) {
	f := newFB(t, 2, true)
	defer grpcapi.SetFailbackPauseForTest(1500 * time.Millisecond)()
	f.addVM(t, "o1", f.a, &pb.PlacementSpec{Failback: true})
	f.addVM(t, "o2", f.a, &pb.PlacementSpec{Failback: true})
	f.addVM(t, "plain", f.a, nil)
	f.drain(t, f.b)

	emulateLibvirtMove(f.b, f.a)
	h := f.undrain(t, f.a)
	if !h.FailbackStarted {
		t.Fatalf("undrain did not start the run: %q", h.FailbackNote)
	}
	// While it runs (the pause holds it between o1 and o2):
	if _, err := f.failback(t, f.a, &pb.FailbackHostRequest{All: true}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "--follow") {
		t.Fatalf("a second run while one is going = %v, want FailedPrecondition naming --follow", err)
	}
	got, err := f.failback(t, f.a, &pb.FailbackHostRequest{Follow: true})
	if err != nil {
		t.Fatalf("following the run: %v", err)
	}
	for _, vm := range []string{"o1", "o2"} {
		if p := got[vm]; p == nil || p.Status != "moved" {
			t.Errorf("%s = %+v, want moved", vm, p)
		}
	}
	if p := got["plain"]; p == nil || p.Status != "skipped" {
		t.Errorf("plain = %+v, want skipped", p)
	}
	if f.vmAt(t, f.a, "plain").HostName != f.b.Name {
		t.Errorf("a VM that did not opt in was moved")
	}
	// A follow after the run has finished still sees every result.
	got, err = f.failback(t, f.a, &pb.FailbackHostRequest{Follow: true})
	if err != nil || len(got) != 3 {
		t.Errorf("a late follow = %d results, %v; want the whole finished run", len(got), err)
	}
}

// Placement is respected: anti-affinity with a VM now on the returning host and
// the host's capacity each keep the VM where it is, with the reason.
//
// Mutation: skip the placement.ValidatePinned call.
func TestFleet_Failback_RespectsPlacement(t *testing.T) {
	f := newFB(t, 2, true)
	f.addVM(t, "apart", f.a, &pb.PlacementSpec{AntiAffinity: []string{"blocker"}})
	f.addVM(t, "big", f.a, nil)
	f.drain(t, f.b)
	f.undrainSettled(t, f.a)
	f.addVM(t, "blocker", f.a, nil)
	f.fillA(t)

	got, err := f.failback(t, f.b, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, vm := range []string{"apart", "big"} {
		if p := got[vm]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "not a valid placement") {
			t.Errorf("%s = %+v, want skipped: not a valid placement", vm, p)
		}
		if h := f.vmAt(t, f.b, vm).HostName; h != f.b.Name {
			t.Errorf("%s was moved to %s against placement", vm, h)
		}
	}
	if _, err := f.c.SelfClient(f.a).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "hog"}); err != nil {
		t.Fatalf("delete hog: %v", err)
	}
	f.c.WaitConverged(t, convergeTimeout)
	emulateLibvirtMove(f.b, f.a)
	got, err = f.failback(t, f.b, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["big"]; p == nil || p.Status != "moved" {
		t.Errorf("big with room = %+v, want moved", p)
	}
}

// Moves are one at a time with a pause between them.
//
// Mutation: drop the failbackPause wait in runFailback.
func TestFleet_Failback_MovesAtABoundedRate(t *testing.T) {
	f := newFB(t, 2, true)
	pause := 400 * time.Millisecond
	defer grpcapi.SetFailbackPauseForTest(pause)()
	f.addVM(t, "r1", f.a, nil)
	f.addVM(t, "r2", f.a, nil)
	f.drain(t, f.b)
	f.undrainSettled(t, f.a)
	emulateLibvirtMove(f.b, f.a)

	start := time.Now()
	got, err := f.failback(t, f.b, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if got["r1"].GetStatus() != "moved" || got["r2"].GetStatus() != "moved" {
		t.Fatalf("results = %+v", got)
	}
	if d := time.Since(start); d < pause {
		t.Errorf("two moves took %v, want at least one pause (%v) between them", d, pause)
	}
}

// --dry-run reports and moves nothing, and spends nothing.
func TestFleet_Failback_DryRunMovesNothing(t *testing.T) {
	f := newFB(t, 2, true)
	f.addVM(t, "d1", f.a, nil)
	f.drain(t, f.b)
	f.undrainSettled(t, f.a)
	got, err := f.failback(t, f.b, &pb.FailbackHostRequest{All: true, DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["d1"]; p == nil || p.Status != "would-move" {
		t.Fatalf("dry run = %+v, want would-move", p)
	}
	if f.vmAt(t, f.b, "d1").HostName != f.b.Name || migrateCalls(f.b) != 0 || len(f.origins(t, f.b)) != 1 {
		t.Fatal("a dry run moved a VM or spent a record")
	}
}

// The host must be active; a stopped VM and one with a host-local disk are
// reported, on the VM's events, and left with their records.
func TestFleet_Failback_RefusesADrainingHostAndLeavesWhatItCannotMoveLive(t *testing.T) {
	f := newFB(t, 2, true)
	f.addVM(t, "live", f.a, nil)
	f.drain(t, f.b)
	if _, err := f.failback(t, f.b, &pb.FailbackHostRequest{All: true}); err == nil || !strings.Contains(err.Error(), "undrain") {
		t.Fatalf("failback to a draining host = %v, want refused, naming undrain", err)
	}
	f.undrainSettled(t, f.a)

	ctx := context.Background()
	for _, name := range []string{"stopped", "local"} {
		state, disk := "running", "nfs"
		if name == "stopped" {
			state = "stopped"
		} else {
			disk = "local"
		}
		spec, _ := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256})
		if err := corrosion.InsertVM(ctx, f.b.DB, corrosion.VMRecord{
			Name: name, HostName: f.b.Name, State: state, Spec: string(spec), CPUActual: 1, MemActual: 256,
		}, nil, []corrosion.DiskRecord{
			{VMName: name, DiskName: "root", HostName: f.b.Name, Path: "/x/" + name, SizeBytes: 1 << 30, StorageType: disk, TargetDev: "vda"},
		}); err != nil {
			t.Fatal(err)
		}
		vm, _ := corrosion.GetVM(ctx, f.b.DB, name)
		if err := corrosion.PutDrainOrigin(ctx, f.b.DB, fbGrant(t), corrosion.DrainOrigin{
			VM: name, From: f.a.Name, To: f.b.Name, Epoch: vm.OwnerEpoch, CreatedAt: vm.CreatedAt}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	f.c.WaitConverged(t, convergeTimeout)
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, f.b, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["stopped"]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "stopped") {
		t.Errorf("stopped = %+v, want skipped: stopped", p)
	}
	if p := got["local"]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "host-local") {
		t.Errorf("local = %+v, want skipped: host-local", p)
	}
	if got["live"].GetStatus() != "moved" {
		t.Errorf("live = %+v, want moved", got["live"])
	}
	evs, _ := corrosion.ListVMEvents(ctx, f.b.DB, "local", 20, "")
	found := false
	for _, e := range evs {
		found = found || (e.Type == "vm.failback" && strings.Contains(e.Detail, "host-local"))
	}
	if !found {
		t.Errorf("the skip of local is not on the VM's events: %+v", evs)
	}
	if n := len(f.origins(t, f.b)); n != 2 {
		t.Errorf("%d records left, want the two that could not move live", n)
	}
}

// Until every host runs the release that cancels drain records, nothing is
// recorded, failback refuses and says it waits for the upgrade, and an undrain
// behaves as it always has (and says so when the policy is on).
//
// Mutation: drop the failbackFeatureGate call in recordDrainOrigin - a record
// reaches every replica; drop it in failbackPreflight - the failback runs.
func TestFleet_Failback_WaitsForTheUpgrade(t *testing.T) {
	f := newFB(t, 2, false)
	f.addVM(t, "w", f.a, nil)
	f.drain(t, f.b)
	if f.vmAt(t, f.b, "w").HostName != f.b.Name {
		t.Fatal("the drain itself must not depend on the gate")
	}
	for _, n := range f.c.Nodes {
		assertNoPolicyStatements(t, n)
	}
	for _, n := range f.c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
	if err := corrosion.SetFailbackPolicy(context.Background(), f.a.DB, fbGrant(t), true, "test"); err != nil {
		t.Fatal(err)
	}
	h := f.undrain(t, f.a)
	if h.FailbackStarted || !strings.Contains(h.FailbackNote, "waits for the upgrade") {
		t.Fatalf("undrain reply = started %v note %q, want it to say failback waits for the upgrade", h.FailbackStarted, h.FailbackNote)
	}
	if _, err := f.failback(t, f.a, &pb.FailbackHostRequest{All: true}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "waits for the upgrade") {
		t.Fatalf("failback before the upgrade = %v, want FailedPrecondition: waits for the upgrade", err)
	}
	if f.vmAt(t, f.a, "w").HostName != f.b.Name {
		t.Fatal("a VM moved back before the upgrade finished")
	}
}

// Mid-roll: failover_scope_v1 latched long ago (an older release carries it),
// but one host still runs a build without the release token, so drain_failback
// cannot be used. The drain moves the VM as always and records nothing, the
// policy change is refused with the release refusal, failback refuses, and the
// feature is used nowhere. Once that host is upgraded, the first write of the
// feature's data records the use, and every replica holds that record by the
// time the write returns: before the data, which is still travelling.
//
// Mutation: put back the failbackFeatureGate stub (the failover_scope_v1 latch)
// - the drain records w; call corrosion.SetFailbackPolicy without the gate - the
// policy is written mid-roll.
func TestFleet_Failback_WaitsForTheReleaseToken(t *testing.T) {
	ctx := context.Background()
	f, gates := startFB(t, 3)
	latchFailoverScope(t, f.c, gates)
	f.xOut(t)
	// x is still on the previous release: it advertises everything a build
	// before the release token does, and not the token.
	for _, n := range f.c.Nodes {
		n := n
		gates[n.Name].SetPeerPinger(func(pctx context.Context, host string) ([]string, time.Time, error) {
			caps, wall, err := n.Server.PeerCapabilities(pctx, host)
			if host == f.x.Name {
				caps = slices.DeleteFunc(slices.Clone(caps), func(c string) bool { return c == capabilities.ReleaseToken })
			}
			return caps, wall, err
		})
	}

	f.addVM(t, "w", f.a, nil)
	f.drain(t, f.b)
	if f.vmAt(t, f.b, "w").HostName != f.b.Name {
		t.Fatal("the drain itself must not depend on the release token")
	}
	wantRefusal := "the cluster upgrade must finish first (" + string(capabilities.FeatureDrainFailback) + " needs " + capabilities.ReleaseToken + ")"
	_, err := f.c.SelfClient(f.a).SetFailbackPolicy(ctx, &pb.SetFailbackPolicyRequest{Enabled: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), wantRefusal) || !strings.Contains(err.Error(), f.x.Name) {
		t.Fatalf("lv cluster failback on mid-roll = %v, want FailedPrecondition %q naming %s", err, wantRefusal, f.x.Name)
	}
	f.c.WaitConverged(t, convergeTimeout, f.a, f.b)
	for _, n := range []*Node{f.a, f.b} {
		if o := f.origins(t, n); len(o) != 0 {
			t.Fatalf("%s holds drain records mid-roll: %+v", n.Name, o)
		}
		if p, _ := corrosion.GetFailbackPolicy(ctx, n.DB); p.Enabled || p.SetBy != "" {
			t.Fatalf("%s holds a failback policy written mid-roll: %+v", n.Name, p)
		}
		if featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureDrainFailback)) {
			t.Fatalf("%s records drain_failback as used, mid-roll", n.Name)
		}
	}
	h := f.undrain(t, f.a)
	if h.FailbackStarted {
		t.Fatalf("undrain mid-roll started a failback: %q", h.FailbackNote)
	}
	if _, err := f.failback(t, f.a, &pb.FailbackHostRequest{All: true}); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), wantRefusal) {
		t.Fatalf("failback mid-roll = %v, want FailedPrecondition %q", err, wantRefusal)
	}
	if f.vmAt(t, f.a, "w").HostName != f.b.Name {
		t.Fatal("a VM moved back mid-roll")
	}

	// x is upgraded: the token latches, and the first write of the feature's
	// data records the use on every replica before it runs.
	for _, n := range f.c.Nodes {
		gates[n.Name].SetPeerPinger(n.Server.PeerCapabilities)
	}
	latchReleaseToken(t, f.c, gates)
	var st *pb.FailbackPolicyStatus
	eventually(t, 10*time.Second, "the failback policy to be accepted after the upgrade", func() bool {
		st, err = f.c.SelfClient(f.a).SetFailbackPolicy(ctx, &pb.SetFailbackPolicyRequest{Enabled: true})
		return err == nil
	})
	if !st.GetEnabled() || !st.GetSettable() {
		t.Fatalf("policy after the upgrade = %+v", st)
	}
	for _, n := range f.c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureDrainFailback)) {
			t.Fatalf("%s does not hold the drain_failback use record although the policy write has returned", n.Name)
		}
	}
	f.c.WaitConverged(t, convergeTimeout)
	for _, n := range f.c.Nodes {
		if p, _ := corrosion.GetFailbackPolicy(ctx, n.DB); !p.Enabled {
			t.Fatalf("%s has not received the policy", n.Name)
		}
	}

	// A drain now records what it moved, and the undrain, with the policy on,
	// fails that VM back; w, drained before the upgrade, has no record and stays.
	f.addVM(t, "w2", f.a, nil)
	// The quorum view enforceGate seeded predates the gap since the checker's
	// last beat, which it reads as a stall; the HA monitor beats and probes in
	// production. One beat first, then a fresh view.
	for _, n := range f.c.Nodes {
		gates[n.Name].QuorumProof(ctx)
		peers := map[string]bool{}
		for _, o := range f.c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
	f.drain(t, f.b)
	if o := f.origins(t, f.x); len(o) != 1 || o[0].VM != "w2" {
		t.Fatalf("records after the upgrade = %+v, want w2's alone", o)
	}
	emulateLibvirtMove(f.b, f.a)
	if h := f.undrain(t, f.a); !h.FailbackStarted {
		t.Fatalf("undrain with the policy on started no failback: %q", h.FailbackNote)
	}
	got, err := f.failback(t, f.a, &pb.FailbackHostRequest{Follow: true})
	if err != nil {
		t.Fatal(err)
	}
	if got["w2"].GetStatus() != "moved" {
		t.Fatalf("w2 = %+v, want moved", got["w2"])
	}
	if _, ok := got["w"]; ok || f.vmAt(t, f.a, "w").HostName != f.b.Name {
		t.Fatalf("w, drained before the upgrade, was considered (%+v) or moved", got["w"])
	}
}

// A recipient that never acknowledges the drain_failback use record must not
// slow a drain down (secure, don't remove: main's drain has no record and no
// wait). x is a voter that never answers that it holds the record, so the
// first use's acknowledgement wait would run for 30s per VM. A 10-VM drain
// still ends as fast as main's: the records are written after the frames, one
// gate attempt is made and bounded by 3s, and the backoff it starts skips the
// other nine without asking again, each skip on the VM's events. Once x
// answers and the backoff has run out, a drain records again.
//
// Mutations: record inside the result collector - the drain takes the record
// budget; drop the backoff - the gate is asked for every VM; drop the budget -
// the attempt runs the full acknowledgement wait.
func TestFleet_Failback_AnUnacknowledgingRecipientNeverSlowsADrain(t *testing.T) {
	ctx := context.Background()
	f, gates := startFB(t, 3)
	latchFailoverScope(t, f.c, gates)
	latchReleaseToken(t, f.c, gates)
	f.xOut(t)
	t.Cleanup(grpcapi.SetDrainRecordTimingForTest(3*time.Second, 2*time.Second))

	var mu sync.Mutex
	var asks []time.Time
	silent := true
	gates[f.a.Name].SetReleaseUseConfirmer(func(cctx context.Context, host, tok, feature string) (bool, error) {
		mu.Lock()
		asks = append(asks, time.Now())
		mute := silent && host == f.x.Name
		mu.Unlock()
		if mute {
			return false, nil
		}
		return f.a.Server.PeerHoldsReleaseFeatureUse(cctx, host, tok, feature)
	})

	var names []string
	for i := 0; i < 10; i++ {
		n := fmt.Sprintf("v%d", i)
		names = append(names, n)
		f.addVM(t, n, f.a, nil)
	}
	emulateLibvirtMove(f.a, f.b)
	start := time.Now()
	st, err := f.c.SelfClient(f.a).DrainHost(ctx, &pb.DrainHostRequest{Name: f.a.Name})
	if err != nil {
		t.Fatalf("DrainHost: %v", err)
	}
	frames := 0
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("drain: %v", rerr)
		}
		if p.Error != "" {
			t.Fatalf("drain of %s: %s", p.VmName, p.Error)
		}
		if p.Status == "done" {
			frames++
		}
	}
	elapsed := time.Since(start)
	if frames != 10 {
		t.Fatalf("%d done frames, want 10", frames)
	}
	// Main's budget: a drain of these emulated moves takes well under a second;
	// one record's wait (3s) inside the drain would show.
	if elapsed >= 3*time.Second {
		t.Fatalf("the drain took %s with a recipient that never acknowledges; it must not wait on drain records", elapsed)
	}

	f.a.Server.WaitDrainRecordsForTest()
	mu.Lock()
	first, last, n := asks[0], asks[len(asks)-1], len(asks)
	mu.Unlock()
	if span := last.Sub(first); span > 4*time.Second {
		t.Fatalf("the gate was asked over %s (%d asks): the record is bounded by 3s and the backoff stops the rest", span, n)
	}
	if o := f.origins(t, f.a); len(o) != 0 {
		t.Fatalf("records written although x never acknowledged: %+v", o)
	}
	for _, name := range names {
		evs, _ := corrosion.ListVMEvents(ctx, f.a.DB, name, 20, "")
		found := false
		for _, e := range evs {
			found = found || (e.Type == "vm.failback" && strings.Contains(e.Detail, "not recorded for failback"))
		}
		if !found {
			t.Errorf("the skipped record of %s is not on its events: %+v", name, evs)
		}
	}

	// x answers again; after the backoff a drain records.
	mu.Lock()
	silent = false
	mu.Unlock()
	time.Sleep(2100 * time.Millisecond)
	f.undrainSettled(t, f.a)
	f.addVM(t, "after", f.a, nil)
	for _, n := range f.c.Nodes {
		gates[n.Name].QuorumProof(ctx)
		peers := map[string]bool{}
		for _, o := range f.c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
	f.drain(t, f.b)
	if o := f.origins(t, f.a); len(o) != 1 || o[0].VM != "after" {
		t.Fatalf("records after x answered = %+v, want after's", o)
	}
}

// freshQuorum beats every node's checker once and seeds a fresh peer view: the
// view enforceGate seeded predates any gap since the checker's last beat, which
// it reads as a stall (the HA monitor beats and probes in production). A slow
// run (-race) opens such gaps between steps.
func freshQuorum(f *fbScenario, gates map[string]*health.Checker) {
	for _, n := range f.c.Nodes {
		gates[n.Name].QuorumProof(context.Background())
		peers := map[string]bool{}
		for _, o := range f.c.Nodes {
			if o != n {
				peers[o.Name] = true
			}
		}
		gates[n.Name].SeedPeersForTests(peers)
	}
}

// A drain's record describes the drain's move, not whatever placement the VM
// has by the time the record is written. Records are written after the drain's
// frames, behind a first use that can wait seconds for acknowledgements; in
// that window an operator moves the VMs out and back by hand (b -> x -> b).
// The records, when they land, must not describe the operator's placement, or
// a failback would take back VMs an operator placed.
//
// Mutation: build the record from the VM's row at write time (drop the
// placement the worker read when the move finished) - v2, whose record is
// written after the hand moves, is moved back to a.
func TestFleet_Failback_ARecordDescribesTheDrainsMoveNotALaterOne(t *testing.T) {
	ctx := context.Background()
	f, gates := startFB(t, 3)
	latchFailoverScope(t, f.c, gates)
	latchReleaseToken(t, f.c, gates)
	f.xOut(t)
	t.Cleanup(grpcapi.SetDrainRecordTimingForTest(30*time.Second, time.Second))

	// x holds back its acknowledgement of the first use until released, so the
	// records wait behind it.
	held := make(chan struct{})
	gates[f.a.Name].SetReleaseUseConfirmer(func(cctx context.Context, host, tok, feature string) (bool, error) {
		if host == f.x.Name {
			select {
			case <-held:
			default:
				return false, nil
			}
		}
		return f.a.Server.PeerHoldsReleaseFeatureUse(cctx, host, tok, feature)
	})

	f.addVM(t, "v1", f.a, nil)
	f.addVM(t, "v2", f.a, nil)
	freshQuorum(f, gates)
	emulateLibvirtMove(f.a, f.b)
	st, err := f.c.SelfClient(f.a).DrainHost(ctx, &pb.DrainHostRequest{Name: f.a.Name})
	if err != nil {
		t.Fatalf("DrainHost: %v", err)
	}
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("drain: %v", rerr)
		}
		if p.Error != "" {
			t.Fatalf("drain of %s: %s", p.VmName, p.Error)
		}
	}
	f.c.WaitConverged(t, convergeTimeout, f.a, f.b)

	// The operator moves both out and back while the records wait.
	f.xIn(t)
	for _, vm := range []string{"v1", "v2"} {
		freshQuorum(f, gates)
		emulateLibvirtMove(f.b, f.x)
		if err := migrateAt(t, f.c, f.b, vm, f.x.Name); err != nil {
			t.Fatalf("operator migrate %s: %v", vm, err)
		}
		f.c.WaitConverged(t, convergeTimeout)
		freshQuorum(f, gates)
		emulateLibvirtMove(f.x, f.b)
		if err := migrateAt(t, f.c, f.x, vm, f.b.Name); err != nil {
			t.Fatalf("operator migrate %s back: %v", vm, err)
		}
		f.c.WaitConverged(t, convergeTimeout)
	}
	close(held)
	f.a.Server.WaitDrainRecordsForTest()
	f.c.WaitConverged(t, convergeTimeout)

	freshQuorum(f, gates)
	f.undrainSettled(t, f.a)
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, f.x, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, vm := range []string{"v1", "v2"} {
		if p := got[vm]; p != nil && p.Status == "moved" {
			t.Errorf("%s was moved back although an operator placed it by hand after the drain: %+v", vm, p)
		}
		if h := f.vmAt(t, f.a, vm).HostName; h != f.b.Name {
			t.Errorf("%s is on %s, want it left on %s", vm, h, f.b.Name)
		}
	}
}

// The drained host's record is the last thing a drain writes and the first to be
// lost when the host goes away: it powers off for maintenance before the record
// has reached anyone. The VM, meanwhile, is moved by an operator out and back
// (b -> x -> b), and no spend can cancel a record its mover never saw. When the
// host returns its record finally replicates, and it still matches the VM's host
// and owner epoch. A VM an operator placed by hand must not be moved: failback
// may not depend on whether that record travelled in time.
//
// Mutation: drop the placement-generation comparison in checkDrainExpectation
// and failbackOne - web is moved from b to a.
func TestFleet_Failback_ARecordThatReplicatesLateNeverMovesAHandPlacedVM(t *testing.T) {
	f := newFB(t, 3, true)
	f.addVM(t, "web", f.a, nil)
	f.xOut(t)
	f.drain(t, f.b)
	f.xIn(t)

	// a powers off before its record reaches b or x: the record is on a alone.
	f.c.Isolate(f.a)
	for _, n := range []*Node{f.b, f.x} {
		if _, err := n.DB.DB().Exec(`DELETE FROM cluster_policies WHERE key = 'drain_origin/web'`); err != nil {
			t.Fatal(err)
		}
	}
	rec := f.origins(t, f.a)
	if len(rec) != 1 || len(f.origins(t, f.b)) != 0 || len(f.origins(t, f.x)) != 0 {
		t.Fatalf("setup: a holds %d record(s), b %d, x %d; want a alone", len(rec), len(f.origins(t, f.b)), len(f.origins(t, f.x)))
	}

	// The operator moves web out and back while a is away.
	emulateLibvirtMove(f.b, f.x)
	if err := migrateAt(t, f.c, f.b, "web", f.x.Name); err != nil {
		t.Fatalf("operator migrate: %v", err)
	}
	emulateLibvirtMove(f.x, f.b)
	if err := migrateAt(t, f.c, f.x, "web", f.b.Name); err != nil {
		t.Fatalf("operator migrate back: %v", err)
	}
	f.c.WaitConverged(t, convergeTimeout, f.b, f.x)

	// a returns; its record replicates, unspent.
	f.c.ClearLinkFaults()
	if err := corrosion.PutDrainOrigin(context.Background(), f.a.DB, fbGrant(t), rec[0], "drain"); err != nil {
		t.Fatal(err)
	}
	f.c.WaitConverged(t, convergeTimeout)
	if o := f.origins(t, f.b); len(o) != 1 {
		t.Fatalf("setup: b should now hold the late record, holds %+v", o)
	}

	f.undrainSettled(t, f.a)
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, f.x, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["web"]; p != nil && p.Status == "moved" {
		t.Fatalf("web was moved back although an operator placed it by hand: %+v", p)
	}
	if h := f.vmAt(t, f.a, "web").HostName; h != f.b.Name {
		t.Fatalf("web is on %s, want it left on %s", h, f.b.Name)
	}
}

// An owner on a release that does not check a failback move's preconditions
// would migrate the VM unconditionally, so the VM is skipped, never moved.
//
// Mutation: drop the owner-capability check in failbackOne - the VM is moved by
// an owner that ignores the preconditions.
func TestFleet_Failback_SkipsAVMWhoseOwnerCannotCheckThePreconditions(t *testing.T) {
	f := newFB(t, 2, true)
	f.addVM(t, "old", f.a, nil)
	f.drain(t, f.b)
	f.undrainSettled(t, f.a)
	f.b.Server.SetPingWithoutMigratePreconditionsForTest(true)
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, f.a, &pb.FailbackHostRequest{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if p := got["old"]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "older release") {
		t.Fatalf("old = %+v, want skipped: owner on an older release", p)
	}
	if h := f.vmAt(t, f.a, "old").HostName; h != f.b.Name || migrateCalls(f.b) != 0 {
		t.Fatalf("the VM was moved by an owner that cannot check (on %s)", h)
	}
}
