// Fleet scenarios for failback after maintenance: a drain records what it moved,
// and an undrain (or `lv host failback`) moves exactly those VMs back by live
// migration, never one that was moved for another reason.
//
// Multi-node by construction: the drain runs on the drained host, the record
// replicates, and the move back is a migration from another host's daemon.
package fleet

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type fbScenario struct {
	c    *Cluster
	a, b *Node // a is drained and returns; b receives its VMs
}

func newFB(t *testing.T, nodes int) *fbScenario {
	t.Helper()
	c := New(t, Options{Nodes: nodes, SharedCRDT: true})
	t.Cleanup(c.Stop)
	for _, n := range c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
	t.Cleanup(grpcapi.SetFailbackPauseForTest(time.Millisecond))
	return &fbScenario{c: c, a: c.Nodes[0], b: c.Nodes[1]}
}

// addVM adds a running VM on n whose only disk is on shared storage, so a drain
// live-migrates it and a failback may.
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
	if err := n.Virt.DefineDomain(`<domain type='kvm'><name>` + name + `</name><uuid>` + uuid.NewSHA1(uuid.NameSpaceOID, []byte(name)).String() + `</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + disk + `'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define %s: %v", name, err)
	}
	if err := n.Virt.StartDomain(name); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
}

func (f *fbScenario) vm(t *testing.T, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), f.a.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s: %v %v", name, vm, err)
	}
	return vm
}

// drain drains a, whose VMs land on dst (libvirt's move emulated a -> dst).
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
}

func (f *fbScenario) undrain(t *testing.T) {
	t.Helper()
	if _, err := f.c.SelfClient(f.a).UndrainHost(context.Background(), &pb.UndrainHostRequest{Name: f.a.Name}); err != nil {
		t.Fatalf("UndrainHost: %v", err)
	}
}

// failback runs FailbackHost for a and returns each VM's frame.
func (f *fbScenario) failback(t *testing.T, all, dry bool) (map[string]*pb.FailbackProgress, error) {
	t.Helper()
	st, err := f.c.SelfClient(f.a).FailbackHost(context.Background(), &pb.FailbackHostRequest{Name: f.a.Name, All: all, DryRun: dry})
	if err != nil {
		return nil, err
	}
	got := map[string]*pb.FailbackProgress{}
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

func (f *fbScenario) origins(t *testing.T) []corrosion.DrainOrigin {
	t.Helper()
	o, err := corrosion.ListDrainOrigins(context.Background(), f.a.DB, f.a.Name)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func waitHost(t *testing.T, f *fbScenario, vm, host string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if f.vm(t, vm).HostName == host {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%s is on %s, want %s", vm, f.vm(t, vm).HostName, host)
}

// A drain records what it moved; failback --all moves it back live, and the
// record is spent.
//
// Mutation: skip the recordDrainOrigin call in DrainHost — no record, so the
// VM is never offered for failback and stays on b.
func TestFleet_Failback_MovesADrainedVMBack(t *testing.T) {
	f := newFB(t, 2)
	f.addVM(t, "web", f.a, nil)
	f.drain(t, f.b)
	if vm := f.vm(t, "web"); vm.HostName != f.b.Name {
		t.Fatalf("drain left web on %s, want %s", vm.HostName, f.b.Name)
	}
	if o := f.origins(t); len(o) != 1 || o[0].VM != "web" || o[0].To != f.b.Name {
		t.Fatalf("drain records = %+v, want one for web -> %s", o, f.b.Name)
	}

	f.undrain(t)
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, true, false)
	if err != nil {
		t.Fatalf("failback: %v", err)
	}
	if p := got["web"]; p == nil || p.Status != "moved" {
		t.Fatalf("failback result for web = %+v, want moved", p)
	}
	if vm := f.vm(t, "web"); vm.HostName != f.a.Name || vm.State != "running" {
		t.Fatalf("web = host %s state %s after failback, want %s running", vm.HostName, vm.State, f.a.Name)
	}
	if n := migrateCalls(f.b); n != 1 {
		t.Errorf("b started %d libvirt migrations, want the one live move back", n)
	}
	if o := f.origins(t); len(o) != 0 {
		t.Errorf("the drain record survived the move back: %+v", o)
	}
}

// Undrain alone moves nothing; the VM's own opt-in, or the cluster policy,
// makes it move back by itself.
//
// Mutation: drop the `!policyOn && !spec.GetPlacement().GetFailback()` opt-in
// test — the control VM moves back too.
func TestFleet_Failback_IsOptIn(t *testing.T) {
	f := newFB(t, 2)
	f.addVM(t, "plain", f.a, nil)
	f.addVM(t, "optin", f.a, &pb.PlacementSpec{Failback: true})
	f.drain(t, f.b)

	// An undrain moves the opted-in VM back by itself, in the background, and
	// only that one.
	emulateLibvirtMove(f.b, f.a)
	f.undrain(t)
	waitHost(t, f, "optin", f.a.Name)
	time.Sleep(100 * time.Millisecond)
	if f.vm(t, "plain").HostName != f.b.Name {
		t.Fatal("undrain moved back a VM that did not opt in")
	}

	// Asked for explicitly, without --all, the one that did not opt in is
	// reported and left, and its record kept for a later opt-in.
	got, err := f.failback(t, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := got["plain"]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "not opted in") {
		t.Fatalf("plain = %+v, want skipped: not opted in", p)
	}
	if o := f.origins(t); len(o) != 1 || o[0].VM != "plain" {
		t.Fatalf("records = %+v, want only plain's kept", o)
	}

	// The cluster policy opts every VM in.
	if err := corrosion.SetFailbackPolicy(context.Background(), f.a.DB, true, "test"); err != nil {
		t.Fatal(err)
	}
	got, err = f.failback(t, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := got["plain"]; p == nil || p.Status != "moved" {
		t.Fatalf("plain with the policy on = %+v, want moved", p)
	}
}

// A VM an operator moved by hand since the drain stays where it is - wherever
// it went, including back onto the host the drain put it on. A migration spends
// the drain's record; any other ownership transfer (a failover, say) bumps the
// owner epoch, which no longer matches the record.
//
// Mutation: drop the s.spendDrainOrigin call in finalizeMigrationOwnership —
// "again" (moved on and back by hand) is moved to a. Drop the
// `vm.OwnerEpoch != o.Epoch` half of the staleness check - "failedover" is.
func TestFleet_Failback_LeavesAVMAnOperatorMoved(t *testing.T) {
	f := newFB(t, 3)
	c := f.c.Nodes[2]
	setHostCapacity(t, f.c, c.Name, 1, 1024, nil) // the drain can only choose b
	f.addVM(t, "hand", f.a, nil)
	f.addVM(t, "again", f.a, nil)
	f.addVM(t, "failedover", f.a, nil)
	f.drain(t, f.b)
	setHostCapacity(t, f.c, c.Name, 64, 65536, nil)

	// hand: moved on to c by an operator.
	emulateLibvirtMove(f.b, c)
	if err := migrateAt(t, f.c, f.b, "hand", c.Name); err != nil {
		t.Fatalf("operator migrate: %v", err)
	}
	// again: moved to c and back to b by an operator.
	if err := migrateAt(t, f.c, f.b, "again", c.Name); err != nil {
		t.Fatalf("operator migrate: %v", err)
	}
	emulateLibvirtMove(c, f.b)
	if err := migrateAt(t, f.c, c, "again", f.b.Name); err != nil {
		t.Fatalf("operator migrate back: %v", err)
	}
	// failedover: still on b, but its ownership was transferred since (a
	// failover re-homes it to the host it is on).
	if err := corrosion.TransferVMOwnerFresh(context.Background(), f.a.DB, "failedover", f.b.Name, "running"); err != nil {
		t.Fatal(err)
	}

	f.undrain(t)
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := got["failedover"]; p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "moved since the drain") {
		t.Errorf("failedover = %+v, want skipped: moved since the drain", p)
	}
	for _, vm := range []string{"hand", "again"} {
		if p := got[vm]; p != nil && p.Status == "moved" {
			t.Errorf("%s was moved back although an operator had moved it: %+v", vm, p)
		}
	}
	if h := f.vm(t, "hand").HostName; h != c.Name {
		t.Errorf("hand is on %s, want it left on %s", h, c.Name)
	}
	for _, vm := range []string{"again", "failedover"} {
		if h := f.vm(t, vm).HostName; h != f.b.Name {
			t.Errorf("%s is on %s, want it left on %s", vm, h, f.b.Name)
		}
	}
	if n := len(f.origins(t)); n != 0 {
		t.Errorf("%d stale record(s) kept; they can never apply again", n)
	}
}

// Placement is respected: anti-affinity with a VM now on the returning host, and
// the host's capacity, each keep the VM where it is, with the reason.
//
// Mutation: skip the placement.ValidatePinned call — both move back.
func TestFleet_Failback_RespectsPlacement(t *testing.T) {
	f := newFB(t, 2)
	f.addVM(t, "apart", f.a, &pb.PlacementSpec{AntiAffinity: []string{"blocker"}})
	f.addVM(t, "big", f.a, nil)
	f.drain(t, f.b)
	f.undrain(t)
	f.addVM(t, "blocker", f.a, nil) // arrives on a after the drain

	// a can hold neither the anti-affine VM nor, with its capacity cut, big.
	setHostCapacity(t, f.c, f.a.Name, 1, 1024, nil)
	got, err := f.failback(t, true, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, vm := range []string{"apart", "big"} {
		p := got[vm]
		if p == nil || p.Status != "skipped" || !strings.Contains(p.Reason, "not a valid placement") {
			t.Errorf("%s = %+v, want skipped: not a valid placement", vm, p)
		}
		if h := f.vm(t, vm).HostName; h != f.b.Name {
			t.Errorf("%s was moved to %s against placement", vm, h)
		}
	}

	// Control: the same VMs once the objections are gone.
	setHostCapacity(t, f.c, f.a.Name, 64, 65536, nil)
	if err := corrosion.UpdateVMState(context.Background(), f.a.DB, "blocker", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	// blocker still counts for anti-affinity while stopped, so only big moves.
	emulateLibvirtMove(f.b, f.a)
	got, err = f.failback(t, true, false)
	if err != nil {
		t.Fatal(err)
	}
	if p := got["big"]; p == nil || p.Status != "moved" {
		t.Errorf("big with room = %+v, want moved", p)
	}
}

// Moves are one at a time with a pause between them: the rate bound.
//
// Mutation: drop the failbackPause wait in runFailback — the two moves are
// back to back and the run is far shorter than one pause.
func TestFleet_Failback_MovesAtABoundedRate(t *testing.T) {
	f := newFB(t, 2)
	pause := 400 * time.Millisecond
	defer grpcapi.SetFailbackPauseForTest(pause)()
	f.addVM(t, "r1", f.a, nil)
	f.addVM(t, "r2", f.a, nil)
	f.drain(t, f.b)
	f.undrain(t)
	emulateLibvirtMove(f.b, f.a)

	start := time.Now()
	got, err := f.failback(t, true, false)
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

// --dry-run reports and moves nothing.
func TestFleet_Failback_DryRunMovesNothing(t *testing.T) {
	f := newFB(t, 2)
	f.addVM(t, "d1", f.a, nil)
	f.drain(t, f.b)
	f.undrain(t)
	got, err := f.failback(t, true, true)
	if err != nil {
		t.Fatal(err)
	}
	if p := got["d1"]; p == nil || p.Status != "would-move" {
		t.Fatalf("dry run = %+v, want would-move", p)
	}
	if f.vm(t, "d1").HostName != f.b.Name || migrateCalls(f.b) != 0 {
		t.Fatal("a dry run moved a VM")
	}
	if len(f.origins(t)) != 1 {
		t.Fatal("a dry run spent the record")
	}
}

// The host must be active, and a VM that is stopped or has a host-local disk is
// reported and left with its record.
func TestFleet_Failback_RefusesADrainingHostAndLeavesWhatItCannotMoveLive(t *testing.T) {
	f := newFB(t, 2)
	f.addVM(t, "live", f.a, nil)
	f.drain(t, f.b)

	if _, err := f.failback(t, true, false); err == nil || !strings.Contains(err.Error(), "undrain") {
		t.Fatalf("failback to a draining host = %v, want refused, naming undrain", err)
	}
	f.undrain(t)

	// A stopped VM and one with a host-local disk, each with a record as a
	// drain would have left it.
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
		if err := corrosion.PutDrainOrigin(ctx, f.b.DB, corrosion.DrainOrigin{
			VM: name, From: f.a.Name, To: f.b.Name, Epoch: vm.OwnerEpoch, CreatedAt: vm.CreatedAt}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	emulateLibvirtMove(f.b, f.a)
	got, err := f.failback(t, true, false)
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
	if n := len(f.origins(t)); n != 2 {
		t.Errorf("%d records left, want the two that could not move live", n)
	}
}

// Until failover_scope_v1 has latched nothing is written to cluster_policies, so
// a drain records nothing and failback has nothing to move.
func TestFleet_Failback_DrainRecordsNothingBeforeTheGateOpens(t *testing.T) {
	f := newFB(t, 2)
	for _, n := range f.c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return false })
	}
	f.addVM(t, "w", f.a, nil)
	f.drain(t, f.b)
	if f.vm(t, "w").HostName != f.b.Name {
		t.Fatal("the drain itself must not depend on the gate")
	}
	for _, n := range f.c.Nodes {
		assertNoPolicyStatements(t, n)
	}
}
