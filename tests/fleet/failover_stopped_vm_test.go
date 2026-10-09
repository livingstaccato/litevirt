// Fleet scenarios: failover leaves a stopped workload where it is (kvm003
// drill 1, merge-lab 2026-10-08).
//
// The majority fenced node-1 and rescheduled its operator-STOPPED VMs like
// running ones: their targets rebuilt each host-local disk blank from its
// image and STARTED them, and the real disks, left on node-1 and no longer
// recorded, were set aside and later deleted by the superseded-disk sweep.
// Failover now recovers only what was running: a stopped VM or container
// stays on its failed host, stopped, with its disks.
//
// Two layers enforce it, so a mutation of either one alone is caught by a
// different scenario here:
//
//   - the coordinator's first check in recoverWorkloads / relocateContainers.
//     Without it, a stopped VM is CLAIMED for a recovery before the write is
//     refused (TestFleet_FailoverClaimsNothingForAStoppedVM), and a stopped
//     container with no image to re-pull has its operator stop overwritten
//     with relocate-skipped (TestFleet_FailoverLeavesStoppedContainers);
//   - the write guard (`state <> 'stopped'`) in WriteVMRescheduleProof,
//     RescheduleVMHost and the container writes. Without it, a stop that
//     lands after the coordinator chose the VM is overwritten with "pending"
//     (TestFleet_AStopAfterSelectionWinsOverTheReschedule).
//
// TestFleet_FailoverLeavesAStoppedVMWithItsDisk goes red only with both
// removed, which is defence in depth, not a weak assertion: it pins the
// outcome the drill got wrong, end to end through the target's reconciler.

package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// insertVMInState is insertVM with a state.
func insertVMInState(t *testing.T, n *Node, name, host, state string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, Spec: `{"on_host_failure":"restart-any"}`, State: state,
		StateDetail: map[bool]string{true: "operator-stop"}[state == "stopped"],
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s on %s: %v", name, n.Name, err)
	}
}

// proofsFor lists every ownership-transfer proof n's replica holds for target.
func proofsFor(t *testing.T, n *Node, target string) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT id FROM runtime_action_proofs WHERE target_name = ? AND deleted_at IS NULL`, target)
	if err != nil {
		t.Fatalf("%s: read proofs: %v", n.Name, err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("id"))
	}
	return out
}

// A stopped VM on a failed host is not started anywhere: its row still names
// the failed host, stopped, with no pending transition and no proof; its disk
// rows still name that host; no survivor defines its domain; and its real
// disk, which the drill's targets set aside, is untouched. A running VM on the
// same host is rescheduled exactly as before, so the test cannot pass because
// failover never ran.
//
// Mutation: remove the coordinator's stopped check AND the write guard — the
// stopped VM is rescheduled pending, a survivor's reconciler sets its disk
// aside and starts it on a blank overlay, and the test goes red. Either one
// alone is caught by the scenarios below.
func TestFleet_FailoverLeavesAStoppedVMWithItsDisk(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	// The stopped VM's real disk, on the victim: an overlay of its image
	// holding the operator's data. In the fleet every node shares one
	// filesystem, so a survivor that rebuilt or set aside the recorded path
	// would touch exactly this file.
	dataDir := filepath.Join(c.tmpRoot, victim.Name, "data")
	store := image.NewStore(dataDir)
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	path := store.DiskPath("sv1", "root")
	if err := qcow2.Create(store.ImagePath("base"), 112<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(path, store.ImagePath("base"), 0, nil); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte("the operator's data")); err != nil {
		t.Fatal(err)
	}
	f.Close()
	realBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "sv1", HostName: victim.Name, State: "stopped", StateDetail: "operator-stop",
		CPUActual: 1, MemActual: 256,
		Spec: `{"name":"sv1","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "sv1", DiskName: "root", HostName: victim.Name, Path: path,
		BackingImage: "base", SizeBytes: 20 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM sv1: %v", err)
	}
	// The control: running, same policy, same host.
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "rv1", HostName: victim.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"rv1","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM rv1: %v", err)
	}

	if got := fenceVictim(t, c, a, victim, a, b); got != 1 {
		t.Fatalf("fencer fired %d times, want 1 — without a fence there is no recovery and this proves nothing", got)
	}

	// The control was recovered as before.
	if vm, _ := corrosion.GetVM(ctx, a.DB, "rv1"); vm == nil || vm.HostName == victim.Name || vm.State != "pending" {
		t.Fatalf("the running control rv1 = %+v, want it pending on a survivor", vm)
	}

	// The survivors' reconcilers, as the daemon runs them.
	for _, n := range []*Node{a, b} {
		rec := health.NewReconciler(n.Name, filepath.Join(c.tmpRoot, n.Name, "data"), n.DB, n.Virt)
		rec.SetAutoPullImage(func(context.Context, string) error { return nil })
		rec.ReconcileOnce(ctx)
	}

	vm, err := corrosion.GetVM(ctx, a.DB, "sv1")
	if err != nil || vm == nil {
		t.Fatalf("sv1 vanished after the failover: %v", err)
	}
	if vm.HostName != victim.Name || vm.State != "stopped" || vm.PendingActionID != "" {
		t.Fatalf("sv1 after the failover = host %s state %s pending %q; want it stopped on %s with no pending transition",
			vm.HostName, vm.State, vm.PendingActionID, victim.Name)
	}
	if p := proofsFor(t, a, "sv1"); len(p) != 0 {
		t.Errorf("failover minted reschedule proofs %v for the stopped sv1", p)
	}
	disks, err := corrosion.GetVMDisks(ctx, a.DB, "sv1")
	if err != nil || len(disks) != 1 || disks[0].HostName != victim.Name {
		t.Errorf("sv1's disk rows = %+v (err %v), want its one disk still on %s", disks, err, victim.Name)
	}
	for _, n := range []*Node{a, b} {
		if n.Virt.DomainExists("sv1") {
			t.Errorf("%s defined the stopped sv1's domain", n.Name)
		}
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, realBytes) {
		t.Errorf("sv1's real disk at %s was changed or removed (err %v)", path, err)
	}
	if aside, _ := filepath.Glob(path + ".superseded-*"); len(aside) != 0 {
		t.Errorf("sv1's real disk was set aside: %v", aside)
	}

	// The skip is audited and recorded as the VM's event, naming why.
	rows, err := a.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'failover.skip' AND target = 'sv1'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("failover.skip audit rows for sv1 = %d (err %v), want 1", len(rows), err)
	}
	evs, err := corrosion.ListVMEvents(ctx, a.DB, "sv1", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		found = found || e.Type == "vm.failover.skipped"
	}
	if !found {
		t.Errorf("sv1 has no vm.failover.skipped event: %+v", evs)
	}
}

// Under recovery claims a stopped VM is not claimed at all: the coordinator's
// first check skips it before any claim round, so no voter holds a decision
// that a later coordinator could re-materialize. The running control is
// claimed and rescheduled.
//
// Mutation: remove the stopped check at the top of recoverWorkloads — the
// write guard still refuses the reschedule, but only after the claim was
// decided, and the voters' state for the stopped VM's key goes red here.
func TestFleet_FailoverClaimsNothingForAStoppedVM(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := claimFleetWith(t, clock, 2911, func(_ *Cluster, a, _, victim *Node) {
		insertVMInState(t, a, "sv-claim", victim.Name, "stopped")
		insertVMInState(t, a, "rv-claim", victim.Name, "running")
	})

	cs := c.NewCoordinators(clock)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.Tick(ctx, a)

	if vm := vmOn(t, a, "rv-claim"); vm.HostName == victim.Name || vm.PendingActionID == "" {
		t.Fatalf("the running control rv-claim was not rescheduled: %+v", vm)
	}
	vm := vmOn(t, a, "sv-claim")
	if vm.HostName != victim.Name || vm.State != "stopped" || vm.PendingActionID != "" {
		t.Fatalf("the stopped sv-claim was moved: %+v", vm)
	}
	key := vmKey(a, "sv-claim", 0)
	for _, n := range []*Node{a, b} {
		if _, found, err := n.DB.ClaimState(ctx, key); err != nil || found {
			t.Errorf("%s holds claim state for the stopped sv-claim (found %v, err %v)", n.Name, found, err)
		}
	}
	if p := proofsFor(t, a, "sv-claim"); len(p) != 0 {
		t.Errorf("failover minted proofs %v for the stopped sv-claim", p)
	}
}

// An operator's stop that lands after the coordinator chose the VM, while it
// is still claiming the recovery, wins: the reschedule write re-reads the row
// in its transaction and refuses a stopped one, so the VM stays stopped on its
// host and no proof is written.
//
// Mutation: drop the `state <> 'stopped'` check from WriteVMRescheduleProof's
// guard — the stop is overwritten with "pending" and the VM moves.
func TestFleet_AStopAfterSelectionWinsOverTheReschedule(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, _, victim := claimFleetWith(t, clock, 2912, func(_ *Cluster, a, _, victim *Node) {
		insertVMInState(t, a, "race-vm", victim.Name, "running")
	})

	// The pause point: the coordinator has read the VM (running), passed its
	// checks and is claiming the recovery from the voters. The stop lands on
	// the coordinator's own replica now, before its write.
	var once sync.Once
	stopped := false
	c.SetClaimScript(func(m ClaimMsg) ClaimFate {
		if m.From == a.Name {
			once.Do(func() {
				if err := corrosion.UpdateVMState(ctx, a.DB, "race-vm", "stopped", "operator-stop"); err != nil {
					t.Errorf("stop race-vm mid-claim: %v", err)
					return
				}
				stopped = true
			})
		}
		return ClaimDefault
	})

	cs := c.NewCoordinators(clock)
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.Tick(ctx, a)

	if !stopped {
		t.Fatal("the coordinator made no claim RPC, so the stop never landed mid-recovery; this proves nothing")
	}
	vm := vmOn(t, a, "race-vm")
	if vm.HostName != victim.Name || vm.State != "stopped" || vm.PendingActionID != "" {
		t.Fatalf("race-vm after a stop that landed mid-recovery = %+v; want it stopped on %s with no pending transition",
			vm, victim.Name)
	}
	if p := proofsFor(t, a, "race-vm"); len(p) != 0 {
		t.Errorf("a reschedule proof was written for race-vm after its stop: %v", p)
	}
}

// A stopped container on a failed host is not relocated: neither one whose
// image could be re-pulled (it would be recreated and started) nor one with
// none (it would be marked relocate-skipped over its operator stop). A
// running re-pullable container on the same host is relocated as before.
//
// Mutation: remove the stopped check at the top of relocateContainers — the
// image-less container's operator stop is overwritten with relocate-skipped
// (the re-pullable one is still held by RelocateContainerWithToken's guard;
// removing both moves it too).
func TestFleet_FailoverLeavesStoppedContainers(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	putContainer(t, victim, "ct-running", "docker.io/library/alpine:3.19", "image-recreate")
	for name, img := range map[string]string{"ct-stopped": "docker.io/library/alpine:3.19", "ct-stopped-noimg": ""} {
		if err := corrosion.UpsertContainer(ctx, victim.DB, corrosion.ContainerRecord{
			HostName: victim.Name, Name: name, Image: img, State: "stopped", StateDetail: "operator-stop",
			OnHostFailure: "image-recreate",
		}); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}

	if got := fenceVictim(t, c, a, victim, a, b); got != 1 {
		t.Fatalf("fencer fired %d times, want 1 — without a fence there is no relocation pass and this proves nothing", got)
	}

	if host, rec := findContainer(t, c, "ct-running"); rec == nil || host == victim.Name {
		t.Fatalf("the running control ct-running was not relocated (host %q, row %+v)", host, rec)
	}
	for _, name := range []string{"ct-stopped", "ct-stopped-noimg"} {
		host, rec := findContainer(t, c, name)
		if rec == nil {
			t.Fatalf("%s vanished", name)
		}
		if host != victim.Name || rec.State != "stopped" || rec.StateDetail != "operator-stop" {
			t.Errorf("%s after the failover = host %s state %s detail %q; want it stopped on %s as the operator left it",
				name, host, rec.State, rec.StateDetail, victim.Name)
		}
		if p := proofsFor(t, a, name); len(p) != 0 {
			t.Errorf("relocation proofs %v were minted for the stopped %s", p, name)
		}
	}
	rows, err := a.DB.Query(ctx, `SELECT target FROM audit_log WHERE action = 'failover.skip' AND target IN ('ct/ct-stopped','ct/ct-stopped-noimg')`)
	if err != nil || len(rows) != 2 {
		t.Errorf("failover.skip audit rows for the stopped containers = %d (err %v), want 2", len(rows), err)
	}
}
