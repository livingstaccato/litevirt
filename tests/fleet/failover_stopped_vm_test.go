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
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
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
		// A host-local disk: the VM stays where it is (one on shared storage
		// only would be moved, still stopped — a separate scenario).
		if err := corrosion.InsertDisk(context.Background(), a.DB, corrosion.DiskRecord{VMName: "sv-claim",
			DiskName: "root", HostName: victim.Name, Path: "/var/lib/litevirt/disks/sv-claim-root", StorageType: "local"}); err != nil {
			t.Fatal(err)
		}
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

// sharedDiskVM inserts name on host with one disk on shared (nfs) storage at
// a real file, stopped with detail, or running when detail is "".
func sharedDiskVM(t *testing.T, c *Cluster, n *Node, name, host, state, detail string) string {
	t.Helper()
	dir := filepath.Join(c.tmpRoot, "shared")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name+"-root.qcow2")
	if err := os.WriteFile(path, []byte("shared disk of "+name), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, State: state, StateDetail: detail, CPUActual: 1, MemActual: 256,
		Spec: `{"name":"` + name + `","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: name, DiskName: "root", HostName: host, Path: path, SizeBytes: 1 << 30,
		StorageType: "nfs", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	return path
}

// reconcileAll runs every given node's reconciler once, as the daemon does.
func reconcileAll(t *testing.T, c *Cluster, nodes ...*Node) {
	t.Helper()
	for _, n := range nodes {
		rec := health.NewReconciler(n.Name, filepath.Join(c.tmpRoot, n.Name, "data"), n.DB, n.Virt)
		rec.SetAutoPullImage(func(context.Context, string) error { return nil })
		rec.ReconcileOnce(context.Background())
	}
}

// A VM the operator stopped whose disks are all on shared storage gets off
// the failed host on its real disk, as on main, but is never started: it is
// re-keyed to a survivor still stopped, the survivor defines its domain there
// shut off, and `lv start` then starts it there like any stopped VM.
//
// Mutation: have stoppedVMRekeyable return false — sv-shared stays on the
// failed host and the test goes red on its host. Drop the reconciler's
// define step — `lv start` on the survivor fails with no domain to start.
// Let the reconciler keep a definition it finds — the stale one on the old
// disk stays and the test goes red on the defined XML.
func TestFleet_FailoverMovesAStoppedSharedDiskVMStoppedAndStartable(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	path := sharedDiskVM(t, c, a, "sv-shared", victim.Name, "stopped", "operator-stop")
	// Each survivor holds a stale definition from an earlier stay, on an old
	// disk: the re-key must never trust it (review M5).
	for _, n := range []*Node{a, b} {
		if err := n.Virt.DefineDomain(`<domain><name>sv-shared</name><devices><disk><source file='/old/sv-shared-root'/></disk></devices></domain>`); err != nil {
			t.Fatal(err)
		}
	}

	if got := fenceVictim(t, c, a, victim, a, b); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	vm, _ := corrosion.GetVM(ctx, a.DB, "sv-shared")
	if vm == nil || vm.HostName == victim.Name || vm.State != "stopped" || vm.PendingActionID != "" ||
		vm.StateDetail != corrosion.StoppedRekeyDetail(victim.Name) {
		t.Fatalf("sv-shared after the failover = %+v; want it stopped on a survivor, marked re-keyed from %s",
			vm, victim.Name)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, a.DB, "sv-shared"); len(disks) != 1 || disks[0].HostName != vm.HostName {
		t.Errorf("sv-shared's disk rows = %+v, want them on %s", disks, vm.HostName)
	}
	if p := proofsFor(t, a, "sv-shared"); len(p) != 0 {
		t.Errorf("a start proof %v was minted for the stopped sv-shared", p)
	}
	dest := c.Node(vm.HostName)

	reconcileAll(t, c, a, b)
	if xml := dest.Virt.DefinedXML("sv-shared"); !strings.Contains(xml, path) || strings.Contains(xml, "/old/") {
		t.Fatalf("%s did not define sv-shared afresh on its shared disk %s:\n%s", dest.Name, path, xml)
	}
	for _, n := range []*Node{a, b} {
		if st, _ := n.Virt.DomainState("sv-shared"); st == "running" {
			t.Fatalf("%s started the stopped sv-shared", n.Name)
		}
	}
	if vm, _ := corrosion.GetVM(ctx, a.DB, "sv-shared"); vm == nil || vm.State != "stopped" ||
		vm.StateDetail != corrosion.StoppedRekeyDetail(victim.Name) {
		t.Fatalf("sv-shared after its domain was defined = %+v, want stopped, still marked re-keyed", vm)
	}

	// The start takes the start lease the define holds: while the reconciler
	// holds it, the start is refused rather than interleaved (review R4).
	if held, err := health.TryVMStartLease(ctx, dest.DB, dest.Name, "sv-shared", time.Now()); err != nil || held != dest.Name {
		t.Fatalf("take the reconciler's start lease: %q %v", held, err)
	}
	if _, err := c.SelfClient(dest).StartVM(ctx, &pb.StartVMRequest{Name: "sv-shared"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("lv start sv-shared while its define holds the lease: %v, want FailedPrecondition", err)
	}
	health.ReleaseVMStartLease(ctx, dest.DB, dest.Name, "sv-shared")
	if _, err := c.SelfClient(dest).StartVM(ctx, &pb.StartVMRequest{Name: "sv-shared"}); err != nil {
		t.Fatalf("lv start sv-shared on %s: %v", dest.Name, err)
	}
	if st, _ := dest.Virt.DomainState("sv-shared"); st != "running" {
		t.Fatalf("sv-shared on %s after lv start: %q, want running", dest.Name, st)
	}
	rows, err := a.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'failover.rekey-stopped' AND target = 'sv-shared'`)
	if err != nil || len(rows) != 1 {
		t.Errorf("failover.rekey-stopped audit rows = %d (err %v), want 1", len(rows), err)
	}
}

// A VM that stopped without anyone asking — a guest or host shutdown, as the
// reconciler records it — is recovered as on main when its disks are all
// shared (restarted elsewhere on its real disk), and left where it is with a
// host-local disk, where the restart would rebuild that disk blank.
//
// Mutation: treat every stopped VM as stopped by intent (StopIsIntent always
// true) — gs-shared stays on the failed host. Drop the host-local check for a
// stop without intent — gs-local is rescheduled pending onto a blank disk.
func TestFleet_FailoverRecoversAGuestShutdownVMOnlyOnSharedStorage(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	sharedDiskVM(t, c, a, "gs-shared", victim.Name, "stopped", corrosion.StopDetailGuestShutdown)
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "gs-local", HostName: victim.Name, State: "stopped", StateDetail: corrosion.StopDetailGuestShutdown,
		CPUActual: 1, MemActual: 256,
		Spec: `{"name":"gs-local","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "gs-local", DiskName: "root", HostName: victim.Name, Path: "/nonexistent/gs-local-root",
		BackingImage: "base", SizeBytes: 1 << 30, StorageType: "local", TargetDev: "vda",
	}}); err != nil {
		t.Fatalf("InsertVM gs-local: %v", err)
	}

	if got := fenceVictim(t, c, a, victim, a, b); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	if vm, _ := corrosion.GetVM(ctx, a.DB, "gs-shared"); vm == nil || vm.HostName == victim.Name || vm.State != "pending" {
		t.Fatalf("gs-shared (guest shutdown, shared disk) = %+v, want it rescheduled pending as on main", vm)
	}
	vm, _ := corrosion.GetVM(ctx, a.DB, "gs-local")
	if vm == nil || vm.HostName != victim.Name || vm.State != "stopped" || vm.PendingActionID != "" {
		t.Fatalf("gs-local (guest shutdown, host-local disk) = %+v, want it stopped on %s", vm, victim.Name)
	}
	evs, err := corrosion.ListVMEvents(ctx, a.DB, "gs-local", 10, "")
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, e := range evs {
		named = named || (e.Type == "vm.failover.skipped" && strings.Contains(e.Detail, "host-local disk"))
	}
	if !named {
		t.Errorf("gs-local has no vm.failover.skipped event naming its host-local disk: %+v", evs)
	}
}

// A host removed with --dead whose only recorded workloads are stopped is
// admitted again under its name, and they come back with it: failover never
// moved them, and their disks are on that machine.
//
// Mutation: AdmitHost back on WorkloadsOnRemovedHost — the admission is
// refused naming vm/vm-stopped.
func TestFleet_ReaddBringsBackTheStoppedWorkloads(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 2913})
	a, b, e, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "vm-stopped", HostName: d.Name, State: "stopped", StateDetail: "operator-stop",
		Spec: `{"on_host_failure":"restart-any"}`,
	}, nil, []corrosion.DiskRecord{{
		VMName: "vm-stopped", DiskName: "root", HostName: d.Name, Path: "/var/lib/litevirt/disks/vm-stopped-root",
		StorageType: "local",
	}}); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)

	c.Kill(d)
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	withOperatorPKI(t, a)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	survivors := []*Node{a, b, e}
	adoptAll(t, c, 2, survivors...)
	c.WaitConverged(t, convergeTimeout, survivors...)
	if left, _ := corrosion.WorkloadsOnRemovedHost(ctx, a.DB, d.Name); len(left) != 1 {
		t.Fatalf("workloads recorded on the removed %s = %v, want vm-stopped", d.Name, left)
	}

	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: "0a0b0c0d0e0f",
	}); err != nil {
		t.Fatalf("admitting %s back with only a stopped VM recorded on it: %v", d.Name, err)
	}
	if vm := vmOn(t, a, "vm-stopped"); vm == nil || vm.HostName != d.Name || vm.State != "stopped" {
		t.Fatalf("vm-stopped after %s was admitted again = %+v, want it stopped on %s", d.Name, vm, d.Name)
	}
}

// Two coordinators that both believe they lead, with replication between them
// cut, both find the same stopped shared-storage VM on the failed host. With
// recovery claims on (the default), each claims the re-key at the VM's
// ownership generation and learns one destination: after the heal exactly one
// host owns the VM, only it defines the domain, and `lv start` starts it
// there.
//
// Mutation: skip the claim in rekeyStoppedVM — no claim state is recorded
// for the VM's key and the test goes red there (the reconcilers then still
// leave one definition, TestFleet_ReKeyedStoppedVMDefinedOnlyWhereTheRowEnds).
func TestFleet_TwoCoordinatorsReKeyAStoppedVMToOneHost(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	var path string
	c, a, b, victim := claimFleetWith(t, clock, 2914, func(c *Cluster, a, _, victim *Node) {
		path = sharedDiskVM(t, c, a, "sv-two", victim.Name, "stopped", "operator-stop")
	})
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
	cs := c.NewCoordinators(clock)
	for _, n := range []*Node{a, b} {
		cs.ByNode[n.Name].Gate = quorateGate{}
	}
	rekeyed := func(n *Node) bool { return vmOn(t, n, "sv-two").HostName != victim.Name }
	for i := 0; i < 20 && !(rekeyed(a) && rekeyed(b)); i++ {
		cs.Tick(ctx, a, b)
		clock.Advance(contentionPoll / 10)
	}
	// Heal, as the two-coordinator claim scenarios do; the victim stays dead.
	c.ClearLinkFaults()
	c.Kill(victim)
	for _, n := range []*Node{a, b} {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	// leader_lease_terms keeps both contested terms by design.
	c.WaitConvergedExcept(t, convergeTimeout, []string{"leader_lease_terms", "health_conditions"}, a, b)

	va, vb := vmOn(t, a, "sv-two"), vmOn(t, b, "sv-two")
	if va.HostName != vb.HostName || va.HostName == victim.Name || va.State != "stopped" {
		t.Fatalf("after the heal sv-two is %s/%s on %s and %s/%s on %s; want one surviving host, stopped",
			va.HostName, va.State, a.Name, vb.HostName, vb.State, b.Name)
	}
	if _, found, err := a.DB.ClaimState(ctx, vmKey(a, "sv-two", 0)); err != nil || !found {
		t.Fatalf("no recovery claim was taken for the re-key (found %v, err %v)", found, err)
	}
	owner := c.Node(va.HostName)
	recs := map[string]*health.Reconciler{}
	for _, n := range []*Node{a, b} {
		recs[n.Name] = health.NewReconciler(n.Name, filepath.Join(c.tmpRoot, n.Name, "data"), n.DB, n.Virt)
	}
	for i := 0; i < 2; i++ {
		for _, n := range []*Node{a, b} {
			recs[n.Name].ReconcileOnce(ctx)
		}
	}
	for _, n := range []*Node{a, b} {
		if defined := n.Virt.DomainExists("sv-two"); defined != (n == owner) {
			t.Errorf("%s defines sv-two: %v; only its owner %s should", n.Name, defined, owner.Name)
		}
	}
	if xml := owner.Virt.DefinedXML("sv-two"); !strings.Contains(xml, path) {
		t.Fatalf("%s's definition of sv-two is not on its shared disk:\n%s", owner.Name, xml)
	}
	if _, err := c.SelfClient(owner).StartVM(ctx, &pb.StartVMRequest{Name: "sv-two"}); err != nil {
		t.Fatalf("lv start sv-two on %s: %v", owner.Name, err)
	}
}

// With recovery claims off, two coordinators can re-key one stopped VM to two
// hosts. Each target defines it while its own replica names it. After the
// heal the row names one host: that host keeps (or makes) its definition and
// can start the VM, and the other undefines the one it made. The marker
// is never rewritten, so the host the row converges on still defines.
//
// Mutation: rewrite the marker to operator-stop after defining (round 1) —
// the converged row can carry the loser's rewrite and the owner never
// defines. Drop cleanupRekeyLeftovers — the loser keeps its definition.
func TestFleet_ReKeyedStoppedVMDefinedOnlyWhereTheRowEnds(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2915})
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	sharedDiskVM(t, c, a, "sv-split", victim.Name, "stopped", "operator-stop")
	c.WaitConverged(t, convergeTimeout)
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
	// Each side's coordinator re-keys to its own host, at the same generation.
	for _, n := range []*Node{a, b} {
		if err := corrosion.RekeyStoppedVM(ctx, n.DB, "sv-split", victim.Name, n.Name, "stopped", 0); err != nil {
			t.Fatalf("re-key on %s: %v", n.Name, err)
		}
	}
	recs := map[string]*health.Reconciler{}
	for _, n := range []*Node{a, b} {
		recs[n.Name] = health.NewReconciler(n.Name, filepath.Join(c.tmpRoot, n.Name, "data"), n.DB, n.Virt)
		recs[n.Name].ReconcileOnce(ctx)
		if !n.Virt.DomainExists("sv-split") {
			t.Fatalf("%s did not define sv-split while its replica named it", n.Name)
		}
	}
	c.ClearLinkFaults()
	for _, n := range []*Node{a, b} {
		corrosion.NewAntiEntropy(n.DB, n.PKIDir, 0).RunOnce(ctx)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for i := 0; i < 2; i++ {
		for _, n := range []*Node{a, b} {
			recs[n.Name].ReconcileOnce(ctx)
		}
	}
	va := vmOn(t, a, "sv-split")
	if !corrosion.IsStoppedRekeyDetail(va.StateDetail) || va.State != "stopped" {
		t.Fatalf("sv-split after the heal = %+v, want stopped and still marked", va)
	}
	owner := c.Node(va.HostName)
	for _, n := range []*Node{a, b} {
		if defined := n.Virt.DomainExists("sv-split"); defined != (n == owner) {
			t.Errorf("%s defines sv-split: %v; only its owner %s should", n.Name, defined, owner.Name)
		}
	}
	if _, err := c.SelfClient(owner).StartVM(ctx, &pb.StartVMRequest{Name: "sv-split"}); err != nil {
		t.Fatalf("lv start sv-split on %s: %v", owner.Name, err)
	}
}

// Under the shared-storage fence, a stopped VM on shared storage is moved off
// a failed host only on a proof-grade fence of that host, as a running VM's
// transfer is. A fence that is not proof-grade leaves it where it is.
//
// Mutation: delete the shared-storage-fence refusal in stoppedVMRekeyable —
// sv-fence is moved on a best-effort fence.
func TestFleet_StoppedVMReKeyNeedsAProofGradeFenceUnderTheSharedStorageFence(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	sharedDiskVM(t, c, a, "sv-fence", victim.Name, "stopped", "operator-stop")
	nowRFC := time.Now().UTC().Format(time.RFC3339)
	for _, o := range []*Node{a, b} {
		if err := a.DB.Execute(ctx,
			`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, 'suspect', 5, NULL, ?)`, o.Name, victim.Name, nowRFC); err != nil {
			t.Fatal(err)
		}
	}
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.Gate = quorateGate{}
	coord.SharedStorageFenceEnforce = true
	fences := 0
	coord.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "fleet-test", Success: true} // not proof-grade
	})
	coord.RunOnce(ctx)
	if fences != 1 {
		t.Fatalf("fencer fired %d times, want 1", fences)
	}
	if vm, _ := corrosion.GetVM(ctx, a.DB, "sv-fence"); vm == nil || vm.HostName != victim.Name || vm.State != "stopped" {
		t.Fatalf("sv-fence = %+v; want it left stopped on %s without a proof-grade fence", vm, victim.Name)
	}
}

// A claimed re-key advances the VM's ownership generation, so the claim key
// it was decided at is retired: when the host it moved to fails later, with
// the VM started there, the VM fails over normally to one other host.
//
// Mutation: re-key without the mint under claims (RekeyStoppedVM in place of
// RekeyStoppedVMClaimed) — the second failover adopts the first re-key's
// decided value, whose destination is now the failed host, and strands.
func TestFleet_AClaimedReKeyLeavesTheNextFailoverFree(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: 2916})
	a, b, f := c.Nodes[0], c.Nodes[1], c.Nodes[4]
	sharedDiskVM(t, c, a, "sv-next", f.Name, "stopped", "operator-stop")
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)

	clock := NewVirtualClock(time.Now().UTC())
	survivors := c.Nodes[:4]
	c.Kill(f)
	for _, n := range survivors {
		PublishHealth(t, n, f.Name, 5, clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, survivors...)
	cs := c.NewCoordinators(clock)
	for _, n := range c.Nodes {
		cs.ByNode[n.Name].Gate = quorateGate{}
	}
	cs.Tick(ctx, a)
	c.WaitConverged(t, convergeTimeout, survivors...)
	vm := vmOn(t, a, "sv-next")
	if vm.HostName == f.Name || vm.State != "stopped" || vm.OwnerEpoch != 1 {
		t.Fatalf("sv-next after the claimed re-key = %+v; want it stopped on a survivor at generation 1", vm)
	}
	x := c.Node(vm.HostName)
	health.NewReconciler(x.Name, filepath.Join(c.tmpRoot, x.Name, "data"), x.DB, x.Virt).ReconcileOnce(ctx)
	if _, err := c.SelfClient(x).StartVM(ctx, &pb.StartVMRequest{Name: "sv-next"}); err != nil {
		t.Fatalf("lv start sv-next on %s: %v", x.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, survivors...)

	// x fails with the VM running on it.
	var rest []*Node
	for _, n := range survivors {
		if n != x {
			rest = append(rest, n)
		}
	}
	c.Kill(x)
	// Past the failover lease the first coordinator took, which x may hold.
	clock.Advance(2 * time.Minute)
	for _, n := range rest {
		PublishHealth(t, n, x.Name, 5, clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, rest...)
	coord := a
	if x == a {
		coord = b
	}
	cs.Tick(ctx, coord)
	got := vmOn(t, coord, "sv-next")
	if got.HostName == x.Name || got.PendingActionID == "" {
		t.Fatalf("sv-next after %s failed = %+v; want it rescheduled off %s (a stale claim strands it)", x.Name, got, x.Name)
	}
}

// The re-key's marker reaches a destination that is not the coordinator by
// ordinary replication — not only by anti-entropy — so that host defines the
// VM and `lv start` works there. Both forms of the re-key, claimed and not.
//
// Mutation: write the marker at the move's timestamp — the receiver meets an
// exact tie, keeps its own (empty) detail, and the test goes red waiting for
// the marker.
func TestFleet_ReKeyMarkerReachesTheDestinationByReplication(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2917})
	a, b, f := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	sharedDiskVM(t, c, a, "sv-wal", f.Name, "stopped", "operator-stop")
	sharedDiskVM(t, c, a, "sv-wal-claimed", f.Name, "stopped", "operator-stop")
	c.WaitConverged(t, convergeTimeout)

	if err := corrosion.RekeyStoppedVM(ctx, a.DB, "sv-wal", f.Name, b.Name, "stopped", 0); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RekeyStoppedVMClaimed(ctx, a.DB, "sv-wal-claimed", f.Name, b.Name, "stopped", 0); err != nil {
		t.Fatal(err)
	}
	want := corrosion.StoppedRekeyDetail(f.Name)
	deadline := time.Now().Add(15 * time.Second)
	for _, name := range []string{"sv-wal", "sv-wal-claimed"} {
		for {
			v := vmOn(t, b, name)
			if v != nil && v.HostName == b.Name && v.StateDetail == want {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s on %s's replica = %+v; the re-key marker never arrived by replication", name, b.Name, v)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	health.NewReconciler(b.Name, filepath.Join(c.tmpRoot, b.Name, "data"), b.DB, b.Virt).ReconcileOnce(ctx)
	for _, name := range []string{"sv-wal", "sv-wal-claimed"} {
		if !b.Virt.DomainExists(name) {
			t.Fatalf("%s did not define %s", b.Name, name)
		}
		if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: name}); err != nil {
			t.Fatalf("lv start %s on %s: %v", name, b.Name, err)
		}
	}
}
