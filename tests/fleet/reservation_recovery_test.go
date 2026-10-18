package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Fleet scenarios for host reservation recovery: the sweep's release reaching
// every replica, the deputy for a removed host, and the manual release's
// forward to the reservation's target host (lv operation release-reservation).

// resStep is one epoch's steps of a seeded reservation-bearing operation.
type resStep struct {
	epoch int64
	names []string
}

// seedReservationOp writes a resize operation's header at headerEpoch and its
// steps through n's client, so they replicate as production's writes do. Test
// fixture data.
func seedReservationOp(t *testing.T, n *Node, id, vm string, headerEpoch int64, rv corrosion.ReservationVector, steps []resStep) {
	t.Helper()
	ctx := context.Background()
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode reservation: %v", err)
	}
	if err := corrosion.InsertOperation(ctx, n.DB, corrosion.OperationRecord{
		ID: id, Method: "ResizeVMLive", ResourceKind: "vm", ResourceID: vm,
		OperationKind: string(corrosion.OpResourceUpdateRunning), RequestHash: "h",
		ReservationJSON: enc, VMOwnerEpoch: headerEpoch,
	}); err != nil {
		t.Fatalf("InsertOperation %s on %s: %v", id, n.Name, err)
	}
	for _, st := range steps {
		for _, name := range st.names {
			if err := corrosion.AppendOperationStep(ctx, n.DB, corrosion.OperationStepRecord{
				OperationID: id, OwnerEpoch: st.epoch, StepName: name}); err != nil {
				t.Fatalf("append %s@%d on %s: %v", name, st.epoch, n.Name, err)
			}
		}
	}
}

// labLeakSteps is the lab's leaked resize: admission at the header's epoch 0,
// the whole workload operation, through completed, at the VM's epoch 1.
func labLeakSteps() []resStep {
	return []resStep{
		{0, []string{corrosion.OpStepReserved, corrosion.OpStepAdmitted}},
		{1, []string{corrosion.OpStepPlanned, corrosion.OpStepDesiredPersisted, corrosion.OpStepConfigApplied,
			corrosion.OpStepLiveApplied, corrosion.OpStepObserved, corrosion.OpStepCompleted}},
	}
}

// ageOnEveryNode moves the operation's and the VM's creation stamps into the
// past by the same amount on every node, as time passing would: an abandoned
// admission is only told apart from one still committing once it is older
// than the admission window. Written locally and identically everywhere, so
// no replica differs from another.
func ageOnEveryNode(t *testing.T, c *Cluster, opID, vm string) {
	t.Helper()
	ctx := context.Background()
	opAt := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	vmAt := time.Now().Add(-48 * time.Hour).UTC().Format(time.RFC3339Nano)
	for _, n := range c.Nodes {
		if err := localExec(ctx, n.DB, `UPDATE operations SET created_at = ? WHERE id = ?`, opAt, opID); err != nil {
			t.Fatalf("age %s on %s: %v", opID, n.Name, err)
		}
		if err := localExec(ctx, n.DB, `UPDATE vms SET created_at = ? WHERE name = ?`, vmAt, vm); err != nil {
			t.Fatalf("age %s on %s: %v", vm, n.Name, err)
		}
	}
}

// seedAbandonedResize seeds the abandoned pre-commit shape (class C) targeting
// target: VM vm there with no barrier, and a resize admitted at epoch 1 an
// hour ago that nothing began. It waits until every node holds it.
func seedAbandonedResize(t *testing.T, c *Cluster, target *Node, opID, vm string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, target.DB, corrosion.VMRecord{
		Name: vm, HostName: target.Name, State: "running", Spec: "{}",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", vm, err)
	}
	seedReservationOp(t, target, opID, vm, 1,
		corrosion.ReservationVector{TargetHost: target.Name, TargetCPU: 1, TargetMemMiB: 512, Provisional: true},
		[]resStep{{1, []string{corrosion.OpStepReserved, corrosion.OpStepAdmitted}}})
	c.WaitConverged(t, convergeTimeout)
	ageOnEveryNode(t, c, opID, vm)
	for _, n := range c.Nodes {
		v, err := corrosion.ClassifyReservation(ctx, n.DB, opID)
		if err != nil || v == nil || v.Class != corrosion.ReservationNoRunningOperation {
			t.Fatalf("precondition on %s: %s classified %+v (err %v), want no_running_operation", n.Name, opID, v, err)
		}
	}
}

// adminUser creates an Admin user on n and returns a client calling n as that
// user with a session token.
func adminUser(t *testing.T, c *Cluster, n *Node, name string) (pb.LiteVirtClient, string) {
	t.Helper()
	ctx := context.Background()
	pw := name + "-password-0123456789"
	if _, err := c.SelfClient(n).CreateUser(ctx, &pb.CreateUserRequest{Username: name, Password: pw, Role: "admin"}); err != nil {
		t.Fatalf("CreateUser %s: %v", name, err)
	}
	login, err := c.SelfClient(n).Login(ctx, &pb.LoginRequest{Username: name, Password: pw})
	if err != nil {
		t.Fatalf("Login %s: %v", name, err)
	}
	return c.bearerClient(n, login.GetToken()), pw
}

func hostReservedMem(t *testing.T, n *Node, host string) int {
	t.Helper()
	_, mem, err := corrosion.HostReserved(context.Background(), n.DB, host)
	if err != nil {
		t.Fatalf("HostReserved(%s) on %s: %v", host, n.Name, err)
	}
	return mem
}

// F1: the lab's leaked resize, held against node-0 on every replica, is
// released by node-0's sweep, and the release reaches every replica as one
// identical row: each stops counting it, and a create that needs the freed
// memory, entering another node, is admitted.
//
// Mutation (red): write the release at the terminal's epoch 1 instead of the
// header's epoch 0 (reservationReleaseStatement). No replica's reader reduces
// epoch 1 for the reservation, so every node still counts 512 MiB and the
// create is refused.
func TestReservationRecovery_LabLeakShapeHealsClusterWide(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1016})
	owner, entry := c.Nodes[0], c.Nodes[1]
	setHostCapacity(t, c, owner.Name, 8, 4096)
	for _, n := range c.Nodes[1:] {
		setHostCapacity(t, c, n.Name, 32, 65536)
	}
	if err := corrosion.InsertVM(ctx, owner.DB, corrosion.VMRecord{
		Name: "leaky", HostName: owner.Name, State: "running", Spec: "{}", CPUActual: 1, MemActual: 1024,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	seedReservationOp(t, owner, "leak-op", "leaky", 0,
		corrosion.ReservationVector{TargetHost: owner.Name, TargetMemMiB: 512, Provisional: true}, labLeakSteps())
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := hostReservedMem(t, n, owner.Name); got != 512 {
			t.Fatalf("precondition: %s counts %d MiB reserved on %s, want the leaked 512", n.Name, got, owner.Name)
		}
	}

	_, free, ok, err := corrosion.HostFreeCapacity(ctx, owner.DB, owner.Name)
	if err != nil || !ok || free <= 0 {
		t.Fatalf("free memory on %s: %d ok=%v err=%v", owner.Name, free, ok, err)
	}
	// Needs the leaked 512 MiB back: more than is free now (with its qemu
	// overhead), and within what is free once the leak is released.
	want := int32(free + 256)
	if _, err := runVM(t, c, entry, "after-leak", owner.Name, 1, want); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a %d MiB create pinned to %s through %s while the leak is held: %v, want ResourceExhausted",
			want, owner.Name, entry.Name, err)
	}

	for _, n := range c.Nodes[1:] {
		if got := n.Server.SweepReservationsOnce(ctx); got != 0 {
			t.Fatalf("%s's sweep released %d reservations of active host %s, want 0", n.Name, got, owner.Name)
		}
	}
	if got := owner.Server.SweepReservationsOnce(ctx); got != 1 {
		t.Fatalf("%s's sweep released %d, want the leaked reservation", owner.Name, got)
	}
	c.WaitConverged(t, convergeTimeout)

	header, err := corrosion.GetOperation(ctx, owner.DB, "leak-op")
	if err != nil || header == nil {
		t.Fatalf("header: %+v %v", header, err)
	}
	var first string
	for _, n := range c.Nodes {
		if got := hostReservedMem(t, n, owner.Name); got != 0 {
			t.Errorf("%s still counts %d MiB reserved on %s after the sweep, want 0", n.Name, got, owner.Name)
		}
		rows, err := n.DB.Query(ctx, `SELECT owner_epoch, facts, created_at FROM operation_steps
			WHERE operation_id = 'leak-op' AND step_name = ? AND deleted_at IS NULL`, corrosion.OpStepCancelled)
		if err != nil || len(rows) != 1 {
			t.Fatalf("%s: release rows %+v err %v, want exactly one", n.Name, rows, err)
		}
		r := rows[0]
		row := strings.Join([]string{r.String("owner_epoch"), r.String("facts"), r.String("created_at")}, "|")
		if r.Int64("owner_epoch") != 0 || r.String("facts") != corrosion.ReservationReleasedFacts || r.String("created_at") != header.CreatedAt {
			t.Errorf("%s: release row %s, want owner_epoch 0, facts %q, created_at %s (the header's)",
				n.Name, row, corrosion.ReservationReleasedFacts, header.CreatedAt)
		}
		if first == "" {
			first = row
		} else if row != first {
			t.Errorf("%s: release row %s differs from %s", n.Name, row, first)
		}
		if k := n.DB.UnresolvedTieCount(); k != 0 {
			t.Errorf("%s tracks %d unresolved merge conflicts, want 0", n.Name, k)
		}
	}

	if _, err := runVM(t, c, entry, "after-release", owner.Name, 1, want); err != nil {
		t.Fatalf("the same %d MiB create after the release: %v", want, err)
	}
}

// F2: a finished reservation whose target host was removed (lv host rm --dead)
// is released by the deputy, the lexically smallest active host, and by no
// other node; the release replicates to the remaining nodes. While the target
// was active, no other node released it.
//
// Mutation (red): drop the deputy branch of isReservationWriter (return false
// for any host but the target): the deputy releases nothing.
func TestReservationRecovery_DeputyReleasesForRemovedHost(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1017})
	deputy, other, gone := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	c.WaitConverged(t, convergeTimeout)
	seedReservationOp(t, deputy, "orphan-op", "orphan-vm", 0,
		corrosion.ReservationVector{TargetHost: gone.Name, TargetMemMiB: 256, Provisional: true}, labLeakSteps())
	c.WaitConverged(t, convergeTimeout)
	for _, n := range []*Node{deputy, other} {
		if got := n.Server.SweepReservationsOnce(ctx); got != 0 {
			t.Fatalf("%s released %d reservations of active host %s, want 0", n.Name, got, gone.Name)
		}
	}

	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	settleByAntiEntropy(t, c, true)
	gone.Stop()
	c.Kill(gone)
	// Its owned ephemeral endpoint is stopped. Remove it from the seeded
	// gossip view before deleting its host row, so the resolver cannot fall
	// back to a real host's default port after removal.
	gone.seededGossipAbsent.Store(true)
	withOperatorPKI(t, deputy)
	if err := deputy.DB.Execute(ctx,
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		"confirm-"+gone.Name, gone.Name, "manual", "manual-confirmed",
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "operator confirmation"); err != nil {
		t.Fatalf("fence-confirm %s: %v", gone.Name, err)
	}
	if err := corrosion.UpdateHostState(ctx, deputy.DB, gone.Name, "fenced"); err != nil {
		t.Fatalf("record %s fenced: %v", gone.Name, err)
	}
	if err := cli.HostRemoveDead(ctx, c.SelfClient(deputy), gone.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", gone.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, deputy, other)
	if h, _ := corrosion.GetHost(ctx, other.DB, gone.Name); h != nil && h.State == "active" {
		t.Fatalf("precondition: %s still holds %s active", other.Name, gone.Name)
	}

	if got := other.Server.SweepReservationsOnce(ctx); got != 0 {
		t.Fatalf("%s, not the deputy, released %d", other.Name, got)
	}
	if got := deputy.Server.SweepReservationsOnce(ctx); got != 1 {
		t.Fatalf("the deputy %s released %d, want the removed host's reservation", deputy.Name, got)
	}
	c.WaitConverged(t, convergeTimeout, deputy, other)
	for _, n := range []*Node{deputy, other} {
		if got := hostReservedMem(t, n, gone.Name); got != 0 {
			t.Errorf("%s still counts %d MiB reserved on removed %s, want 0", n.Name, got, gone.Name)
		}
	}
}

// F3: the manual release entering node-1 for a reservation held on node-0 is
// decided on node-0. While node-0 holds the VM's lock, node-0's refusal reaches
// the caller unchanged; once it is free, node-0 releases it. Both requests are
// audited once each, by the node called, as the caller.
//
// Mutations (each red):
//   - execute on the entry node instead of forwarding: the first call is
//     released there, under a lock nobody holds;
//   - drop the trailer the deciding host sets (ReleaseHostReservation's
//     SetTrailer): the target's lock-busy refusal reads as an unreachable host
//     and names lv host rm.
func TestReleaseHostReservation_ForwardsToTargetAndRefusesWhileHeld(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1018})
	target, entry := c.Nodes[0], c.Nodes[1]
	c.WaitConverged(t, convergeTimeout)
	seedAbandonedResize(t, c, target, "stuck-op", "held")
	ada, _ := adminUser(t, c, entry, "ada")
	req := &pb.ReleaseHostReservationRequest{OperationId: "stuck-op", Force: true}

	release := target.Server.HoldVMLockForTest("held")
	_, err := ada.ReleaseHostReservation(ctx, req)
	release()
	want := `VM "held" has a request in flight on ` + target.Name
	if msg := status.Convert(err).Message(); status.Code(err) != codes.Unavailable || !strings.HasPrefix(msg, want) {
		t.Fatalf("release through %s while %s holds the VM's lock: %v, want %s's own Unavailable %q, unchanged",
			entry.Name, target.Name, err, target.Name, want)
	}
	for _, n := range c.Nodes {
		if got := hostReservedMem(t, n, target.Name); got != 512 {
			t.Fatalf("%s counts %d MiB on %s after the refused release, want 512", n.Name, got, target.Name)
		}
	}

	resp, err := ada.ReleaseHostReservation(ctx, req)
	if err != nil || !resp.Released || resp.Host != target.Name || resp.Vm != "held" || resp.Vcpu != 1 || resp.MemoryMib != 512 {
		t.Fatalf("release once the lock is free: %+v err %v, want 1 vCPU/512 MiB of held released on %s", resp, err, target.Name)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if got := hostReservedMem(t, n, target.Name); got != 0 {
			t.Errorf("%s still counts %d MiB on %s, want 0", n.Name, got, target.Name)
		}
		rows, err := n.DB.Query(ctx, `SELECT host_name, username, result FROM audit_log
			WHERE action = 'operation.reservation.release' AND target = 'stuck-op'`)
		if err != nil {
			t.Fatalf("audit on %s: %v", n.Name, err)
		}
		results := map[string]int{}
		for _, r := range rows {
			if r.String("host_name") != entry.Name || r.String("username") != "ada" {
				t.Errorf("%s: audit row by %s on %s, want ada on the entry node %s",
					n.Name, r.String("username"), r.String("host_name"), entry.Name)
			}
			results[r.String("result")]++
		}
		if len(rows) != 2 || results["refused"] != 1 || results["ok"] != 1 {
			t.Errorf("%s: audit results %v over %d rows, want one refused and one ok", n.Name, results, len(rows))
		}
	}
}

// F4: a target host that cannot decide the request. An older build answers
// Unimplemented, which reads as an upgrade to do; a host up and answering that
// refuses the forwarded call before its handler runs gets a retry, not a
// removal; one that cannot be reached at all is named with both remedies.
//
// Mutations (each red, each pinned by its own substring):
//   - swap the Unavailable and Unimplemented branches of the forward's mapping;
//   - drop refusedBeforeHandler's check: the not-yet-replicated login is told
//     to remove a live host.
func TestReleaseHostReservation_UnreachableAndOldTarget(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 1019})
	target, entry := c.Nodes[0], c.Nodes[1]
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		n.Server.SetForwardedIdentity(true)
	}
	for _, n := range c.Nodes {
		g := gates[n.Name]
		eventually(t, 10*time.Second, n.Name+" to latch forwarded_identity_v1", func() bool {
			return g.Enforced(ctx, capabilities.ForwardedIdentityV1)
		})
	}
	seedAbandonedResize(t, c, target, "stuck-op", "held")
	ada, pw := adminUser(t, c, entry, "ada")
	c.WaitConverged(t, convergeTimeout)
	req := &pb.ReleaseHostReservationRequest{OperationId: "stuck-op", Force: true}

	restore := target.DoNotImplement("ReleaseHostReservation")
	_, err := ada.ReleaseHostReservation(ctx, req)
	restore()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv host upgrade "+target.Name) {
		t.Fatalf("target on an older build: %v, want FailedPrecondition naming lv host upgrade %s", err, target.Name)
	}

	// A login the target has not replicated yet: the target refuses the
	// forwarded identity before any handler runs, so no trailer comes back.
	c.Isolate(target)
	login, err := c.SelfClient(entry).Login(ctx, &pb.LoginRequest{Username: "ada", Password: pw})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	_, err = c.bearerClient(entry, login.GetToken()).ReleaseHostReservation(ctx, req)
	c.ClearLinkFaults()
	if msg := status.Convert(err).Message(); status.Code(err) != codes.Unavailable ||
		!strings.Contains(msg, "refused the request before handling it") ||
		!strings.Contains(msg, "forwarded identity not yet visible on owner; retry") || strings.Contains(msg, "lv host rm") {
		t.Fatalf("target that has not seen the login yet: %v, want Unavailable passing on its retry and no lv host rm", err)
	}

	c.SetLinkFault(entry, target, LinkFault{BlockAll: true})
	_, err = ada.ReleaseHostReservation(ctx, req)
	c.SetLinkFault(entry, target, LinkFault{})
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "lv host rm "+target.Name) {
		t.Fatalf("target cut off: %v, want Unavailable naming lv host rm %s", err, target.Name)
	}

	target.Stop()
	_, err = ada.ReleaseHostReservation(ctx, req)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "lv host rm "+target.Name) {
		t.Fatalf("target down: %v, want Unavailable naming lv host rm %s", err, target.Name)
	}
	if got := hostReservedMem(t, entry, target.Name); got != 512 {
		t.Fatalf("%s counts %d MiB on %s, want the unreleased 512", entry.Name, got, target.Name)
	}
}
