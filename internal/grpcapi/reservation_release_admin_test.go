package grpcapi

import (
	"context"
	"github.com/litevirt/litevirt/internal/pki"
	"net"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func releaseReq(op string) *pb.ReleaseHostReservationRequest {
	return &pb.ReleaseHostReservationRequest{OperationId: op, Force: true}
}

// reservationReleaseAudits is every operation.reservation.release audit row for op.
func reservationReleaseAudits(t *testing.T, s *Server, op string) []corrosion.Row {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT username, target, detail, result FROM audit_log
		WHERE action = 'operation.reservation.release' AND target = ?`, op)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	return rows
}

// seedStuckResize seeds the abandoned pre-commit shape (class C): VM vm on
// test-host with no barrier, and a resize admitted at epoch 1 an hour ago that
// nothing began.
func seedStuckResize(t *testing.T, s *Server, op, vm string, cpu, mem int) {
	t.Helper()
	sweepVM(t, s, vm, 1, sweepAgoNano(48*time.Hour), "")
	rv := sweepVector("test-host", mem)
	rv.TargetCPU = cpu
	sweepOp(t, s, op, corrosion.OpResourceUpdateRunning, vm, 1, rv, sweepAgo(time.Hour), sweepAdmittedSteps(1))
}

// seedStuckContainer seeds a container create no running operation holds: the
// container row exists with no barrier (or one naming barrier).
func seedStuckContainer(t *testing.T, s *Server, op, ct, barrier string) {
	t.Helper()
	ctx := context.Background()
	now := sweepAgo(time.Hour)
	if err := s.db.Execute(ctx, `INSERT INTO containers (host_name, name, image, state, created_at, updated_at, active_operation_id)
		VALUES ('test-host', ?, 'img', 'running', ?, ?, ?)`, ct, now, now, barrier); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	sweepOpAs(t, s, op, corrosion.OpWorkloadCreate, "container", ct, "CreateContainer", 0,
		corrosion.ReservationVector{TargetHost: "test-host", TargetMemMiB: 256, Workload: ct},
		sweepAgo(time.Hour), map[int64][]string{0: {corrosion.OpStepPlanned, corrosion.OpStepReserved}})
}

// G6: each refusal, with its code and a stable piece of its text.
func TestReleaseHostReservation_Refusals(t *testing.T) {
	leaseCreated := time.Now().Add(-2 * time.Hour).UTC().Truncate(time.Second)
	cases := []struct {
		name string
		seed func(t *testing.T, s *Server) (ctx context.Context, req *pb.ReleaseHostReservationRequest, release func())
		code codes.Code
		want []string
		not  string
	}{
		{"no operation id", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			return adminCtx(), releaseReq(""), nil
		}, codes.InvalidArgument, []string{"operation_id is required"}, ""},
		{"no force", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			seedStuckResize(t, s, "stuck", "vm1", 1, 512)
			return adminCtx(), &pb.ReleaseHostReservationRequest{OperationId: "stuck"}, nil
		}, codes.FailedPrecondition, []string{"requires force", "lv host inspect"}, ""},
		{"not found", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			return adminCtx(), releaseReq("deadbeef"), nil
		}, codes.NotFound, []string{"no operation deadbeef", "lv host inspect"}, ""},
		{"not counted", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
			sweepOp(t, s, "done", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("test-host", 512),
				sweepAgo(time.Hour), map[int64][]string{1: {corrosion.OpStepReserved, corrosion.OpStepCompleted}})
			return adminCtx(), releaseReq("done"), nil
		}, codes.FailedPrecondition, []string{"holds no reservation counted", "nothing to release"}, ""},
		{"manifest", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			sweepOpAs(t, s, "journal", corrosion.OpVMReplace, "vm", "vm1", "CutoverVM", 0, sweepVector("test-host", 16),
				sweepAgo(time.Hour), map[int64][]string{0: {corrosion.OpStepPlanned}})
			return adminCtx(), releaseReq("journal"), nil
		}, codes.InvalidArgument, []string{"vm_replace journal", "never released by hand"}, ""},
		{"capacity lease", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			sweepOpAs(t, s, "lease", corrosion.OpResourceUpdateRunning, corrosion.CapacityResourceKind, "", "MigrateVM", 0,
				sweepVector("test-host", 64), leaseCreated.Format(time.RFC3339), map[int64][]string{0: {corrosion.OpStepReserved}})
			return adminCtx(), releaseReq("lease"), nil
		}, codes.FailedPrecondition, []string{"admission lease", "stale-lease sweep releases it on its own at " +
			leaseCreated.Add(corrosion.TransferCapacityLeaseMaxAge).Format(time.RFC3339)}, ""},
		{"barrier held", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "running")
			sweepOp(t, s, "running", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("test-host", 512),
				sweepAgo(time.Hour), map[int64][]string{1: {corrosion.OpStepReserved, corrosion.OpStepAdmitted, corrosion.OpStepPlanned}})
			return adminCtx(), releaseReq("running"), nil
		}, codes.FailedPrecondition, []string{"still running", "lv operation show vm1", "lv operation abort vm1 --force"}, ""},
		{"container barrier held", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			seedStuckContainer(t, s, "ct-op", "ct1", "ct-op")
			return adminCtx(), releaseReq("ct-op"), nil
		}, codes.FailedPrecondition, []string{"still running", `container "ct1"`}, "lv operation"},
		{"admitting", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
			sweepOp(t, s, "young", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("test-host", 512),
				sweepAgo(5*time.Minute), sweepAdmittedSteps(1))
			return adminCtx(), releaseReq("young"), nil
		}, codes.FailedPrecondition, []string{"may still be committing"}, ""},
		{"VM lock held", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			seedStuckResize(t, s, "stuck", "vm1", 1, 512)
			return adminCtx(), releaseReq("stuck"), s.lockVM("vm1")
		}, codes.Unavailable, []string{`VM "vm1" has a request in flight on test-host`}, ""},
		{"replica untrusted", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			for _, h := range []string{"test-host", "peer-host"} {
				if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
					t.Fatal(err)
				}
			}
			s.db.MarkReplicaStale("test: restarted")
			seedStuckResize(t, s, "stuck", "vm1", 1, 512)
			return adminCtx(), releaseReq("stuck"), nil
		}, codes.Unavailable, []string{"ReleaseHostReservation refused on test-host"}, ""},
		{"forwarded hop held elsewhere", func(t *testing.T, s *Server) (context.Context, *pb.ReleaseHostReservationRequest, func()) {
			if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: "zz-other", Address: "10.0.0.1", State: "active"}); err != nil {
				t.Fatal(err)
			}
			sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
			sweepOp(t, s, "elsewhere", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("zz-other", 512),
				sweepAgo(time.Hour), sweepAdmittedSteps(1))
			return replicationPeerCtx("peer-x"), releaseReq("elsewhere"), nil
		}, codes.FailedPrecondition, []string{"held on zz-other", "not here"}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			ctx, req, unlock := tc.seed(t, s)
			_, err := s.ReleaseHostReservation(ctx, req)
			if unlock != nil {
				unlock()
			}
			if status.Code(err) != tc.code {
				t.Fatalf("code %s (%v), want %s", status.Code(err), err, tc.code)
			}
			msg := status.Convert(err).Message()
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("message %q does not contain %q", msg, w)
				}
			}
			if tc.not != "" && strings.Contains(msg, tc.not) {
				t.Errorf("message %q contains %q", msg, tc.not)
			}
			if req.GetOperationId() != "" && req.GetOperationId() != "deadbeef" && releaseRows(t, s, req.GetOperationId()) != 0 {
				t.Errorf("a refused release wrote a release row")
			}
		})
	}
}

// G7: an abandoned pre-commit reservation (class C) — the one the sweep never
// releases — is released by hand on its target host; a second call is an
// idempotent "already released".
func TestReleaseHostReservation_ReleasesAbandonedPreCommit(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	seedStuckResize(t, s, "stuck", "vm1", 2, 512)
	if v, _ := corrosion.ClassifyReservation(context.Background(), s.db, "stuck"); v == nil || v.Class != corrosion.ReservationNoRunningOperation {
		t.Fatalf("precondition: want no_running_operation, got %+v", v)
	}
	if n := s.SweepReservationsOnce(context.Background()); n != 0 {
		t.Fatalf("precondition: the sweep released %d, want 0 (class C is manual only)", n)
	}

	resp, err := s.ReleaseHostReservation(adminCtx(), releaseReq("stuck"))
	if err != nil {
		t.Fatalf("release: %v", err)
	}
	if !resp.Released || resp.Host != "test-host" || resp.Vm != "vm1" || resp.Vcpu != 2 || resp.MemoryMib != 512 ||
		resp.Detail != string(corrosion.ReservationNoRunningOperation) {
		t.Fatalf("response %+v, want released 2 vCPU/512 MiB of vm1 on test-host", resp)
	}
	if got := reservedMem(t, s, "test-host"); got != 0 {
		t.Fatalf("test-host still reserves %d MiB", got)
	}
	if releaseRows(t, s, "stuck") != 1 {
		t.Fatal("no release row")
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_releases_total", map[string]string{"reason": "admin"}); v != 1 {
		t.Errorf("releases_total{admin} = %v, want 1", v)
	}

	again, err := s.ReleaseHostReservation(adminCtx(), releaseReq("stuck"))
	if err != nil || again.Released || again.Detail != "already released" || again.Host != "test-host" {
		t.Fatalf("second release: %+v err %v, want an idempotent already released", again, err)
	}
	if releaseRows(t, s, "stuck") != 1 {
		t.Fatal("second release wrote again")
	}
}

// m-6: a blocked vm_gone reservation — its release row tombstoned, no terminal
// at any epoch, so neither the sweep nor the reaper ever ends it — is ended by
// the manual release, which reservation_stale names; the condition then clears.
func TestReleaseHostReservation_EndsABlockedVMGoneReservation(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	sweepOp(t, s, "blocked", corrosion.OpResourceUpdateRunning, "vm-x", 1, sweepVector("test-host", 512),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
		OperationID: "blocked", OwnerEpoch: 1, StepName: corrosion.OpStepCancelled, Facts: corrosion.ReservationReleasedFacts}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE operation_steps SET deleted_at = ?
		WHERE operation_id = 'blocked' AND step_name = 'cancelled'`, sweepAgo(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if v, _ := corrosion.ClassifyReservation(ctx, s.db, "blocked"); v == nil || v.Class != corrosion.ReservationVMGone || !v.ReleaseBlocked {
		t.Fatalf("precondition: want a blocked vm_gone, got %+v", v)
	}
	s.SweepReservationsOnce(ctx)
	_, ev, open := staleCondition(t, s)
	if !open || ev.Count != 1 || !strings.Contains(ev.Reservations[0].Remedy, "lv operation release-reservation <operation-id> --force") {
		t.Fatalf("reservation_stale: open=%v %+v, want the blocked reservation naming the manual release", open, ev)
	}

	resp, err := s.ReleaseHostReservation(adminCtx(), releaseReq("blocked"))
	if err != nil || !resp.Released || !strings.Contains(resp.Detail, "failed step") {
		t.Fatalf("release: %+v err %v, want released with a failed step", resp, err)
	}
	if got := reservedMem(t, s, "test-host"); got != 0 {
		t.Fatalf("test-host still reserves %d MiB", got)
	}
	s.SweepReservationsOnce(ctx)
	if row, _, open := staleCondition(t, s); open {
		t.Fatalf("reservation_stale still open after the release: %+v", row)
	}
	again, err := s.ReleaseHostReservation(adminCtx(), releaseReq("blocked"))
	if err != nil || again.Released || again.Detail != "already released" {
		t.Fatalf("second release: %+v err %v, want already released", again, err)
	}
}

// A container's reservation is decided under the container lock, not the VM
// lock of the same name.
func TestReleaseHostReservation_LocksByWorkloadKind(t *testing.T) {
	s := testServer(t)
	seedStuckContainer(t, s, "ct-op", "ct1", "")

	unlock, ok := s.TryLockContainer("ct1")
	if !ok {
		t.Fatal("TryLockContainer")
	}
	_, err := s.ReleaseHostReservation(adminCtx(), releaseReq("ct-op"))
	unlock()
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), `container "ct1" has a request in flight`) {
		t.Fatalf("under the container lock: %v, want Unavailable naming the container", err)
	}

	vmUnlock := s.lockVM("ct1")
	resp, err := s.ReleaseHostReservation(adminCtx(), releaseReq("ct-op"))
	vmUnlock()
	if err != nil || !resp.Released {
		t.Fatalf("under a VM lock of the same name: %+v err %v, want released", resp, err)
	}
}

// The decision is re-made under the lock: an operation that took the VM's
// barrier between the listing and the lock is not released.
func TestReleaseHostReservation_ReclassifiesUnderTheLock(t *testing.T) {
	s := testServer(t)
	seedStuckResize(t, s, "stuck", "vm1", 1, 512)
	s.resRelease.beforeReclassify = func(string) {
		if err := s.db.Execute(context.Background(), `UPDATE vms SET active_operation_id = 'stuck' WHERE name = 'vm1'`); err != nil {
			t.Errorf("take the barrier: %v", err)
		}
	}
	_, err := s.ReleaseHostReservation(adminCtx(), releaseReq("stuck"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("barrier taken before the re-classify: %v, want FailedPrecondition still running", err)
	}
	if releaseRows(t, s, "stuck") != 0 {
		t.Fatal("released a reservation whose operation took its barrier")
	}
}

// A reservation whose target host was removed is released on the node called.
func TestReleaseHostReservation_RemovedTargetIsDecidedHere(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "y-removed", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, s.db, "y-removed", "removed"); err != nil {
		t.Fatal(err)
	}
	s.db.MarkReplicaCaughtUpForTests("y-removed")
	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "orphan", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("y-removed", 128),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	resp, err := s.ReleaseHostReservation(adminCtx(), releaseReq("orphan"))
	if err != nil || !resp.Released || resp.Host != "y-removed" {
		t.Fatalf("release: %+v err %v, want released here for the removed host", resp, err)
	}
}

// G8: the verb is Admin's, not Operator's.
func TestReleaseHostReservation_RBAC(t *testing.T) {
	s := testServer(t)
	seedStuckResize(t, s, "stuck", "vm1", 1, 512)
	op := boundAtCtx(t, s, "olga", "operator", "Operator", "/")
	if _, err := s.ReleaseHostReservation(op, releaseReq("stuck")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Operator at /: %v, want PermissionDenied", err)
	}
	if releaseRows(t, s, "stuck") != 0 {
		t.Fatal("an Operator released a reservation")
	}
	admin := boundAtCtx(t, s, "ada", "operator", "Admin", "/")
	if resp, err := s.ReleaseHostReservation(admin, releaseReq("stuck")); err != nil || !resp.Released {
		t.Fatalf("Admin at /: %+v err %v, want released", resp, err)
	}
}

// G9: one audit row on the node the user called, attributed to the user; none
// on a forwarded hop; a refusal is audited as refused with its code.
func TestReleaseHostReservation_AuditsOnceWithCaller(t *testing.T) {
	s := testServer(t)
	seedStuckResize(t, s, "stuck", "vm1", 1, 512)
	seedStuckResize(t, s, "hop", "vm2", 1, 256)

	if _, err := s.ReleaseHostReservation(userCtx("ada", "admin"), releaseReq("stuck")); err != nil {
		t.Fatalf("release: %v", err)
	}
	rows := reservationReleaseAudits(t, s, "stuck")
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if r := rows[0]; r.String("username") != "ada" || r.String("result") != "ok" ||
		!strings.Contains(r.String("detail"), "host=test-host vm=vm1 vcpu=1 mem_mib=512 class=no_running_operation") {
		t.Errorf("audit row: user=%q result=%q detail=%q", r.String("username"), r.String("result"), r.String("detail"))
	}

	if resp, err := s.ReleaseHostReservation(replicationPeerCtx("peer-x"), releaseReq("hop")); err != nil || !resp.Released {
		t.Fatalf("forwarded hop: %+v err %v, want released", resp, err)
	}
	if rows := reservationReleaseAudits(t, s, "hop"); len(rows) != 0 {
		t.Fatalf("the forwarded hop wrote %d audit rows, want none (the entry node audits)", len(rows))
	}

	if _, err := s.ReleaseHostReservation(userCtx("ada", "admin"), &pb.ReleaseHostReservationRequest{OperationId: "stuck2"}); err == nil {
		t.Fatal("no force: want a refusal")
	}
	rows = reservationReleaseAudits(t, s, "stuck2")
	if len(rows) != 1 || rows[0].String("result") != "refused" || rows[0].String("username") != "ada" ||
		!strings.Contains(rows[0].String("detail"), "code=FailedPrecondition") {
		t.Fatalf("refusal audit rows: %+v, want one refused row with its code", rows)
	}

	if _, err := s.ReleaseHostReservation(userCtx("ada", "admin"), releaseReq("stuck")); err != nil {
		t.Fatalf("already released: %v", err)
	}
	rows = reservationReleaseAudits(t, s, "stuck")
	if len(rows) != 2 || rows[1].String("result") != "already" && rows[0].String("result") != "already" {
		t.Fatalf("already-released audit rows: %d, want a second row with result already", len(rows))
	}
}

// A refusal names the workload only to a caller who may read it, as the
// success response's vm field does: a role holding the release verb at /
// without vm.read learns no VM name from any refusal.
func TestReleaseHostReservation_RefusalsWithholdUnreadableNames(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertRole(ctx, s.db, corrosion.RoleRecord{Name: "Releaser", Verbs: []string{reservationReleaseVerb}}); err != nil {
		t.Fatalf("InsertRole: %v", err)
	}
	rita := boundAtCtx(t, s, "rita", "viewer", "Releaser", "/")
	if s.canReadVM(rita, "secret-held") {
		t.Fatal("precondition: the Releaser role reads VMs")
	}

	seedStuckResize(t, s, "held", "secret-held", 1, 512)
	sweepVM(t, s, "secret-run", 1, sweepAgoNano(48*time.Hour), "running")
	sweepOp(t, s, "running", corrosion.OpResourceUpdateRunning, "secret-run", 1, sweepVector("test-host", 512),
		sweepAgo(time.Hour), map[int64][]string{1: {corrosion.OpStepReserved, corrosion.OpStepAdmitted, corrosion.OpStepPlanned}})
	sweepOpAs(t, s, "journal", corrosion.OpVMReplace, "vm", "secret-journal", "CutoverVM", 0, sweepVector("test-host", 16),
		sweepAgo(time.Hour), map[int64][]string{0: {corrosion.OpStepPlanned}})

	cases := []struct {
		op, vm string
		code   codes.Code
		want   string
		lock   bool
	}{
		{"held", "secret-held", codes.Unavailable, "VM (name withheld) has a request in flight", true},
		{"running", "secret-run", codes.FailedPrecondition, "lv operation show <vm>", false},
		{"journal", "secret-journal", codes.InvalidArgument, "lv operation show <vm>", false},
	}
	for _, tc := range cases {
		t.Run(tc.op, func(t *testing.T) {
			call := func(ctx context.Context) error {
				if tc.lock {
					defer s.lockVM(tc.vm)()
				}
				_, err := s.ReleaseHostReservation(ctx, releaseReq(tc.op))
				return err
			}
			err := call(rita)
			if status.Code(err) != tc.code || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), tc.vm) {
				t.Fatalf("as a caller without vm.read: %v, want %s with %q and no %q", err, tc.code, tc.want, tc.vm)
			}
			if err := call(adminCtx()); status.Code(err) != tc.code || !strings.Contains(err.Error(), tc.vm) {
				t.Fatalf("as Admin: %v, want %s naming %q", err, tc.code, tc.vm)
			}
		})
	}

	// The entry node withholds the name from a refusal the target returned:
	// the target judged a peer, which reads every VM.
	mustInsertVM(t, s, "secret-fwd", "")
	fwd := status.Error(codes.FailedPrecondition,
		`operation x is still running: it holds VM "secret-fwd"'s mutation barrier. inspect it with lv operation show secret-fwd; abort a wedged one with lv operation abort secret-fwd --force`)
	got := s.redactWorkloadName(rita, fwd, "secret-fwd")
	if status.Code(got) != codes.FailedPrecondition || strings.Contains(got.Error(), "secret-fwd") ||
		!strings.Contains(got.Error(), "VM (name withheld)'s") || !strings.Contains(got.Error(), "lv operation abort <vm> --force") {
		t.Fatalf("forwarded refusal for a caller without vm.read: %v", got)
	}
	if got := s.redactWorkloadName(adminCtx(), fwd, "secret-fwd"); got != fwd {
		t.Fatalf("forwarded refusal for Admin was rewritten: %v", got)
	}
}

// A container reservation is locked by the container its create journalled
// (the operation's resource id), not by the reservation vector's copy of the
// name, which a legacy reservation may leave empty.
func TestReleaseHostReservation_ContainerLockNamedByResourceID(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	now := sweepAgo(time.Hour)
	if err := s.db.Execute(ctx, `INSERT INTO containers (host_name, name, image, state, created_at, updated_at, active_operation_id)
		VALUES ('test-host', 'ct2', 'img', 'running', ?, ?, '')`, now, now); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	sweepOpAs(t, s, "legacy-ct", corrosion.OpWorkloadCreate, "container", "ct2", "CreateContainer", 0,
		corrosion.ReservationVector{TargetHost: "test-host", TargetMemMiB: 256},
		now, map[int64][]string{0: {corrosion.OpStepPlanned, corrosion.OpStepReserved}})
	if v, _ := corrosion.ClassifyReservation(ctx, s.db, "legacy-ct"); v == nil || v.Class != corrosion.ReservationNoRunningOperation {
		t.Fatalf("precondition: want a counted no_running_operation reservation, got %+v", v)
	}

	unlock, ok := s.TryLockContainer("ct2")
	if !ok {
		t.Fatal("TryLockContainer")
	}
	_, err := s.ReleaseHostReservation(adminCtx(), releaseReq("legacy-ct"))
	unlock()
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), `container "ct2" has a request in flight`) {
		t.Fatalf("under ct2's lock: %v, want Unavailable naming ct2", err)
	}
	if releaseRows(t, s, "legacy-ct") != 0 {
		t.Fatal("released a container reservation while its container's lock was held")
	}
	if resp, err := s.ReleaseHostReservation(adminCtx(), releaseReq("legacy-ct")); err != nil || !resp.Released {
		t.Fatalf("after the lock is released: %+v err %v, want released", resp, err)
	}
}

// A forwarded request the target answered "already released" is audited as
// already released, whatever the entry node's replica classified it as before
// the forward.
func TestReleaseHostReservation_ForwardedAlreadyReleasedAudit(t *testing.T) {
	s := testServer(t)
	f := &reservationReleaseFacts{host: "peer-y", vm: "vm1", class: string(corrosion.ReservationNoRunningOperation), vcpu: 1, memMiB: 512}
	s.auditReservationRelease(userCtx("ada", "admin"), "fwd-op", f,
		&pb.ReleaseHostReservationResponse{Released: false, Host: "peer-y", Detail: "already released"}, nil)
	rows := reservationReleaseAudits(t, s, "fwd-op")
	if len(rows) != 1 || rows[0].String("result") != "already" ||
		!strings.Contains(rows[0].String("detail"), "class=already_released") {
		t.Fatalf("audit rows %+v, want one result=already row with class=already_released", rows)
	}
}

// Only the target's interceptor refusals — the host is up and answering —
// are told apart from a target that cannot be reached.
func TestRefusedBeforeHandler(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{status.Error(codes.Unavailable, forwardedIdentityNotVisible), true},
		{status.Error(codes.Unavailable, walQuarantineUserRefusal+" (behind) and accepts no user logins, sessions or API tokens; use another node"), true},
		{status.Error(codes.Unavailable, "connection error: desc = \"transport: Error while dialing: dial tcp 10.0.0.9:7443: connect: connection refused\""), false},
	} {
		if got := refusedBeforeHandler(tc.err); got != tc.want {
			t.Errorf("refusedBeforeHandler(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// One reservation whose data cannot be read does not stop the release of
// another; asked to release it, the release refuses — FailedPrecondition, not
// Internal — and writes nothing.
func TestReleaseHostReservation_UnreadableRowFailsClosedAlone(t *testing.T) {
	s := testServer(t)
	seedStuckResize(t, s, "stuck", "vm1", 1, 512)
	seedUnreadableSweepRows(t, s)
	if resp, err := s.ReleaseHostReservation(adminCtx(), releaseReq("stuck")); err != nil || !resp.Released {
		t.Fatalf("release beside an unreadable reservation: %+v err %v, want released", resp, err)
	}
	for _, id := range []string{"bad-here", "bad-blind"} {
		_, err := s.ReleaseHostReservation(adminCtx(), releaseReq(id))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot be read") {
			t.Fatalf("release %s: %v, want FailedPrecondition saying it cannot be read", id, err)
		}
		if releaseRows(t, s, id) != 0 {
			t.Fatalf("released %s, whose reservation could not be read", id)
		}
	}
}

// A finished operation's reservation on a fenced, offline or maintenance host
// that cannot be reached is released by the deputy sweep: the refusal says so
// rather than asking for the host to be removed.
func TestReleaseHostReservation_UnreachableNotActiveTargetNamesTheDeputy(t *testing.T) {
	for _, state := range []string{"fenced", "offline", "maintenance"} {
		t.Run(state, func(t *testing.T) {
			s := testServer(t)
			port, attempts := privateUnavailableReservationPeer(t, s)
			ctx := context.Background()
			for _, h := range []string{"test-host", "b-down"} {
				if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "127.0.0.1", GRPCPort: port, State: "active"}); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.UpdateHostState(ctx, s.db, "b-down", state); err != nil {
				t.Fatal(err)
			}
			sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
			sweepOp(t, s, "done", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("b-down", 512),
				sweepAgo(time.Hour), sweepLeakSteps())
			sweepOp(t, s, "stuck", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("b-down", 64),
				sweepAgo(time.Hour), sweepAdmittedSteps(1))
			cctx, cancel := context.WithTimeout(adminCtx(), 20*time.Second)
			defer cancel()

			_, err := s.ReleaseHostReservation(cctx, releaseReq("done"))
			msg := status.Convert(err).Message()
			if status.Code(err) != codes.Unavailable || !strings.Contains(msg, "deputy") ||
				!strings.Contains(msg, "lv host inspect b-down") || strings.Contains(msg, "lv host rm") {
				t.Fatalf("finished operation on a %s target: %v, want Unavailable naming the deputy sweep and no lv host rm", state, err)
			}
			if attempts.Load() == 0 {
				t.Fatal("unavailable branch never attempted private transport")
			}
			// A reservation the sweep never releases keeps the removal remedy.
			_, err = s.ReleaseHostReservation(cctx, releaseReq("stuck"))
			if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "lv host rm b-down") {
				t.Fatalf("stale reservation on a %s target: %v, want the lv host rm remedy", state, err)
			}
		})
	}
}

// The forwarded refusal's bare workload name is withheld only where it is a
// command's argument: words elsewhere that equal the name, or contain it, stay.
func TestRedactWorkloadName_OnlyTheArgument(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertRole(ctx, s.db, corrosion.RoleRecord{Name: "Releaser", Verbs: []string{reservationReleaseVerb}}); err != nil {
		t.Fatalf("InsertRole: %v", err)
	}
	rita := boundAtCtx(t, s, "rita", "viewer", "Releaser", "/")
	for _, tc := range []struct{ name, in, want string }{
		{"operation",
			`operation op1 is still running: it holds VM "operation"'s mutation barrier. inspect it with lv operation show operation; abort a wedged one with lv operation abort operation --force`,
			`operation op1 is still running: it holds VM (name withheld)'s mutation barrier. inspect it with lv operation show <vm>; abort a wedged one with lv operation abort <vm> --force`},
		{"node-0",
			`operation op1 is a vm_replace journal on node-0 (inspect it with lv operation show node-0)`,
			`operation op1 is a vm_replace journal on node-0 (inspect it with lv operation show <vm>)`},
		{"web",
			`webhook web-2 and web are fine; lv operation show web-2; lv operation show web.`,
			`webhook web-2 and web are fine; lv operation show web-2; lv operation show <vm>.`},
	} {
		got := s.redactWorkloadName(rita, status.Error(codes.FailedPrecondition, tc.in), tc.name)
		if m := status.Convert(got).Message(); m != tc.want {
			t.Errorf("redact %q:\n got %q\nwant %q", tc.name, m, tc.want)
		}
	}
}

func privateUnavailableReservationPeer(t *testing.T, s *Server) (int, *atomic.Int64) {
	t.Helper()
	s.pkiDir = t.TempDir()
	crt, key := filepath.Join(s.pkiDir, "ca.crt"), filepath.Join(s.pkiDir, "ca.key")
	if e := pki.GenerateCA(crt, key); e != nil {
		t.Fatal(e)
	}
	if e := pki.GenerateHostCert(crt, key, filepath.Join(s.pkiDir, "host.crt"), filepath.Join(s.pkiDir, "host.key"), s.hostName, net.ParseIP("127.0.0.1")); e != nil {
		t.Fatal(e)
	}
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	var attempts atomic.Int64
	done := make(chan struct{})
	t.Cleanup(func() {
		l.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("private unavailable listener not joined")
		}
	})
	go func() {
		defer close(done)
		for {
			c, e := l.Accept()
			if e != nil {
				return
			}
			attempts.Add(1)
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, &attempts
}
