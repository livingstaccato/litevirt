package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
)

// sweepOp seeds one reservation-bearing operation: its header at headerEpoch
// with the given created_at, and the given steps at their epochs. Test fixture
// data.
func sweepOp(t *testing.T, s *Server, id string, kind corrosion.OperationKind, resourceID string,
	headerEpoch int64, rv corrosion.ReservationVector, createdAt string, steps map[int64][]string) {
	t.Helper()
	sweepOpAs(t, s, id, kind, "vm", resourceID, "ResizeVMLive", headerEpoch, rv, createdAt, steps)
}

// sweepOpAs is sweepOp with an explicit resource kind and method.
func sweepOpAs(t *testing.T, s *Server, id string, kind corrosion.OperationKind, resourceKind, resourceID, method string,
	headerEpoch int64, rv corrosion.ReservationVector, createdAt string, steps map[int64][]string) {
	t.Helper()
	ctx := context.Background()
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := corrosion.InsertOperation(ctx, s.db, corrosion.OperationRecord{
		ID: id, Method: method, ResourceKind: resourceKind, ResourceID: resourceID,
		OperationKind: string(kind), RequestHash: "h", ReservationJSON: enc, VMOwnerEpoch: headerEpoch,
	}); err != nil {
		t.Fatalf("InsertOperation %s: %v", id, err)
	}
	if err := s.db.Execute(ctx, `UPDATE operations SET created_at = ? WHERE id = ?`, createdAt, id); err != nil {
		t.Fatalf("set created_at: %v", err)
	}
	for epoch, names := range steps {
		for _, n := range names {
			if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
				OperationID: id, OwnerEpoch: epoch, StepName: n}); err != nil {
				t.Fatalf("append %s@%d: %v", n, epoch, err)
			}
		}
	}
}

// sweepVM seeds a live VM row on test-host with an explicit owner epoch,
// incarnation stamp and barrier.
func sweepVM(t *testing.T, s *Server, name string, epoch int64, createdAt, activeOp string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: name, HostName: "test-host", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ?, created_at = ?, active_operation_id = ? WHERE name = ?`,
		epoch, createdAt, activeOp, name); err != nil {
		t.Fatalf("set vm fields: %v", err)
	}
}

func sweepAgo(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

func sweepAgoNano(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }

// sweepLeakSteps is the lab's leaked resize: admission at the header's epoch 0,
// the whole workload operation, through completed, at the VM's epoch 1.
func sweepLeakSteps() map[int64][]string {
	return map[int64][]string{
		0: {corrosion.OpStepReserved, corrosion.OpStepAdmitted},
		1: {corrosion.OpStepPlanned, corrosion.OpStepDesiredPersisted, corrosion.OpStepConfigApplied,
			corrosion.OpStepLiveApplied, corrosion.OpStepObserved, corrosion.OpStepCompleted},
	}
}

// sweepAdmittedSteps is an operation admitted at epoch e that nothing finished.
func sweepAdmittedSteps(e int64) map[int64][]string {
	return map[int64][]string{e: {corrosion.OpStepReserved, corrosion.OpStepAdmitted}}
}

func sweepVector(host string, mem int) corrosion.ReservationVector {
	return corrosion.ReservationVector{TargetHost: host, TargetMemMiB: mem, Provisional: true}
}

// sweepMetrics attaches reservation metrics on a fresh registry.
func sweepMetrics(s *Server) *prometheus.Registry {
	reg := prometheus.NewRegistry()
	s.SetReservationMetrics(metrics.NewReservationMetricsWith(reg))
	return reg
}

// metricValue is the value of name's series whose labels include want, 0 when
// there is none.
func metricValue(t *testing.T, reg *prometheus.Registry, name string, want map[string]string) float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
	series:
		for _, m := range mf.GetMetric() {
			have := map[string]string{}
			for _, lp := range m.GetLabel() {
				have[lp.GetName()] = lp.GetValue()
			}
			for k, v := range want {
				if have[k] != v {
					continue series
				}
			}
			switch {
			case m.GetCounter() != nil:
				return m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				return m.GetGauge().GetValue()
			}
		}
	}
	return 0
}

// releaseRows counts op's release rows.
func releaseRows(t *testing.T, s *Server, op string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT 1 FROM operation_steps
		WHERE operation_id = ? AND step_name = ? AND facts = ? AND deleted_at IS NULL`,
		op, corrosion.OpStepCancelled, corrosion.ReservationReleasedFacts)
	if err != nil {
		t.Fatalf("query release rows: %v", err)
	}
	return len(rows)
}

func reservedMem(t *testing.T, s *Server, host string) int {
	t.Helper()
	_, mem, err := corrosion.HostReserved(context.Background(), s.db, host)
	if err != nil {
		t.Fatalf("HostReserved(%s): %v", host, err)
	}
	return mem
}

// G1: the lab's leaked resize is released, audited as the system actor, and
// counted under its reason.
func TestReservationSweep_ReleasesLabLeakShape(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	ctx := context.Background()
	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "leak", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("test-host", 512),
		sweepAgo(time.Hour), sweepLeakSteps())
	if got := reservedMem(t, s, "test-host"); got != 512 {
		t.Fatalf("precondition: test-host reserves %d MiB, want the leaked 512", got)
	}

	if n := s.SweepReservationsOnce(ctx); n != 1 {
		t.Fatalf("sweep released %d, want 1", n)
	}
	if got := reservedMem(t, s, "test-host"); got != 0 {
		t.Fatalf("after the sweep test-host still reserves %d MiB, want 0", got)
	}
	rows, err := s.db.Query(ctx, `SELECT username, target, detail, result FROM audit_log
		WHERE action = 'operation.reservation.release'`)
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	if r := rows[0]; r.String("username") != "litevirt" || r.String("target") != "leak" || r.String("result") != "ok" ||
		!strings.Contains(r.String("detail"), "by=sweep") || !strings.Contains(r.String("detail"), "mem_mib=512") {
		t.Errorf("audit row: user=%q target=%q result=%q detail=%q", r.String("username"), r.String("target"),
			r.String("result"), r.String("detail"))
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_releases_total", map[string]string{"reason": "terminal_past_header"}); v != 1 {
		t.Errorf("releases_total{terminal_past_header} = %v, want 1", v)
	}
	if v := metricValue(t, reg, "litevirt_host_reserved_memory_mib", nil); v != 0 {
		t.Errorf("reserved_memory_mib = %v, want 0 after the release", v)
	}
	if n := s.SweepReservationsOnce(ctx); n != 0 || releaseRows(t, s, "leak") != 1 {
		t.Fatalf("second sweep released %d (release rows %d), want 0 and one row", n, releaseRows(t, s, "leak"))
	}
}

// G2: a real resize parked between its admission and its barrier is never
// released, even when its evidence reads vm_gone (a skewed incarnation stamp):
// the VM lock it holds is the only thing that says it is in flight.
func TestReservationSweep_NeverReleasesInFlightResize(t *testing.T) {
	s := coordResizeServer(t)
	reg := sweepMetrics(s)
	ctx := adminCtx()
	seedRunningVM(t, s, "gr", &pb.VMSpec{Name: "gr", Cpu: 2, MaxCpu: 8, MemoryMib: 2048, MinMemoryMib: 1024, MaxMemoryMib: 8192}, 2, 2048)
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 1 WHERE name = 'gr'`); err != nil {
		t.Fatalf("set owner epoch: %v", err)
	}
	s.db.MarkReplicaCaughtUpForTests("peer-host")
	var parkedOp string
	var swept int
	s.admissionVerifiedHook = func(opID string) {
		parkedOp = opID
		// A clock-skewed incarnation stamp: the VM row looks newer than the
		// operation, so the evidence alone says vm_gone.
		future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano)
		if err := s.db.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'gr'`, future); err != nil {
			t.Errorf("skew the incarnation stamp: %v", err)
		}
		v, err := corrosion.ClassifyReservation(ctx, s.db, opID)
		if err != nil || v == nil || !v.Releasable() {
			t.Errorf("parked resize must read releasable for this test to mean anything: view=%+v err=%v", v, err)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			swept = s.SweepReservationsOnce(context.Background())
		}()
		wg.Wait()
		if err := s.db.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'gr'`, sweepAgoNano(48*time.Hour)); err != nil {
			t.Errorf("restore the incarnation stamp: %v", err)
		}
	}
	if err := s.resizeVMLive(ctx, "gr", &pb.VMSpec{Cpu: 2, MemoryMib: 2560}, "k-gr"); err != nil {
		t.Fatalf("grow: %v", err)
	}
	if parkedOp == "" {
		t.Fatal("the admission hook never ran")
	}
	if swept != 0 || releaseRows(t, s, parkedOp) != 0 {
		t.Fatalf("the sweep released a resize mid-admission: released=%d release rows=%d", swept, releaseRows(t, s, parkedOp))
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_sweep_skipped_total", map[string]string{"reason": "vm_busy"}); v != 1 {
		t.Errorf("sweep_skipped_total{vm_busy} = %v, want 1", v)
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_releases_total", map[string]string{"reason": "vm_gone"}); v != 0 {
		t.Errorf("releases_total{vm_gone} = %v, want 0", v)
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "gr"); vm == nil || vm.ActiveOperationID != "" {
		t.Fatalf("resize did not complete: %+v", vm)
	}
	if got := reservedMem(t, s, "test-host"); got != 0 {
		t.Fatalf("after the completed resize test-host reserves %d MiB, want 0", got)
	}
}

// G3: an untrusted replica releases nothing, and the skip is counted.
func TestReservationSweep_SkipsUntrustedReplica(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	ctx := context.Background()
	for _, h := range []string{"test-host", "peer-host"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	s.db.MarkReplicaStale("test: restarted")
	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "leak", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("test-host", 512),
		sweepAgo(time.Hour), sweepLeakSteps())

	if n := s.SweepReservationsOnce(ctx); n != 0 || releaseRows(t, s, "leak") != 0 {
		t.Fatalf("untrusted replica: released %d (rows %d), want nothing", n, releaseRows(t, s, "leak"))
	}
	if got := reservedMem(t, s, "test-host"); got != 512 {
		t.Fatalf("untrusted replica: test-host reserves %d MiB, want 512", got)
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_sweep_skipped_total", map[string]string{"reason": "replica_untrusted"}); v != 1 {
		t.Errorf("sweep_skipped_total{replica_untrusted} = %v, want 1", v)
	}
	s.db.MarkReplicaCaughtUpForTests("peer-host")
	if n := s.SweepReservationsOnce(ctx); n != 1 {
		t.Fatalf("caught up: released %d, want 1", n)
	}
}

// G4: only the target host releases, or — for terminal_past_header alone —
// the smallest active host when the target is gone.
func TestReservationSweep_OnlyTargetOrDeputy(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, h := range []string{"test-host", "zz-other", "x-gone", "y-removed", "b-offline"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := s.db.Execute(ctx, `UPDATE hosts SET deleted_at = ? WHERE name = 'x-gone'`, sweepAgo(time.Minute)); err != nil {
		t.Fatalf("tombstone x-gone: %v", err)
	}
	if err := corrosion.UpdateHostState(ctx, s.db, "y-removed", "removed"); err != nil {
		t.Fatalf("remove y-removed: %v", err)
	}
	// Sorts before test-host but is not active, so it is never the deputy.
	if err := corrosion.UpdateHostState(ctx, s.db, "b-offline", "offline"); err != nil {
		t.Fatalf("offline b-offline: %v", err)
	}
	s.db.MarkReplicaCaughtUpForTests("zz-other")

	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "peer-a", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("zz-other", 128),
		sweepAgo(time.Hour), sweepLeakSteps())
	sweepOp(t, s, "orphan-a", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("x-gone", 256),
		sweepAgo(time.Hour), sweepLeakSteps())
	sweepOp(t, s, "orphan-b", corrosion.OpResourceUpdateRunning, "gone-vm", 1, sweepVector("y-removed", 64),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	sweepOp(t, s, "orphan-d", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("y-removed", 16),
		sweepAgo(time.Hour), sweepLeakSteps())
	if v, _ := corrosion.ClassifyReservation(ctx, s.db, "orphan-b"); v == nil || v.Class != corrosion.ReservationVMGone {
		t.Fatalf("precondition: orphan-b must be vm_gone, got %+v", v)
	}

	if n := s.SweepReservationsOnce(ctx); n != 2 {
		t.Fatalf("released %d, want 2 (the gone and the removed host's terminal reservations)", n)
	}
	if releaseRows(t, s, "orphan-d") != 1 {
		t.Error("the deputy did not release a terminal reservation of a host that is present but not active")
	}
	if releaseRows(t, s, "peer-a") != 0 {
		t.Error("released an active peer's reservation")
	}
	if releaseRows(t, s, "orphan-a") != 1 {
		t.Error("the deputy did not release the removed host's terminal reservation")
	}
	if releaseRows(t, s, "orphan-b") != 0 {
		t.Error("released a vm_gone reservation by deputy")
	}

	// A smaller active host is the deputy now.
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "a-first", Address: "10.0.0.2", State: "active"}); err != nil {
		t.Fatalf("InsertHost a-first: %v", err)
	}
	sweepOp(t, s, "orphan-c", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("x-gone", 32),
		sweepAgo(time.Hour), sweepLeakSteps())
	if n := s.SweepReservationsOnce(ctx); n != 0 || releaseRows(t, s, "orphan-c") != 0 {
		t.Fatalf("not the deputy: released %d (rows %d), want nothing", n, releaseRows(t, s, "orphan-c"))
	}
}

// G5: a resize whose VM was deleted is released on its target host.
func TestReservationSweep_VMGone(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	ctx := context.Background()
	sweepVM(t, s, "doomed", 1, sweepAgoNano(48*time.Hour), "")
	if err := s.db.Execute(ctx, `UPDATE vms SET deleted_at = ? WHERE name = 'doomed'`, sweepAgo(time.Minute)); err != nil {
		t.Fatalf("tombstone the VM: %v", err)
	}
	sweepOp(t, s, "gone", corrosion.OpResourceUpdateRunning, "doomed", 1, sweepVector("test-host", 768),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	if n := s.SweepReservationsOnce(ctx); n != 1 {
		t.Fatalf("released %d, want 1", n)
	}
	if got := reservedMem(t, s, "test-host"); got != 0 {
		t.Fatalf("test-host still reserves %d MiB, want 0", got)
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_releases_total", map[string]string{"reason": "vm_gone"}); v != 1 {
		t.Errorf("releases_total{vm_gone} = %v, want 1", v)
	}
}

func staleCondition(t *testing.T, s *Server) (corrosion.HealthCondition, staleReservationEvidence, bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), s.db, reservationSweepEvaluator,
		CondReservationStale, "host", s.hostName)
	if err != nil {
		t.Fatalf("GetHealthCondition: %v", err)
	}
	open := found && row.Lifecycle != corrosion.ConditionResolved
	var ev staleReservationEvidence
	if open {
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			t.Fatalf("evidence %q: %v", row.Evidence, err)
		}
	}
	return row, ev, open
}

// reservation_stale: raised for a reservation no running operation holds past
// its bound, naming it and the remedy; not for one in flight or still
// admitting; unchanged evidence writes nothing; resolved once it is released.
func TestReservationSweep_StaleCondition(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	ctx := context.Background()
	sweepVM(t, s, "c1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "stuck", corrosion.OpResourceUpdateRunning, "c1", 1, sweepVector("test-host", 256),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	sweepVM(t, s, "f1", 1, sweepAgoNano(48*time.Hour), "flying")
	sweepOp(t, s, "flying", corrosion.OpResourceUpdateRunning, "f1", 1, sweepVector("test-host", 128),
		sweepAgo(2*time.Hour), map[int64][]string{1: {corrosion.OpStepReserved, corrosion.OpStepAdmitted, corrosion.OpStepPlanned}})
	sweepVM(t, s, "y1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "young", corrosion.OpResourceUpdateRunning, "y1", 1, sweepVector("test-host", 64),
		sweepAgo(5*time.Minute), sweepAdmittedSteps(1))

	if n := s.SweepReservationsOnce(ctx); n != 0 {
		t.Fatalf("released %d, want 0 (none is releasable by the sweep)", n)
	}
	row, ev, open := staleCondition(t, s)
	if !open || row.Severity != corrosion.SeverityWarning {
		t.Fatalf("reservation_stale: open=%v severity=%q, want an open warning", open, row.Severity)
	}
	if ev.Count != 1 || len(ev.Reservations) != 1 {
		t.Fatalf("evidence lists %d (count %d), want only the stuck reservation: %+v", len(ev.Reservations), ev.Count, ev)
	}
	e := ev.Reservations[0]
	if e.OperationID != "stuck" || e.VM != "c1" || e.MemoryMiB != 256 ||
		!strings.Contains(e.Remedy, "lv operation release-reservation <operation-id> --force") ||
		!strings.Contains(e.Remedy, "lv operation show <vm>") {
		t.Errorf("evidence entry: %+v", e)
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_oldest_seconds", nil); v < 3500 || v > 3700 {
		t.Errorf("oldest_seconds = %v, want about an hour (the in-flight one is older and excluded)", v)
	}
	if v := metricValue(t, reg, "litevirt_host_reserved_memory_mib", nil); v != 448 {
		t.Errorf("reserved_memory_mib = %v, want 448", v)
	}

	s.SweepReservationsOnce(ctx)
	if again, _, _ := staleCondition(t, s); again.ObserveCount != row.ObserveCount {
		t.Errorf("an unchanged condition was rewritten: observe count %d -> %d", row.ObserveCount, again.ObserveCount)
	}

	if _, err := corrosion.ReleaseReservation(ctx, s.db, "stuck"); err != nil {
		t.Fatalf("release by hand: %v", err)
	}
	s.SweepReservationsOnce(ctx)
	if row, _, open := staleCondition(t, s); open {
		t.Fatalf("reservation_stale still open after the release: %+v", row)
	}
}

// A blocked release is never released, is logged once per operation (not every
// pass), and holds reservation_stale once past its bound.
func TestReservationSweep_BlockedReleaseIsAFaultLoggedOnce(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	logs := &lockedLog{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	for _, op := range []struct {
		id  string
		age time.Duration
	}{{"blocked-old", time.Hour}, {"blocked-young", 5 * time.Minute}} {
		sweepOp(t, s, op.id, corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("test-host", 512),
			sweepAgo(op.age), sweepLeakSteps())
		if err := corrosion.AppendOperationStep(ctx, s.db, corrosion.OperationStepRecord{
			OperationID: op.id, OwnerEpoch: 0, StepName: corrosion.OpStepCancelled}); err != nil {
			t.Fatalf("append cancelled: %v", err)
		}
		if err := s.db.Execute(ctx, `UPDATE operation_steps SET deleted_at = ?
			WHERE operation_id = ? AND owner_epoch = 0 AND step_name = ?`, sweepAgo(time.Minute), op.id, corrosion.OpStepCancelled); err != nil {
			t.Fatalf("tombstone cancelled: %v", err)
		}
	}
	for i := 0; i < 3; i++ {
		if n := s.SweepReservationsOnce(ctx); n != 0 {
			t.Fatalf("pass %d released %d, want 0", i, n)
		}
	}
	if got := reservedMem(t, s, "test-host"); got != 1024 {
		t.Fatalf("test-host reserves %d MiB, want both blocked reservations still counted (1024)", got)
	}
	out := logs.String()
	if n := strings.Count(out, "could not release a reservation"); n != 2 {
		t.Errorf("fault logged %d times over three passes, want once per operation (2); log:\n%s", n, out)
	}
	for _, id := range []string{"blocked-old", "blocked-young"} {
		if n := strings.Count(out, "operation_id="+id+" "); n != 1 {
			t.Errorf("%s: logged %d times over three passes, want once; log:\n%s", id, n, out)
		}
	}
	_, ev, open := staleCondition(t, s)
	if !open || ev.Count != 1 || ev.Reservations[0].OperationID != "blocked-old" ||
		!strings.Contains(ev.Reservations[0].Remedy, "tombstoned") {
		t.Fatalf("reservation_stale: open=%v evidence=%+v, want only blocked-old with the blocked remedy", open, ev)
	}
}

// The listing is re-checked under the VM lock: a reservation whose VM came back
// between the listing and the lock is not released, and a terminal
// reservation is not released while its VM's lock is held.
func TestReservationSweep_ReclassifiesUnderTheLock(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	ctx := context.Background()
	sweepVM(t, s, "rc", 1, sweepAgoNano(48*time.Hour), "")
	if err := s.db.Execute(ctx, `UPDATE vms SET deleted_at = ? WHERE name = 'rc'`, sweepAgo(time.Minute)); err != nil {
		t.Fatalf("tombstone the VM: %v", err)
	}
	sweepOp(t, s, "back", corrosion.OpResourceUpdateRunning, "rc", 1, sweepVector("test-host", 64),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	s.resSweep.beforeReclassify = func(string) {
		if err := s.db.Execute(ctx, `UPDATE vms SET deleted_at = NULL WHERE name = 'rc'`); err != nil {
			t.Errorf("restore the VM: %v", err)
		}
	}
	if n := s.SweepReservationsOnce(ctx); n != 0 || releaseRows(t, s, "back") != 0 {
		t.Fatalf("released a reservation whose VM is back: released %d, rows %d", n, releaseRows(t, s, "back"))
	}
	s.resSweep.beforeReclassify = nil

	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "leak", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("test-host", 512),
		sweepAgo(time.Hour), sweepLeakSteps())
	unlock := s.lockVM("vm1")
	if n := s.SweepReservationsOnce(ctx); n != 0 || releaseRows(t, s, "leak") != 0 {
		unlock()
		t.Fatalf("released a terminal reservation under a held VM lock: released %d", n)
	}
	unlock()
	if v := metricValue(t, reg, "litevirt_host_reservation_sweep_skipped_total", map[string]string{"reason": "vm_busy"}); v != 1 {
		t.Errorf("sweep_skipped_total{vm_busy} = %v, want 1", v)
	}
	if n := s.SweepReservationsOnce(ctx); n != 1 {
		t.Fatalf("lock released: released %d, want 1", n)
	}
}

// A release write that fails is retried every pass, counted as a state-write
// failure, logged once, and named in reservation_stale; a pass that finds its
// VM busy keeps the fault rather than dropping and re-logging it.
func TestReservationSweep_ReleaseWriteFailure(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	logs := &lockedLog{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	var writeFails []string
	s.SetStateWriteFailObserver(func(op, _ string) { writeFails = append(writeFails, op) })
	s.resSweep.release = func(context.Context, *corrosion.Client, string) (bool, error) {
		return false, errors.New("disk I/O error")
	}

	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "leak", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("test-host", 512),
		sweepAgo(time.Hour), sweepLeakSteps())
	for i := 0; i < 3; i++ {
		if n := s.SweepReservationsOnce(ctx); n != 0 {
			t.Fatalf("pass %d released %d with a failing write", i, n)
		}
	}
	if len(writeFails) != 3 || writeFails[0] != "reservation_release" {
		t.Errorf("state-write failures = %v, want reservation_release once per pass", writeFails)
	}
	row, ev, open := staleCondition(t, s)
	if !open || ev.Count != 1 || ev.Reservations[0].OperationID != "leak" ||
		!strings.Contains(ev.Reservations[0].Remedy, "could not write its release row") {
		t.Fatalf("reservation_stale: open=%v evidence=%+v, want leak with the failed-write remedy", open, ev)
	}

	unlock := s.lockVM("vm1")
	s.SweepReservationsOnce(ctx)
	unlock()
	if again, ev2, open2 := staleCondition(t, s); !open2 || ev2.Count != 1 || again.ObserveCount != row.ObserveCount {
		t.Errorf("a busy pass changed the condition: open=%v count=%d observe %d -> %d",
			open2, ev2.Count, row.ObserveCount, again.ObserveCount)
	}
	s.SweepReservationsOnce(ctx)
	if n := strings.Count(logs.String(), "could not release a reservation"); n != 1 {
		t.Errorf("the failed release was logged %d times, want once", n)
	}

	s.resSweep.release = nil
	if n := s.SweepReservationsOnce(ctx); n != 1 {
		t.Fatalf("write recovered: released %d, want 1", n)
	}
	if _, _, open := staleCondition(t, s); open {
		t.Error("reservation_stale still open after the release")
	}
}

// The oldest-reservation gauge leaves out a manifest journal and an admission
// lease within its own max age.
func TestReservationSweep_OldestLeavesOutHeldReservations(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	ctx := context.Background()
	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOpAs(t, s, "journal", corrosion.OpVMReplace, "vm", "vm1", "ReplaceVM", 0, sweepVector("test-host", 64),
		sweepAgo(3*time.Hour), sweepLeakSteps())
	sweepOpAs(t, s, "transfer", corrosion.OpResourceUpdateRunning, corrosion.CapacityResourceKind, "", "MigrateVM", 0,
		sweepVector("test-host", 64), sweepAgo(2*time.Hour), sweepLeakSteps())
	sweepOp(t, s, "stuck", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("test-host", 64),
		sweepAgo(30*time.Minute), sweepAdmittedSteps(1))
	if got := reservedMem(t, s, "test-host"); got != 192 {
		t.Fatalf("precondition: test-host reserves %d MiB, want all three counted (192)", got)
	}
	s.SweepReservationsOnce(ctx)
	if v := metricValue(t, reg, "litevirt_host_reservation_oldest_seconds", nil); v < 1700 || v > 1900 {
		t.Errorf("oldest_seconds = %v, want about 1800 (the journal and the transfer lease left out)", v)
	}

	// A lease past its own max age counts.
	sweepOpAs(t, s, "expired", corrosion.OpResourceUpdateRunning, corrosion.CapacityResourceKind, "", "CreateVM", 0,
		sweepVector("test-host", 64), sweepAgo(time.Hour), sweepLeakSteps())
	s.SweepReservationsOnce(ctx)
	if v := metricValue(t, reg, "litevirt_host_reservation_oldest_seconds", nil); v < 3500 || v > 3700 {
		t.Errorf("oldest_seconds = %v, want about 3600 (an admission lease past its max age)", v)
	}
}

// reservation_stale lists the longest-held reservations first.
func TestReservationSweep_StaleConditionListsOldestFirst(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	sweepVM(t, s, "c1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "a-new", corrosion.OpResourceUpdateRunning, "c1", 1, sweepVector("test-host", 64),
		sweepAgo(30*time.Minute), sweepAdmittedSteps(1))
	sweepOp(t, s, "z-old", corrosion.OpResourceUpdateRunning, "c1", 1, sweepVector("test-host", 64),
		sweepAgo(2*time.Hour), sweepAdmittedSteps(1))
	s.SweepReservationsOnce(ctx)
	_, ev, open := staleCondition(t, s)
	if !open || len(ev.Reservations) != 2 || ev.Reservations[0].OperationID != "z-old" {
		t.Fatalf("reservation_stale: open=%v evidence=%+v, want z-old listed first", open, ev)
	}
}

// A container's stale reservation names the container check, not the VM-only
// lv operation show, and the same manual release.
func TestReservationSweep_StaleConditionContainerRemedy(t *testing.T) {
	s := testServer(t)
	seedStuckContainer(t, s, "ct-op", "ct1", "")
	s.SweepReservationsOnce(context.Background())
	_, ev, open := staleCondition(t, s)
	if !open || ev.Count != 1 {
		t.Fatalf("reservation_stale: open=%v %+v, want the container reservation", open, ev)
	}
	r := ev.Reservations[0].Remedy
	if !strings.Contains(r, "lv ct inspect <container>") || strings.Contains(r, "lv operation show") ||
		!strings.Contains(r, "lv operation release-reservation <operation-id> --force") {
		t.Fatalf("container remedy %q, want the container check and the manual release", r)
	}
}

// seedUnreadableSweepRows adds two reservations whose data cannot be read:
// bad-here, a test-host reservation whose vector names another project than
// its operation, and bad-blind, whose vector does not decode (target unknown).
func seedUnreadableSweepRows(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	rv := sweepVector("test-host", 8)
	rv.Project = "beta"
	sweepOp(t, s, "bad-here", corrosion.OpResourceUpdateRunning, "vm1", 0, rv, sweepAgo(time.Hour), sweepLeakSteps())
	sweepOp(t, s, "bad-blind", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("test-host", 8),
		sweepAgo(time.Hour), sweepLeakSteps())
	for _, q := range []string{
		`UPDATE operations SET project = 'alpha' WHERE id = 'bad-here'`,
		`UPDATE operations SET reservation_json = '{not json' WHERE id = 'bad-blind'`,
	} {
		if err := s.db.Execute(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
}

// A reservation whose data cannot be read does not stop the sweep: every
// readable reservation is still released, gauged and reported, while the
// unreadable one is never released, and is counted, logged once and named in
// reservation_stale.
func TestReservationSweep_UnreadableRowDoesNotStopThePass(t *testing.T) {
	s := testServer(t)
	reg := sweepMetrics(s)
	ctx := context.Background()
	logs := &lockedLog{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "leak", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("test-host", 512),
		sweepAgo(time.Hour), sweepLeakSteps())
	sweepOp(t, s, "stuck", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("test-host", 256),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	seedUnreadableSweepRows(t, s)

	if n := s.SweepReservationsOnce(ctx); n != 1 || releaseRows(t, s, "leak") != 1 {
		t.Fatalf("released %d (leak rows %d), want the readable terminal reservation released", n, releaseRows(t, s, "leak"))
	}
	s.SweepReservationsOnce(ctx)
	for _, id := range []string{"bad-here", "bad-blind"} {
		if releaseRows(t, s, id) != 0 {
			t.Errorf("released %s, whose reservation could not be read", id)
		}
		if n := strings.Count(logs.String(), "operation_id="+id+" "); n != 1 {
			t.Errorf("%s logged %d times over two passes, want once; log:\n%s", id, n, logs.String())
		}
	}
	if !strings.Contains(logs.String(), "reservation sweep: a reservation could not be read") {
		t.Errorf("no unreadable-reservation log line; log:\n%s", logs.String())
	}
	if v := metricValue(t, reg, "litevirt_host_reservation_sweep_skipped_total", map[string]string{"reason": "unreadable"}); v != 4 {
		t.Errorf("sweep_skipped_total{unreadable} = %v, want 4 (two rows, two passes)", v)
	}
	if v := metricValue(t, reg, "litevirt_host_reserved_memory_mib", nil); v != 256 {
		t.Errorf("reserved_memory_mib = %v, want 256 (the readable stuck reservation)", v)
	}
	_, ev, open := staleCondition(t, s)
	byOp := map[string]staleReservation{}
	for _, r := range ev.Reservations {
		byOp[r.OperationID] = r
	}
	if !open || len(byOp) != 2 || byOp["stuck"].OperationID == "" {
		t.Fatalf("reservation_stale: open=%v evidence=%+v, want stuck and bad-here", open, ev)
	}
	if r := byOp["bad-here"]; r.Class != "unreadable" || !strings.Contains(r.Remedy, "cannot be read") {
		t.Fatalf("bad-here entry %+v, want class unreadable with its remedy", r)
	}
}

// A removed host's reservations that no sweep releases are reported by the
// deputy (the smallest active host) under the removed host's subject, with the
// remedy that frees them; the deputy resolves that condition once none is
// left, and resolves one the removed host raised about itself.
func TestReservationSweep_DeputyOwnsARemovedHostsCondition(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, h := range []string{"test-host", "a-first", "z-removed", "y-gone"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatalf("InsertHost %s: %v", h, err)
		}
	}
	if err := corrosion.UpdateHostState(ctx, s.db, "z-removed", "removed"); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE hosts SET deleted_at = ? WHERE name = 'y-gone'`, sweepAgo(time.Minute)); err != nil {
		t.Fatal(err)
	}
	s.db.MarkReplicaCaughtUpForTests("a-first")
	ts := sweepAgo(2 * time.Hour)
	if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{
		Evaluator: reservationSweepEvaluator, Code: CondReservationStale, SubjectKind: "host", SubjectID: "y-gone",
		Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning, Hosts: []string{"y-gone"},
		FirstSeen: ts, ConfirmedAt: ts, LastSeen: ts, Reporter: "y-gone", Evidence: `{"count":1,"reservations":[]}`,
	}); err != nil {
		t.Fatal(err)
	}
	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "orphan-c", corrosion.OpResourceUpdateRunning, "vm1", 1, sweepVector("z-removed", 128),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	sweepOp(t, s, "orphan-gone", corrosion.OpResourceUpdateRunning, "gone-vm", 1, sweepVector("z-removed", 64),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))

	subject := func(host string) (corrosion.HealthCondition, staleReservationEvidence, bool) {
		t.Helper()
		row, found, err := corrosion.GetHealthCondition(ctx, s.db, reservationSweepEvaluator, CondReservationStale, "host", host)
		if err != nil {
			t.Fatal(err)
		}
		var ev staleReservationEvidence
		open := found && row.Lifecycle != corrosion.ConditionResolved
		if open {
			if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
				t.Fatalf("evidence %q: %v", row.Evidence, err)
			}
		}
		return row, ev, open
	}

	// Not the deputy: a-first is active and sorts first.
	s.SweepReservationsOnce(ctx)
	if _, _, open := subject("z-removed"); open {
		t.Fatal("a node that is not the deputy reported a removed host's reservations")
	}
	if _, _, open := subject("y-gone"); !open {
		t.Fatal("a node that is not the deputy resolved a removed host's condition")
	}

	if err := corrosion.UpdateHostState(ctx, s.db, "a-first", "removed"); err != nil {
		t.Fatal(err)
	}
	s.SweepReservationsOnce(ctx)
	row, ev, open := subject("z-removed")
	if !open || row.Reporter != "test-host" || ev.Count != 2 {
		t.Fatalf("z-removed: open=%v reporter=%q evidence=%+v, want both reservations reported by the deputy", open, row.Reporter, ev)
	}
	for _, r := range ev.Reservations {
		if !strings.Contains(r.Remedy, "lv operation release-reservation <operation-id> --force") ||
			!strings.Contains(r.Remedy, "project quota") {
			t.Errorf("%s remedy %q, want the manual release and the quota it frees", r.OperationID, r.Remedy)
		}
	}
	if _, _, open := subject("y-gone"); open {
		t.Fatal("the deputy left a removed host's own condition open")
	}

	for _, id := range []string{"orphan-c", "orphan-gone"} {
		if resp, err := s.ReleaseHostReservation(adminCtx(), releaseReq(id)); err != nil || !resp.Released {
			t.Fatalf("release %s: %+v %v", id, resp, err)
		}
	}
	s.SweepReservationsOnce(ctx)
	if _, _, open := subject("z-removed"); open {
		t.Fatal("reservation_stale on the removed host still open after its reservations were released")
	}
}
