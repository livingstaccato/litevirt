package grpcapi

import (
	"context"
	"encoding/json"
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
	ctx := context.Background()
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := corrosion.InsertOperation(ctx, s.db, corrosion.OperationRecord{
		ID: id, Method: "ResizeVMLive", ResourceKind: "vm", ResourceID: resourceID,
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
	for _, h := range []string{"test-host", "zz-other", "x-gone", "y-removed"} {
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
	s.db.MarkReplicaCaughtUpForTests("zz-other")

	sweepVM(t, s, "vm1", 1, sweepAgoNano(48*time.Hour), "")
	sweepOp(t, s, "peer-a", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("zz-other", 128),
		sweepAgo(time.Hour), sweepLeakSteps())
	sweepOp(t, s, "orphan-a", corrosion.OpResourceUpdateRunning, "vm1", 0, sweepVector("x-gone", 256),
		sweepAgo(time.Hour), sweepLeakSteps())
	sweepOp(t, s, "orphan-b", corrosion.OpResourceUpdateRunning, "gone-vm", 1, sweepVector("y-removed", 64),
		sweepAgo(time.Hour), sweepAdmittedSteps(1))
	if v, _ := corrosion.ClassifyReservation(ctx, s.db, "orphan-b"); v == nil || v.Class != corrosion.ReservationVMGone {
		t.Fatalf("precondition: orphan-b must be vm_gone, got %+v", v)
	}

	if n := s.SweepReservationsOnce(ctx); n != 1 {
		t.Fatalf("released %d, want 1 (the removed host's terminal reservation)", n)
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
		!strings.Contains(e.Remedy, "manual reservation release") || !strings.Contains(e.Remedy, "lv operation show") {
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
