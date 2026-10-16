package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
)

// The reservation sweep releases a host capacity reservation whose operation is
// provably no longer running: one that finished at an owner epoch past its
// header's (terminal_past_header), or whose VM no longer exists (vm_gone). The
// classification is corrosion.HostReservations', the same one `lv host
// inspect` shows; the release row is corrosion.ReleaseReservation's.

// reservationRecoveryInterval is the sweep's cadence.
const reservationRecoveryInterval = 60 * time.Second

const (
	reservationSweepEvaluator = "reservation-sweep"
	// CondReservationStale is raised by a node about itself while a reservation
	// counted against it is older than its operation kind's expected bound and
	// the sweep cannot release it. Resolved by the first pass with none.
	CondReservationStale = "reservation_stale"
	// reservationStaleListed caps the reservations the condition's evidence
	// names; `count` always carries the total.
	reservationStaleListed = 20
)

const (
	remedyNoRunningOperation = "no running operation holds this reservation, and the sweep releases only one " +
		"whose operation finished or whose VM is gone: check with lv operation show <vm> that nothing is running, " +
		"then release it with lv operation release-reservation <operation-id> --force (admin, audited)"
	remedyNoRunningContainerOperation = "no running operation holds this reservation, and the sweep releases only " +
		"a VM's: check with lv ct inspect <container> that nothing is running on the container, " +
		"then release it with lv operation release-reservation <operation-id> --force (admin, audited)"
	remedyReleaseBlocked = "its release row (cancelled at the header's owner epoch) is tombstoned and cannot be " +
		"written again, so the sweep cannot release it: release it with lv operation release-reservation " +
		"<operation-id> --force (admin, audited), which writes a failed step at the header's owner epoch instead"
	remedyReleaseFailed = "the sweep could not write its release row and retries every pass; the daemon log " +
		"names the error (reservation sweep: could not release a reservation)"
)

// noRunningOperationRemedy is the reservation_stale remedy of a reservation no
// running operation holds, worded for its workload kind.
func noRunningOperationRemedy(v *corrosion.HostReservationView) string {
	if v.Op.ResourceKind == "container" {
		return remedyNoRunningContainerOperation
	}
	return remedyNoRunningOperation
}

// reservationSweepState is the sweep's in-memory state.
type reservationSweepState struct {
	mu sync.Mutex
	// untrusted is whether the last pass found the replica untrusted, so the
	// state change is logged once rather than every pass.
	untrusted bool
	// faultLogged is, per operation, the fault last logged for it, so each is
	// logged once per operation and condition rather than every pass.
	faultLogged map[string]string

	// Test seams: beforeReclassify runs under the VM lock before the
	// re-classify; release replaces corrosion.ReleaseReservation.
	beforeReclassify func(opID string)
	release          func(ctx context.Context, c *corrosion.Client, opID string) (bool, error)
}

// faultRemedy is the condition remedy of a logged fault.
func faultRemedy(fault string) string {
	if fault == "release_blocked" {
		return remedyReleaseBlocked
	}
	return remedyReleaseFailed
}

// SetReservationMetrics attaches the reservation sweep's metrics.
func (s *Server) SetReservationMetrics(m *metrics.ReservationMetrics) { s.reservationMetrics = m }

// RunReservationRecovery runs the reservation sweep every
// reservationRecoveryInterval until ctx ends.
func (s *Server) RunReservationRecovery(ctx context.Context) {
	t := time.NewTicker(reservationRecoveryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SweepReservationsOnce(ctx)
		}
	}
}

// SweepReservationsOnce runs one sweep pass and returns how many reservations
// it released.
//
// It acts only on a trusted replica. A reservation is released by its target
// host, or — for terminal_past_header only — by the deputy for a target host
// that is removed or not active. The VM lock is held across the re-classify
// and the write, so no resize admission of that VM in this process can be
// between its reserve and its barrier while the release is decided.
func (s *Server) SweepReservationsOnce(ctx context.Context) (released int) {
	st := &s.resSweep
	st.mu.Lock()
	defer st.mu.Unlock()

	if ok, why := corrosion.ReplicaTrusted(ctx, s.db, s.hostName, s.db.ReplicaCaughtUp); !ok {
		s.reservationMetrics.Skipped("replica_untrusted")
		if !st.untrusted {
			slog.Info("reservation sweep: replica not trusted; releasing nothing until it is", "reason", why)
		}
		st.untrusted = true
		return 0
	}
	if st.untrusted {
		slog.Info("reservation sweep: replica trusted again; resuming")
	}
	st.untrusted = false

	views, err := corrosion.HostReservations(ctx, s.db, "")
	if err != nil {
		slog.Warn("reservation sweep: list host reservations", "error", err)
		return 0
	}

	var hosts []corrosion.HostRecord
	var hostsErr error
	hostsLoaded := false
	loadHosts := func() ([]corrosion.HostRecord, error) {
		if !hostsLoaded {
			hosts, hostsErr = corrosion.ListHosts(ctx, s.db)
			hostsLoaded = true
		}
		return hosts, hostsErr
	}

	releasedIDs := map[string]bool{}
	faults := map[string]string{} // op id → remedy, for the condition
	for i := range views {
		v := &views[i]
		if v.ReleaseBlocked && sweepReleasableClass(v.Class) && s.isReservationWriter(v, loadHosts) {
			s.noteReservationFault(v, "release_blocked", corrosion.ErrReservationReleaseBlocked)
			faults[v.Op.ID] = remedyReleaseBlocked
			continue
		}
		if !v.Releasable() || !s.isReservationWriter(v, loadHosts) {
			continue
		}
		ok, remedy := s.releaseSweptReservation(ctx, v, loadHosts)
		if ok {
			releasedIDs[v.Op.ID] = true
			released++
		} else if remedy != "" {
			faults[v.Op.ID] = remedy
		}
	}
	for op := range st.faultLogged {
		if _, still := faults[op]; !still {
			delete(st.faultLogged, op)
		}
	}
	s.publishReservationHealth(ctx, views, releasedIDs, faults)
	return released
}

// releaseSweptReservation releases one releasable reservation under the VM lock.
// ok is whether it wrote the release; remedy is non-empty when it could not and
// the failure is a fault rather than a changed state.
func (s *Server) releaseSweptReservation(ctx context.Context, v *corrosion.HostReservationView,
	loadHosts func() ([]corrosion.HostRecord, error)) (ok bool, remedy string) {
	unlock, locked := s.tryLockVM(v.VMName)
	if !locked {
		s.reservationMetrics.Skipped("vm_busy")
		// Not retried this pass: a fault it had stays recorded, so it is
		// neither logged again nor dropped from the condition.
		if f := s.resSweep.faultLogged[v.Op.ID]; f != "" {
			return false, faultRemedy(f)
		}
		return false, ""
	}
	defer unlock()
	if h := s.resSweep.beforeReclassify; h != nil {
		h(v.Op.ID)
	}

	cur, err := corrosion.ClassifyReservation(ctx, s.db, v.Op.ID)
	if err != nil {
		slog.Warn("reservation sweep: re-classify a reservation", "operation_id", v.Op.ID, "error", err)
		return false, ""
	}
	if cur == nil {
		return false, "" // released or reaped since the listing
	}
	if cur.ReleaseBlocked && sweepReleasableClass(cur.Class) {
		s.noteReservationFault(cur, "release_blocked", corrosion.ErrReservationReleaseBlocked)
		return false, remedyReleaseBlocked
	}
	if !cur.Releasable() || !s.isReservationWriter(cur, loadHosts) {
		return false, ""
	}
	release := corrosion.ReleaseReservation
	if s.resSweep.release != nil {
		release = s.resSweep.release
	}
	already, err := release(ctx, s.db, cur.Op.ID)
	switch {
	case errors.Is(err, corrosion.ErrReservationReleaseBlocked):
		s.noteReservationFault(cur, "release_blocked", err)
		return false, remedyReleaseBlocked
	case errors.Is(err, corrosion.ErrReservationInFlight), errors.Is(err, corrosion.ErrReservationNotFound):
		return false, "" // the operation took a barrier or was reaped in between
	case err != nil:
		s.noteStateWriteFail("reservation_release", err)
		s.noteReservationFault(cur, "release_failed", err)
		return false, remedyReleaseFailed
	case already:
		return false, ""
	}
	slog.Warn("released a host reservation whose operation is no longer running",
		"operation_id", cur.Op.ID, "method", cur.Op.Method, "vm", cur.VMName,
		"host", cur.Vector.TargetHost, "vcpu", cur.Vector.TargetCPU, "mem_mib", cur.Vector.TargetMemMiB,
		"class", string(cur.Class), "header_epoch", cur.HeaderEpoch, "terminal_epoch", cur.LatestEpoch)
	s.auditAs(ctx, "litevirt", "operation.reservation.release", cur.Op.ID,
		reservationReleaseDetail(cur)+" by=sweep", "ok")
	s.reservationMetrics.Released(string(cur.Class))
	return true, ""
}

// reservationReleaseDetail is the audit detail of a reservation release.
func reservationReleaseDetail(v *corrosion.HostReservationView) string {
	return fmt.Sprintf("host=%s vm=%s vcpu=%d mem_mib=%d class=%s",
		v.Vector.TargetHost, v.VMName, v.Vector.TargetCPU, v.Vector.TargetMemMiB, v.Class)
}

// sweepReleasableClass: the classes the sweep releases when nothing blocks it.
func sweepReleasableClass(c corrosion.ReservationClass) bool {
	return c == corrosion.ReservationTerminalPastHeader || c == corrosion.ReservationVMGone
}

// isReservationWriter reports whether this node releases v: it is v's target
// host, or v is terminal_past_header and this node is the deputy for a target
// host whose hosts row is gone or not active — the lexically smallest active
// host. vm_gone is decided only on the target, under its own VM lock.
func (s *Server) isReservationWriter(v *corrosion.HostReservationView, loadHosts func() ([]corrosion.HostRecord, error)) bool {
	if v.Vector.TargetHost == s.hostName {
		return true
	}
	if v.Class != corrosion.ReservationTerminalPastHeader {
		return false
	}
	hosts, err := loadHosts()
	if err != nil {
		return false
	}
	deputy := ""
	for _, h := range hosts {
		if h.State != "active" {
			continue
		}
		if h.Name == v.Vector.TargetHost {
			return false
		}
		if deputy == "" || h.Name < deputy {
			deputy = h.Name
		}
	}
	return deputy == s.hostName
}

// noteReservationFault logs a reservation the sweep cannot release, once per
// operation and fault.
func (s *Server) noteReservationFault(v *corrosion.HostReservationView, fault string, err error) {
	st := &s.resSweep
	if st.faultLogged == nil {
		st.faultLogged = map[string]string{}
	}
	if st.faultLogged[v.Op.ID] == fault {
		return
	}
	st.faultLogged[v.Op.ID] = fault
	slog.Error("reservation sweep: could not release a reservation",
		"operation_id", v.Op.ID, "vm", v.VMName, "host", v.Vector.TargetHost,
		"vcpu", v.Vector.TargetCPU, "mem_mib", v.Vector.TargetMemMiB, "class", string(v.Class),
		"fault", fault, "error", err)
}

// staleReservation is one entry of the reservation_stale condition's evidence.
type staleReservation struct {
	OperationID string `json:"operation_id"`
	Method      string `json:"method"`
	VM          string `json:"vm"`
	VCPU        int    `json:"vcpu"`
	MemoryMiB   int    `json:"memory_mib"`
	CreatedAt   string `json:"created_at"`
	Class       string `json:"class"`
	Remedy      string `json:"remedy"`
}

type staleReservationEvidence struct {
	Count        int                `json:"count"`
	Reservations []staleReservation `json:"reservations"`
}

// reservationCountsTowardOldest: the oldest-reservation gauge leaves out what
// is legitimately still held — one an operation holds in flight, a manifest
// journal, and an admission lease within its own max age.
func reservationCountsTowardOldest(v *corrosion.HostReservationView, age time.Duration) bool {
	switch v.Class {
	case corrosion.ReservationInFlight, corrosion.ReservationManifest:
		return false
	case corrosion.ReservationCapacityLease:
		return age > corrosion.CapacityLeaseMaxAge(v.Op.Method)
	}
	return true
}

// reservationExpectedBound is how long a reservation of kind may be held with no
// operation holding it in flight. Every kind the sweep sees past its admission
// holds a barrier while it runs, so the bound is the admission window.
func reservationExpectedBound(corrosion.OperationKind) time.Duration {
	return corrosion.RPCScopedLeaseMaxAge
}

// publishReservationHealth sets this host's reservation gauges and its
// reservation_stale condition from the pass's listing.
func (s *Server) publishReservationHealth(ctx context.Context, views []corrosion.HostReservationView,
	released map[string]bool, faults map[string]string) {
	now := time.Now()
	var oldest float64
	var stale []staleReservation
	for i := range views {
		v := &views[i]
		if v.Vector.TargetHost != s.hostName || released[v.Op.ID] {
			continue
		}
		created, perr := time.Parse(time.RFC3339Nano, v.Op.CreatedAt)
		createdOK := perr == nil
		age := now.Sub(created)
		if reservationCountsTowardOldest(v, age) && createdOK && age.Seconds() > oldest {
			oldest = age.Seconds()
		}
		remedy := ""
		switch {
		case v.Class == corrosion.ReservationNoRunningOperation:
			remedy = noRunningOperationRemedy(v)
		case faults[v.Op.ID] != "":
			remedy = faults[v.Op.ID]
		case v.ReleaseBlocked && sweepReleasableClass(v.Class):
			remedy = remedyReleaseBlocked
		default:
			continue
		}
		if !createdOK || age <= reservationExpectedBound(corrosion.OperationKind(v.Op.OperationKind)) {
			continue
		}
		stale = append(stale, staleReservation{
			OperationID: v.Op.ID, Method: v.Op.Method, VM: v.VMName,
			VCPU: v.Vector.TargetCPU, MemoryMiB: v.Vector.TargetMemMiB,
			CreatedAt: v.Op.CreatedAt, Class: string(v.Class), Remedy: remedy,
		})
	}
	cpu, mem, err := corrosion.HostReserved(ctx, s.db, s.hostName)
	if err != nil {
		slog.Warn("reservation sweep: read this host's reserved capacity", "error", err)
	} else {
		s.reservationMetrics.SetHostReserved(cpu, mem, oldest)
	}
	s.writeReservationStaleCondition(ctx, stale)
}

// writeReservationStaleCondition raises, updates or resolves this host's
// reservation_stale condition. An unchanged open condition writes nothing.
func (s *Server) writeReservationStaleCondition(ctx context.Context, stale []staleReservation) {
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, reservationSweepEvaluator, CondReservationStale, "host", s.hostName)
	if err != nil {
		slog.Warn("reservation sweep: read the reservation_stale condition", "error", err)
		return
	}
	open := found && row.Lifecycle != corrosion.ConditionResolved
	ts := time.Now().UTC().Format(time.RFC3339)
	if len(stale) == 0 {
		if !open {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("reservation sweep: resolve the reservation_stale condition", "error", err)
		}
		return
	}
	// Oldest first, so the listed ones are the longest held.
	sort.Slice(stale, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, stale[i].CreatedAt)
		tj, _ := time.Parse(time.RFC3339Nano, stale[j].CreatedAt)
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return stale[i].OperationID < stale[j].OperationID
	})
	ev := staleReservationEvidence{Count: len(stale), Reservations: stale[:min(len(stale), reservationStaleListed)]}
	b, _ := json.Marshal(ev)
	if open && row.Evidence == string(b) {
		return
	}
	if !open {
		row = corrosion.HealthCondition{Evaluator: reservationSweepEvaluator, Code: CondReservationStale,
			SubjectKind: "host", SubjectID: s.hostName, Lifecycle: corrosion.ConditionConfirmed,
			FirstSeen: ts, ConfirmedAt: ts}
	}
	row.Evidence, row.Severity, row.Hosts = string(b), corrosion.SeverityWarning, []string{s.hostName}
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen, row.ResolvedAt, row.Reporter = ts, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("reservation sweep: record the reservation_stale condition", "error", err)
	}
}
