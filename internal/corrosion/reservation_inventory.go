package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// The host reservation inventory: every in-flight capacity claim counted
// against a host, each with ONE classification that the reservation sweep,
// `lv host inspect` and the manual release all read, so they cannot disagree
// about whether a reservation is still relied on.

// RPCScopedLeaseMaxAge is how long an admission lease may sit nonterminal before
// it is treated as orphaned (the stale capacity-lease sweep), and how long any
// other reservation is reported as still admitting.
//
// Most leases are held for the duration of ONE RPC — seconds — so this is orders
// of magnitude above any legitimate lifetime, which is the point: expiring early
// would free capacity a live admission is still deciding against, and that is the
// one thing worse than leaking it. Migration and drain leases span the whole
// transfer and age against TransferCapacityLeaseMaxAge instead.
const RPCScopedLeaseMaxAge = 15 * time.Minute

// ReservationReleasedFacts is the facts value of the `cancelled` step that
// releases a reservation. It is the same constant for every writer, so two nodes
// releasing one reservation write the same row.
const ReservationReleasedFacts = "reservation-released"

// ReservationClass says whether a counted reservation is still relied on.
type ReservationClass string

const (
	// ReservationInFlight: the VM's (or container's) mutation barrier names the
	// operation, so it is running or resumable.
	ReservationInFlight ReservationClass = "in_flight"
	// ReservationAdmitting: younger than RPCScopedLeaseMaxAge with no barrier —
	// an admission that may still be committing.
	ReservationAdmitting ReservationClass = "admitting"
	// ReservationCapacityLease: an admission lease; the stale-lease sweep owns it.
	ReservationCapacityLease ReservationClass = "capacity_lease"
	// ReservationManifest: a vm_replace or drain_cold_move journal. A terminal
	// written on one would stop its recovery.
	ReservationManifest ReservationClass = "manifest"
	// ReservationTerminalPastHeader: the operation finished at an owner epoch
	// later than its header's, where no reader looks for its terminal.
	ReservationTerminalPastHeader ReservationClass = "terminal_past_header"
	// ReservationVMGone: the VM the operation was for no longer exists.
	ReservationVMGone ReservationClass = "vm_gone"
	// ReservationNoRunningOperation: none of the above — no barrier names it, it
	// is past the admission window, and nothing proves it finished.
	ReservationNoRunningOperation ReservationClass = "no_running_operation"
)

// HostReservationView is one counted reservation and the evidence it was
// classified from.
type HostReservationView struct {
	Op     OperationRecord
	Vector ReservationVector
	// HeaderEpoch is the header's vm_owner_epoch: the only epoch every reader
	// reduces the operation by.
	HeaderEpoch  int64
	StepsByEpoch map[int64][]string
	// LatestEpoch is the highest owner epoch any live step is at (HeaderEpoch
	// when there are no steps).
	LatestEpoch int64
	// LatestState is ReduceOperationState at LatestEpoch.
	LatestState string
	Admitted    bool
	// VMName is resource_id for a vm-kind operation, the vector's workload
	// otherwise.
	VMName string
	// VMLive is the live vms row named VMName, nil when there is none (or the
	// operation is not for a VM).
	VMLive *VMRecord
	// BarrierHeld: a live vms or containers row's active_operation_id names the
	// operation.
	BarrierHeld bool
	// ReleaseBlocked: a tombstoned cancelled row already holds the release
	// row's key at the header epoch, so ReleaseReservation cannot write it and
	// the reservation stays counted whatever its class (Releasable is false).
	ReleaseBlocked bool
	Class          ReservationClass
	Detail         string
}

// Releasable reports whether the sweep may release the reservation on its own
// evidence: its class is terminal_past_header or vm_gone, and its release is
// not blocked. The caller must still hold the VM lock on the target host.
func (v *HostReservationView) Releasable() bool {
	return !v.ReleaseBlocked && (v.Class == ReservationTerminalPastHeader || v.Class == ReservationVMGone)
}

// reservationSweepKinds are the operation kinds whose reservation can be
// released on terminal-past-header or vm-gone evidence. A manifest kind is never
// one (its terminal stops its recovery), and every other kind holds no
// workload-id reservation.
var reservationSweepKinds = map[OperationKind]bool{
	OpResourceUpdateRunning: true,
	OpWorkloadCreate:        true,
}

// reservationManifestKinds journal work whose reservation_json is a cleanup
// manifest. Nothing here ever releases them.
var reservationManifestKinds = map[OperationKind]bool{
	OpVMReplace:     true,
	OpDrainColdMove: true,
}

// HostReservations lists every reservation counted against host, classified. An
// empty host lists every counted reservation, whatever its target.
//
// Membership is exactly the operations nonterminalReservationsByID counts — the
// scan behind HostReserved and admission — so the listed vectors sum to what
// admission subtracts.
func HostReservations(ctx context.Context, c *Client, host string) ([]HostReservationView, error) {
	views, _, err := hostReservations(ctx, c, host, false)
	return views, err
}

// HostReservationsPartial is HostReservations for a reader that must not lose
// every row to one bad one: an operation whose reservation data cannot be read
// is left out of the views and returned in unreadable, when it targets host or
// its target cannot be decoded. A query error still fails it.
func HostReservationsPartial(ctx context.Context, c *Client, host string) ([]HostReservationView, []UnreadableReservation, error) {
	return hostReservations(ctx, c, host, true)
}

func hostReservations(ctx context.Context, c *Client, host string, tolerate bool) ([]HostReservationView, []UnreadableReservation, error) {
	byID, admitted, bad, err := nonterminalReservationsScan(ctx, c, tolerate)
	if err != nil {
		return nil, nil, err
	}
	var unreadable []UnreadableReservation
	for _, b := range bad {
		if host == "" || b.TargetHost == "" || b.TargetHost == host {
			unreadable = append(unreadable, b)
		}
	}
	sort.Slice(unreadable, func(i, j int) bool { return unreadable[i].OperationID < unreadable[j].OperationID })
	now := time.Now()
	out := make([]HostReservationView, 0, len(byID))
	for id, rv := range byID {
		if host != "" && rv.TargetHost != host {
			continue
		}
		v, err := loadReservationView(ctx, c, id, rv, admitted[id], now)
		if err != nil {
			return nil, nil, err
		}
		if v != nil {
			out = append(out, *v)
		}
	}
	// created_at mixes second and nanosecond stamps, which do not sort as
	// strings; order by the instant, then id.
	// An unparseable created_at sorts last.
	sort.Slice(out, func(i, j int) bool {
		ti, iok := parseReservationTime(out[i].Op.CreatedAt)
		tj, jok := parseReservationTime(out[j].Op.CreatedAt)
		if iok != jok {
			return iok
		}
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return out[i].Op.ID < out[j].Op.ID
	})
	return out, unreadable, nil
}

// ClassifyReservation classifies one operation's reservation. It returns nil
// when the operation holds no counted reservation (absent, reaped, terminal at
// its header epoch, or not attributable to its project's current authority).
func ClassifyReservation(ctx context.Context, c *Client, opID string) (*HostReservationView, error) {
	byID, admitted, err := nonterminalReservationsByID(ctx, c)
	if err != nil {
		return nil, err
	}
	rv, ok := byID[opID]
	if !ok {
		return nil, nil
	}
	return loadReservationView(ctx, c, opID, rv, admitted[opID], time.Now())
}

func loadReservationView(ctx context.Context, c *Client, id string, rv ReservationVector, admitted bool, now time.Time) (*HostReservationView, error) {
	op, err := GetOperation(ctx, c, id)
	if err != nil {
		return nil, err
	}
	if op == nil {
		return nil, nil // reaped between the scan and this read
	}
	v := &HostReservationView{
		Op: *op, Vector: rv, HeaderEpoch: op.VMOwnerEpoch, Admitted: admitted,
		StepsByEpoch: map[int64][]string{},
	}
	srows, err := c.Query(ctx,
		`SELECT owner_epoch, step_name FROM operation_steps
		 WHERE operation_id = ? AND deleted_at IS NULL`, id)
	if err != nil {
		return nil, err
	}
	v.LatestEpoch = v.HeaderEpoch
	for i, r := range srows {
		e := r.Int64("owner_epoch")
		v.StepsByEpoch[e] = append(v.StepsByEpoch[e], r.String("step_name"))
		if i == 0 || e > v.LatestEpoch {
			v.LatestEpoch = e
		}
	}
	v.LatestState, _ = ReduceOperationState(OperationKind(op.OperationKind), v.StepsByEpoch[v.LatestEpoch])

	switch op.ResourceKind {
	case "vm":
		v.VMName = op.ResourceID
		if v.VMLive, err = GetVM(ctx, c, op.ResourceID); err != nil {
			return nil, err
		}
		v.BarrierHeld = v.VMLive != nil && v.VMLive.ActiveOperationID == id
	default:
		v.VMName = rv.Workload
		if op.ResourceKind == "container" {
			rows, err := c.Query(ctx,
				`SELECT 1 FROM containers WHERE active_operation_id = ? AND deleted_at IS NULL`, id)
			if err != nil {
				return nil, err
			}
			v.BarrierHeld = len(rows) != 0
		}
	}
	brows, err := c.Query(ctx,
		`SELECT 1 FROM operation_steps
		 WHERE operation_id = ? AND owner_epoch = ? AND step_name = ? AND deleted_at IS NOT NULL`,
		id, v.HeaderEpoch, OpStepCancelled)
	if err != nil {
		return nil, err
	}
	v.ReleaseBlocked = len(brows) != 0
	v.Class, v.Detail = classifyReservation(v, now)
	if v.ReleaseBlocked {
		v.Detail = fmt.Sprintf("still counted; release blocked: its release row (cancelled at owner epoch %d) is tombstoned. %s",
			v.HeaderEpoch, v.Detail)
	}
	return v, nil
}

// classifyReservation is the one classification rule. The first clause that
// matches wins.
func classifyReservation(v *HostReservationView, now time.Time) (ReservationClass, string) {
	kind := OperationKind(v.Op.OperationKind)
	created, createdOK := parseReservationTime(v.Op.CreatedAt)
	switch {
	case reservationManifestKinds[kind]:
		return ReservationManifest, fmt.Sprintf("%s journal; it finishes through its own recovery", kind)
	case v.Op.ResourceKind == CapacityResourceKind:
		maxAge := CapacityLeaseMaxAge(v.Op.Method)
		if !createdOK {
			return ReservationCapacityLease, "admission lease; the stale-lease sweep releases it"
		}
		return ReservationCapacityLease, fmt.Sprintf("admission lease; the stale-lease sweep releases it at %s",
			created.Add(maxAge).UTC().Format(time.RFC3339))
	case v.BarrierHeld:
		return ReservationInFlight, fmt.Sprintf("operation holds the mutation barrier of %q (state %s at owner epoch %d)",
			v.VMName, v.LatestState, v.LatestEpoch)
	}
	sweepable := v.Op.ResourceKind == "vm" && reservationSweepKinds[kind]
	if sweepable && v.LatestEpoch > v.HeaderEpoch && isHardTerminal(v.LatestState) {
		return ReservationTerminalPastHeader, fmt.Sprintf(
			"terminal (%s) at owner epoch %d, header at %d; released by the next sweep",
			v.LatestState, v.LatestEpoch, v.HeaderEpoch)
	}
	if sweepable && createdOK && reservationVMGone(v.VMLive, created) {
		if v.VMLive == nil {
			return ReservationVMGone, fmt.Sprintf("VM %q no longer exists; released by the next sweep", v.VMName)
		}
		return ReservationVMGone, fmt.Sprintf("VM %q was re-created after this operation began; released by the next sweep", v.VMName)
	}
	if !createdOK || now.Sub(created) < RPCScopedLeaseMaxAge {
		return ReservationAdmitting, "admitted recently; it may still be committing"
	}
	return ReservationNoRunningOperation, fmt.Sprintf(
		"no running operation holds it (state %q at owner epoch %d, header at %d)",
		v.LatestState, v.LatestEpoch, v.HeaderEpoch)
}

// CapacityLeaseMaxAge is how long an admission lease taken by method may be held
// before the stale-lease sweep releases it.
func CapacityLeaseMaxAge(method string) time.Duration {
	if transferLeaseMethods[method] {
		return TransferCapacityLeaseMaxAge
	}
	return RPCScopedLeaseMaxAge
}

// isHardTerminal: completed, failed or cancelled. superseded alone is an
// epoch-takeover marker, not a finish of the work.
func isHardTerminal(state string) bool {
	return state == OpStepCompleted || state == OpStepFailed || state == OpStepCancelled
}

// reservationVMGone: no live row, or the live row is a later incarnation than
// the operation. The row's created_at is a nanosecond incarnation stamp, while
// most operation headers are stamped in whole seconds (InsertOperation,
// BeginVMOperation; a create header is nanoseconds). Both are truncated to the
// second before comparing, so a row created in the operation's own second is
// never called newer.
func reservationVMGone(vm *VMRecord, opCreated time.Time) bool {
	if vm == nil {
		return true
	}
	vmCreated, ok := parseReservationTime(vm.CreatedAt)
	if !ok {
		return false
	}
	return vmCreated.Truncate(time.Second).After(opCreated.Truncate(time.Second))
}

func parseReservationTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

var (
	// ErrReservationNotFound: no live operation header has that id.
	ErrReservationNotFound = errors.New("no such operation")
	// ErrReservationNotReleasable: the operation is a capacity lease or a
	// manifest journal, which nothing releases by a written terminal.
	ErrReservationNotReleasable = errors.New("operation is not a releasable reservation")
	// ErrReservationInFlight: a live VM or container mutation barrier names the
	// operation.
	ErrReservationInFlight = errors.New("operation still holds a mutation barrier")
	// ErrReservationReleaseBlocked: the reservation is still counted, and a
	// tombstoned release row holds the key the release would be written at, so
	// it cannot be released by a written terminal.
	ErrReservationReleaseBlocked = errors.New("reservation release blocked")
)

// ReleaseReservation writes the row that releases opID's reservation: a
// `cancelled` step at the header's owner epoch, the only epoch every reader —
// on every build — reduces the operation by.
//
// Its created_at is the header's and its facts are ReservationReleasedFacts, so
// every node that releases the same reservation writes the same row and the
// immutable merge takes it as one.
//
// already=true, with nothing written, when the header epoch already reduces to a
// terminal. A tombstoned cancelled row already holding the release row's key
// is ErrReservationReleaseBlocked: the row cannot be inserted again and the
// reservation stays counted. In the same transaction as the write it
// refuses an operation a live mutation barrier names (ErrReservationInFlight),
// and it never releases a capacity lease or a manifest journal
// (ErrReservationNotReleasable). Whether the
// reservation is safe to release otherwise is the caller's decision
// (ClassifyReservation, under the VM lock on the target host).
func ReleaseReservation(ctx context.Context, c *Client, opID string) (already bool, err error) {
	return releaseReservationWith(ctx, c, opID, OpStepCancelled)
}

// ReleaseBlockedReservation releases a reservation whose release is blocked
// (HostReservationView.ReleaseBlocked: a tombstoned `cancelled` row holds the
// release row's key). It writes a `failed` step at the header's owner epoch
// instead, with ReservationReleasedFacts and the header's created_at, through
// the same ledgered statement and the same guards as ReleaseReservation; every
// reader on every build reduces it as terminal. Only the manual release calls
// it, and only for a resize or create operation: no reader replays a `failed`
// step's facts for those kinds. A tombstoned `failed` row at that key is
// ErrReservationReleaseBlocked in turn.
func ReleaseBlockedReservation(ctx context.Context, c *Client, opID string) (already bool, err error) {
	return releaseReservationWith(ctx, c, opID, OpStepFailed)
}

// IsReservationReleaseStep reports whether a live step at an operation's header
// epoch is a written release of its reservation: any `cancelled` (the release
// row, an expiry or an abort), or the `failed` row ReleaseBlockedReservation
// writes.
func IsReservationReleaseStep(st OperationStepRecord) bool {
	return st.StepName == OpStepCancelled ||
		(st.StepName == OpStepFailed && st.Facts == ReservationReleasedFacts)
}

func releaseReservationWith(ctx context.Context, c *Client, opID, step string) (already bool, err error) {
	op, err := GetOperation(ctx, c, opID)
	if err != nil {
		return false, err
	}
	if op == nil {
		return false, fmt.Errorf("release reservation %s: %w", opID, ErrReservationNotFound)
	}
	if op.ResourceKind == CapacityResourceKind || reservationManifestKinds[OperationKind(op.OperationKind)] ||
		(step != OpStepCancelled && !reservationSweepKinds[OperationKind(op.OperationKind)]) {
		return false, fmt.Errorf("release reservation %s (%s %s): %w",
			opID, op.ResourceKind, op.OperationKind, ErrReservationNotReleasable)
	}
	var inFlight, gone, blocked bool
	guard := func(tx *sql.Tx) (bool, error) {
		var n int
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM operations WHERE id = ? AND deleted_at IS NULL`, opID).Scan(&n); err != nil {
			return false, err
		}
		if n == 0 {
			gone = true
			return false, nil
		}
		for _, q := range []string{
			`SELECT COUNT(*) FROM vms WHERE active_operation_id = ? AND deleted_at IS NULL`,
			`SELECT COUNT(*) FROM containers WHERE active_operation_id = ? AND deleted_at IS NULL`,
		} {
			if err := tx.QueryRowContext(ctx, q, opID).Scan(&n); err != nil {
				return false, err
			}
			if n != 0 {
				inFlight = true
				return false, nil
			}
		}
		// A tombstoned release row at this key would make the insert fail on the
		// primary key on every attempt. It cannot be written again.
		if err := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM operation_steps
			 WHERE operation_id = ? AND owner_epoch = ? AND step_name = ? AND deleted_at IS NOT NULL`,
			opID, op.VMOwnerEpoch, step).Scan(&n); err != nil {
			return false, err
		}
		if n != 0 {
			blocked = true
			return false, nil
		}
		rows, err := tx.QueryContext(ctx,
			`SELECT step_name FROM operation_steps
			 WHERE operation_id = ? AND owner_epoch = ? AND deleted_at IS NULL`, opID, op.VMOwnerEpoch)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var s string
			if err := rows.Scan(&s); err != nil {
				return false, err
			}
			names = append(names, s)
		}
		if err := rows.Err(); err != nil {
			return false, err
		}
		state, _ := ReduceOperationState(OperationKind(op.OperationKind), names)
		return !IsOperationTerminal(state), nil
	}
	applied, err := c.ExecuteBatchGuarded(ctx, guard, []Statement{reservationReleaseStatement(*op, step, c.NowTS())})
	switch {
	case err != nil:
		return false, err
	case inFlight:
		return false, fmt.Errorf("release reservation %s: %w", opID, ErrReservationInFlight)
	case gone:
		return false, fmt.Errorf("release reservation %s: %w", opID, ErrReservationNotFound)
	case blocked:
		return false, fmt.Errorf("release reservation %s: %w: still counted; its release row "+
			"(%s at owner epoch %d) is tombstoned and cannot be re-inserted",
			opID, ErrReservationReleaseBlocked, step, op.VMOwnerEpoch)
	}
	return !applied, nil
}

// reservationReleaseStatement is the release row: the ledgered operation_steps
// insert, with no replication guard. Its created_at is the header's, never the
// writer's clock — see ReleaseReservation.
func reservationReleaseStatement(op OperationRecord, step, now string) Statement {
	return operationStepInsertStatement(op.ID, op.VMOwnerEpoch, step,
		ReservationReleasedFacts, op.CreatedAt, now, nil)
}
