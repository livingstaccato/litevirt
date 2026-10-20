package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/hlc"
)

// This is an ordinary storage claim, not permission to execute a rebuild.
const vmSnapshotClaimSQL = `UPDATE vms SET spec = ?, spec_generation = ?, active_operation_id = ?, updated_at = ?
	WHERE name = ? AND created_at = ? AND host_name = ? AND vm_owner_epoch = ?
	AND spec_generation = ? AND active_operation_id = '' AND deleted_at IS NULL`

type snapshotClaimSnapshot struct {
	CreatedAt      string `json:"created_at"`
	HostName       string `json:"host_name"`
	OwnerEpoch     int64  `json:"owner_epoch"`
	SpecGeneration int64  `json:"spec_generation"`
	IdentityHash   string `json:"identity_hash"`
	FirewallID     string `json:"firewall_id"`
}

func claimSnapshot(s VMDeleteSnapshot) snapshotClaimSnapshot {
	return snapshotClaimSnapshot{s.CreatedAt, s.HostName, s.OwnerEpoch, s.SpecGeneration, s.IdentityHash, s.FirewallID}
}

type snapshotClaimFacts struct {
	Version            int                   `json:"version"`
	OperationClaimHash string                `json:"operation_claim_hash"`
	Before             snapshotClaimSnapshot `json:"before"`
	DesiredInputSHA256 string                `json:"desired_input_sha256"`
	After              snapshotClaimSnapshot `json:"after"`
}

func snapshotClaimDigest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func snapshotClaimHashValid(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == sha256.Size && hex.EncodeToString(b) == s
}

func decodeSnapshotClaimFacts(raw string) (snapshotClaimFacts, error) {
	var f snapshotClaimFacts
	if len(raw) > 16384 || json.Unmarshal([]byte(raw), &f) != nil {
		return f, ErrOperationStepConflict
	}
	// Exact canonical bytes also reject omitted, duplicate, unknown, case-folded
	// and null fields. Never upgrade historical empty planned facts.
	canonical, err := json.Marshal(f)
	if err != nil || string(canonical) != raw || f.Version != 1 ||
		!snapshotClaimHashValid(f.OperationClaimHash) || !snapshotClaimHashValid(f.DesiredInputSHA256) {
		return f, ErrOperationStepConflict
	}
	b, a := f.Before, f.After
	if b.CreatedAt == "" || b.HostName == "" || b.OwnerEpoch < 0 ||
		b.SpecGeneration < 0 || b.SpecGeneration == math.MaxInt64 ||
		!snapshotClaimHashValid(b.IdentityHash) || !snapshotClaimHashValid(a.IdentityHash) ||
		a.CreatedAt != b.CreatedAt || a.HostName != b.HostName || a.OwnerEpoch != b.OwnerEpoch ||
		a.SpecGeneration != b.SpecGeneration+1 || a.FirewallID != b.FirewallID {
		return f, ErrOperationStepConflict
	}
	return f, nil
}

func snapshotClaimGuard(op OperationRecord, f snapshotClaimFacts) *MutationGuard {
	return &MutationGuard{
		Protocol: capabilities.VMSnapshotClaimV1, ResourceKind: "vm", ResourceID: op.ResourceID,
		HostName: f.Before.HostName, OperationID: op.ID, OwnerEpoch: f.Before.OwnerEpoch,
		SpecGeneration: f.Before.SpecGeneration, CheckSpecGeneration: true,
		IdentityHash: f.Before.IdentityHash, Incarnation: f.Before.CreatedAt,
		OperationClaimHash: f.OperationClaimHash,
	}
}

func snapshotClaimStatements(op OperationRecord, spec, raw string, f snapshotClaimFacts) []Statement {
	g := snapshotClaimGuard(op, f)
	return []Statement{
		{SQL: vmSnapshotClaimSQL, Params: []interface{}{spec, f.After.SpecGeneration, op.ID, op.UpdatedAt,
			op.ResourceID, f.Before.CreatedAt, f.Before.HostName, f.Before.OwnerEpoch, f.Before.SpecGeneration}, Guard: g},
		operationInsertStatement(op, op.CreatedAt, op.UpdatedAt, g),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepPlanned, raw, op.CreatedAt, op.UpdatedAt, g),
	}
}

type snapshotClaimEntry struct {
	op        OperationRecord
	facts     snapshotClaimFacts
	raw, spec string
}

// Any occurrence selects the whole-entry validator, including a missing or
// rebound guard on the dedicated UPDATE. It must never fall into generic LWW.
func isSnapshotClaimEntry(stmts []Statement) bool {
	for _, s := range stmts {
		if s.Guard != nil && s.Guard.Protocol == capabilities.VMSnapshotClaimV1 {
			return true
		}
		if sh, _, err := parseResolved(s.SQL); err == nil && stmtFingerprint(sh) == mustStatementFingerprint(vmSnapshotClaimSQL) {
			return true
		}
	}
	return false
}

func validateSnapshotClaimEntry(stmts []Statement) (snapshotClaimEntry, error) {
	var e snapshotClaimEntry
	if len(stmts) != 3 {
		return e, invalidf("snapshot claim requires three ordered roles")
	}
	sh, _, err := parseResolved(stmts[1].SQL)
	if err != nil {
		return e, err
	}
	var ok bool
	e.op, ok = guardedOperationClaim(stmts[1], sh)
	if !ok {
		return e, ErrOperationIdentityConflict
	}
	field := func(name string) (string, bool) {
		v, found := guardedInsertField(sh, stmts[1], name)
		s, typed := v.(string)
		return s, found && typed
	}
	if e.op.CreatedAt, ok = field("created_at"); !ok {
		return e, ErrOperationIdentityConflict
	}
	if e.op.UpdatedAt, ok = field("updated_at"); !ok {
		return e, ErrOperationIdentityConflict
	}
	if _, err := time.Parse(time.RFC3339Nano, e.op.CreatedAt); err != nil {
		return e, ErrOperationIdentityConflict
	}
	if _, err := time.Parse(time.RFC3339Nano, e.op.UpdatedAt); err != nil {
		if _, ok := hlc.Parse(e.op.UpdatedAt); !ok {
			return e, ErrOperationIdentityConflict
		}
	}
	if e.op.UpdatedAt == "" || e.op.ID == "" || e.op.ResourceID == "" || e.op.ResourceKind != "vm" ||
		!IsLegalStep(OperationKind(e.op.OperationKind), OpStepPlanned) {
		return e, ErrOperationIdentityConflict
	}
	if err := validateReservationProject(e.op.ReservationJSON, e.op.Project); err != nil {
		return e, err
	}
	stepShape, _, err := parseResolved(stmts[2].SQL)
	if err != nil {
		return e, err
	}
	v, found := guardedInsertField(stepShape, stmts[2], "facts")
	e.raw, ok = v.(string)
	if !found || !ok {
		return e, ErrOperationStepConflict
	}
	e.facts, err = decodeSnapshotClaimFacts(e.raw)
	if err != nil {
		return e, err
	}
	reservation, err := DecodeReservation(e.op.ReservationJSON)
	if err != nil {
		return e, err
	}
	if reservation.TargetHost != "" && reservation.TargetHost != e.facts.Before.HostName {
		return e, ErrOperationIdentityConflict
	}
	if len(stmts[0].Params) != 9 {
		return e, invalidf("snapshot claim update parameters")
	}
	e.spec, ok = stmts[0].Params[0].(string)
	if !ok || !json.Valid([]byte(e.spec)) || e.facts.OperationClaimHash != operationClaimHash(e.op) ||
		e.op.VMOwnerEpoch != e.facts.Before.OwnerEpoch {
		return e, ErrOperationIdentityConflict
	}
	want := snapshotClaimStatements(e.op, e.spec, e.raw, e.facts)
	for i, s := range stmts {
		shape, _, err := parseResolved(s.SQL)
		if err != nil {
			return e, err
		}
		if s.Guard == nil || *s.Guard != *want[i].Guard ||
			stmtFingerprint(shape) != mustStatementFingerprint(want[i].SQL) {
			return e, invalidf("snapshot claim role %d shape or guard", i)
		}
		// JSON is also the transport representation; this compares numeric
		// parameters identically as native integers and transport json.Number.
		got, err := json.Marshal(s.Params)
		if err != nil {
			return e, err
		}
		expected, err := json.Marshal(want[i].Params)
		if err != nil || string(got) != string(expected) {
			return e, invalidf("snapshot claim role %d binding", i)
		}
	}
	return e, nil
}

func snapshotClaimVM(ctx context.Context, tx *sql.Tx, name string) (*VMRecord, bool, error) {
	var v VMRecord
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT name, COALESCE(stack_name,''), host_name, spec,
		COALESCE(project,'_default'), COALESCE(is_template,0), created_at, updated_at,
		vm_owner_epoch, spec_generation, active_operation_id, deleted_at FROM vms WHERE name = ?`, name).
		Scan(&v.Name, &v.StackName, &v.HostName, &v.Spec, &v.Project, &v.IsTemplate,
			&v.CreatedAt, &v.UpdatedAt, &v.OwnerEpoch, &v.SpecGeneration, &v.ActiveOperationID, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	return &v, deleted.Valid, err
}

func snapshotClaimStep(ctx context.Context, tx *sql.Tx, id string, epoch int64) (*OperationStepRecord, error) {
	var s OperationStepRecord
	var deleted sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at
		FROM operation_steps WHERE operation_id = ? AND owner_epoch = ? AND step_name = ?`, id, epoch, OpStepPlanned).
		Scan(&s.OperationID, &s.OwnerEpoch, &s.StepName, &s.Facts, &s.CreatedAt, &s.UpdatedAt, &deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if deleted.Valid {
		s.DeletedAt = deleted.String
		if s.DeletedAt == "" {
			s.DeletedAt = "tombstone"
		}
	}
	return &s, err
}

type snapshotClaimOutcome string

const (
	snapshotClaimApplied     snapshotClaimOutcome = "snapshot_claim_applied"
	snapshotClaimDuplicate   snapshotClaimOutcome = "snapshot_claim_duplicate"
	snapshotClaimTombstone   snapshotClaimOutcome = "snapshot_claim_superseded_tombstone"
	snapshotClaimIncarnation snapshotClaimOutcome = "snapshot_claim_superseded_incarnation"
)

func snapshotClaimUnavailable() error {
	return fmt.Errorf("snapshot claim unavailable: exact retained state required")
}

// The generic historical decoder uses float64. This protocol binds int64
// counters exactly, including values beyond float64's exact integer range.
func decodeSnapshotClaimStatements(raw string) ([]Statement, error) {
	var stmts []Statement
	d := json.NewDecoder(strings.NewReader(raw))
	d.UseNumber()
	d.DisallowUnknownFields()
	err := d.Decode(&stmts)
	return stmts, err
}

func (c *Client) snapshotClaimKnownConflict(e snapshotClaimEntry) bool {
	// Acknowledgement does not remove a conflict. This deliberately makes no
	// claim about remote, forgotten or not-yet-delivered conflicts.
	c.tieMu.Lock()
	defer c.tieMu.Unlock()
	for _, key := range []string{
		unresolvedKey("vms", pkKey([]interface{}{e.op.ResourceID})),
		unresolvedKey("operations", pkKey([]interface{}{e.op.ID})),
		unresolvedKey("operation_steps", pkKey([]interface{}{e.op.ID, e.op.VMOwnerEpoch, OpStepPlanned})),
	} {
		if _, ok := c.unresolvedTies[key]; ok {
			return true
		}
		if len(c.acknowledgedTies[key]) > 0 || len(c.acknowledgedVersions[key]) > 0 {
			return true
		}
	}
	return false
}

func (c *Client) snapshotClaimTerminal(ctx context.Context, tx *sql.Tx, op OperationRecord) (bool, error) {
	rows, err := tx.QueryContext(ctx, `SELECT step_name, deleted_at FROM operation_steps WHERE operation_id = ? AND owner_epoch = ?`, op.ID, op.VMOwnerEpoch)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var name string
		var deleted sql.NullString
		if err := rows.Scan(&name, &deleted); err != nil {
			return false, err
		}
		if deleted.Valid || !IsLegalStep(OperationKind(op.OperationKind), name) {
			return false, nil
		}
		key := unresolvedKey("operation_steps", pkKey([]interface{}{op.ID, op.VMOwnerEpoch, name}))
		c.tieMu.Lock()
		_, tracked := c.unresolvedTies[key]
		conflict := tracked || len(c.acknowledgedTies[key]) > 0 || len(c.acknowledgedVersions[key]) > 0
		c.tieMu.Unlock()
		if conflict {
			return false, ErrOperationStepConflict
		}
		names = append(names, name)
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	state, faulted := ReduceOperationState(OperationKind(op.OperationKind), names)
	return !faulted && IsOperationTerminal(state), nil
}

func (c *Client) snapshotClaimDecision(ctx context.Context, tx *sql.Tx, e snapshotClaimEntry) (snapshotClaimOutcome, error) {
	if c.snapshotClaimKnownConflict(e) {
		return "", ErrOperationStepConflict
	}
	op, err := operationInTx(ctx, tx, e.op.ID)
	if err != nil {
		return "", err
	}
	step, err := snapshotClaimStep(ctx, tx, e.op.ID, e.op.VMOwnerEpoch)
	if err != nil {
		return "", err
	}
	if op != nil {
		if err := compareOperationClaim(*op, e.op); err != nil {
			return "", err
		}
		var tombstoned bool
		if err := tx.QueryRowContext(ctx, `SELECT deleted_at IS NOT NULL FROM operations WHERE id = ?`, op.ID).Scan(&tombstoned); err != nil {
			return "", err
		}
		if tombstoned || op.CreatedAt != e.op.CreatedAt || op.UpdatedAt != e.op.UpdatedAt {
			return "", ErrOperationIdentityConflict
		}
	}
	if step != nil && (step.DeletedAt != "" || step.Facts != e.raw ||
		step.CreatedAt != e.op.CreatedAt || step.UpdatedAt != e.op.UpdatedAt) {
		return "", ErrOperationStepConflict
	}
	if (op == nil) != (step == nil) {
		return "", snapshotClaimUnavailable()
	}
	v, deleted, err := snapshotClaimVM(ctx, tx, e.op.ResourceID)
	if err != nil {
		return "", err
	}
	if v == nil {
		return "", snapshotClaimUnavailable()
	}
	if deleted && v.CreatedAt == e.facts.Before.CreatedAt {
		return snapshotClaimTombstone, nil
	}
	if v.CreatedAt != e.facts.Before.CreatedAt {
		if op != nil {
			terminal, err := c.snapshotClaimTerminal(ctx, tx, *op)
			if err != nil {
				return "", err
			}
			if terminal {
				return snapshotClaimIncarnation, nil
			}
		}
		return "", snapshotClaimUnavailable()
	}
	if deleted {
		return "", snapshotClaimUnavailable()
	}
	if op != nil {
		if claimSnapshot(SnapshotForDelete(*v)) == e.facts.After && v.ActiveOperationID == e.op.ID &&
			v.Spec == e.spec && v.UpdatedAt == e.op.UpdatedAt {
			return snapshotClaimDuplicate, nil
		}
		return "", snapshotClaimUnavailable()
	}
	if v.ActiveOperationID != "" || claimSnapshot(SnapshotForDelete(*v)) != e.facts.Before ||
		projectOrDefault(v.Project) != projectOrDefault(e.op.Project) {
		return "", snapshotClaimUnavailable()
	}
	reservation, err := DecodeReservation(e.op.ReservationJSON)
	if err != nil {
		return "", err
	}
	if reservation.TargetHost != "" && reservation.TargetHost != v.HostName {
		return "", ErrOperationIdentityConflict
	}
	v.Spec, v.SpecGeneration, v.ActiveOperationID = e.spec, e.facts.After.SpecGeneration, e.op.ID
	if claimSnapshot(SnapshotForDelete(*v)) != e.facts.After {
		return "", ErrOperationStepConflict
	}
	return snapshotClaimApplied, nil
}

func (c *Client) applySnapshotClaim(ctx context.Context, tx *sql.Tx, stmts []Statement) (snapshotClaimOutcome, error) {
	e, err := validateSnapshotClaimEntry(stmts)
	if err != nil {
		return "", err
	}
	if !c.capabilityActive(capabilities.VMSnapshotClaimV1) {
		return "", snapshotClaimUnavailable()
	}
	for i, s := range stmts {
		shape, _, err := parseResolved(s.SQL)
		if err != nil {
			return "", err
		}
		ledger, ok := LedgerLookup(stmtFingerprint(shape))
		if !ok {
			return "", invalidf("unregistered snapshot claim role %d", i)
		}
		if i == 0 && (ledger.Disposition != DispReject ||
			ledger.RequiresCapability != capabilities.VMSnapshotClaimV1 || ledger.DispositionAfter != DispSnapshotClaim) {
			return "", invalidf("snapshot claim ledger disposition")
		}
	}
	outcome, err := c.snapshotClaimDecision(ctx, tx, e)
	if err != nil || outcome != snapshotClaimApplied {
		return outcome, err
	}
	for _, s := range stmts {
		// Execute validated integer values, not json.Number values
		// (database/sql does not promise to accept that transport-only type).
		params := append([]interface{}(nil), s.Params...)
		for i, p := range params {
			if n, ok := p.(json.Number); ok {
				value, err := n.Int64()
				if err != nil {
					return "", err
				}
				params[i] = value
			}
		}
		res, err := tx.ExecContext(ctx, s.SQL, params...)
		if err != nil {
			return "", err
		}
		n, err := res.RowsAffected()
		if err != nil || n != 1 {
			return "", fmt.Errorf("snapshot claim affected rows: %d: %v", n, err)
		}
	}
	after, err := c.snapshotClaimDecision(ctx, tx, e)
	if err != nil {
		return "", err
	}
	if after != snapshotClaimDuplicate {
		return "", ErrOperationStepConflict
	}
	return outcome, nil
}

// BeginVMOperationAtSnapshot binds the original snapshot and exact caller input
// bytes. Retrying reads retained provenance; it never normalizes or stamps again.
func (c *Client) BeginVMOperationAtSnapshot(ctx context.Context, op OperationRecord, desiredSpec string, expected VMDeleteSnapshot) (bool, error) {
	if c.vmSnapshotClaimEmit == nil || !c.vmSnapshotClaimEmit(ctx) {
		return false, snapshotClaimUnavailable()
	}
	if op.VMOwnerEpoch != 0 && op.VMOwnerEpoch != expected.OwnerEpoch {
		return false, ErrOperationIdentityConflict
	}
	op.VMOwnerEpoch = expected.OwnerEpoch
	op.Project = projectOrDefault(op.Project)
	if err := validateReservationProject(op.ReservationJSON, op.Project); err != nil {
		return false, err
	}
	return c.executeSnapshotClaim(ctx, func(tx *sql.Tx) ([]Statement, error) {
		retained, err := operationInTx(ctx, tx, op.ID)
		if err != nil {
			return nil, err
		}
		step, err := snapshotClaimStep(ctx, tx, op.ID, op.VMOwnerEpoch)
		if err != nil {
			return nil, err
		}
		v, deleted, err := snapshotClaimVM(ctx, tx, op.ResourceID)
		if err != nil {
			return nil, err
		}
		if v == nil || deleted {
			return nil, snapshotClaimUnavailable()
		}
		if retained != nil || step != nil {
			if retained == nil || step == nil {
				return nil, snapshotClaimUnavailable()
			}
			if err := compareOperationClaim(*retained, op); err != nil {
				return nil, err
			}
			f, err := decodeSnapshotClaimFacts(step.Facts)
			if err != nil {
				return nil, err
			}
			if f.Before != claimSnapshot(expected) || f.DesiredInputSHA256 != snapshotClaimDigest(desiredSpec) {
				return nil, ErrOperationStepConflict
			}
			op.CreatedAt, op.UpdatedAt = retained.CreatedAt, retained.UpdatedAt
			return snapshotClaimStatements(op, v.Spec, step.Facts, f), nil
		}
		if claimSnapshot(expected) != claimSnapshot(SnapshotForDelete(*v)) || v.ActiveOperationID != "" ||
			expected.SpecGeneration < 0 || expected.SpecGeneration == math.MaxInt64 || expected.OwnerEpoch < 0 {
			return nil, snapshotClaimUnavailable()
		}
		spec, err := keepFirewallID(TagMemberVM, desiredSpec, expected.FirewallID)
		if err != nil {
			return nil, err
		}
		op.CreatedAt, op.UpdatedAt = nowRFC3339(), c.NowTS()
		if c.SpecConflictOn() {
			spec = stampSpec(spec, v.Spec, op.UpdatedAt)
		}
		v.Spec, v.SpecGeneration, v.ActiveOperationID = spec, expected.SpecGeneration+1, op.ID
		f := snapshotClaimFacts{1, operationClaimHash(op), claimSnapshot(expected),
			snapshotClaimDigest(desiredSpec), claimSnapshot(SnapshotForDelete(*v))}
		raw, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		return snapshotClaimStatements(op, spec, string(raw), f), nil
	})
}
