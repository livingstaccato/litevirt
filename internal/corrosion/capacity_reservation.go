package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// ErrProjectAuthorityConflict means a capacity reservation was not written
// because the supplied authority epoch/holder is no longer current.
var ErrProjectAuthorityConflict = errors.New("project authority changed while claiming reservation")

// ClaimCapacityReservation atomically persists an immutable operation header and
// its planned/reserved steps after verifying the current project authority. An
// exact retry is returned unchanged; a different claim for the same operation id
// fails with the operation identity/hash conflict errors.
func ClaimCapacityReservation(ctx context.Context, c *Client, op OperationRecord, facts ReservationFacts) (*OperationRecord, bool, error) {
	return persistCapacityReservation(ctx, c, op, facts, true)
}

// ImportCapacityReservation atomically imports an authority-returned immutable
// header and reserved facts. The peer-authenticated caller verifies the exact
// header before calling this; unlike minting, import does not require the
// authority epoch to have replicated locally first.
func ImportCapacityReservation(ctx context.Context, c *Client, op OperationRecord, facts ReservationFacts) (*OperationRecord, bool, error) {
	return persistCapacityReservation(ctx, c, op, facts, false)
}

func persistCapacityReservation(ctx context.Context, c *Client, op OperationRecord, facts ReservationFacts, verifyAuthority bool) (*OperationRecord, bool, error) {
	op.Project = projectOrDefault(op.Project)
	if op.ID == "" || op.Method == "" || op.ResourceKind == "" ||
		op.ResourceID == "" || op.OperationKind == "" || op.RequestHash == "" {
		return nil, false, fmt.Errorf("capacity reservation immutable operation identity is incomplete")
	}
	factsJSON, err := reservationStepFacts(&facts, op.Project)
	if err != nil {
		return nil, false, err
	}
	if err := validateReservationProject(op.ReservationJSON, op.Project); err != nil {
		return nil, false, err
	}
	reservation, err := DecodeReservation(op.ReservationJSON)
	if err != nil {
		return nil, false, err
	}
	if reservation == (ReservationVector{}) {
		return nil, false, fmt.Errorf("capacity reservation vector is required")
	}

	now, wall := c.NowTS(), nowRFC3339()
	guard := func(tx *sql.Tx) (bool, error) {
		existing, err := operationInTx(ctx, tx, op.ID)
		if err != nil {
			return false, err
		}
		if existing != nil {
			if existing.DeletedAt != "" {
				return false, ErrOperationIdentityConflict
			}
			if err := compareOperationClaim(*existing, op); err != nil {
				return false, err
			}
			if err := compareReservedStepInTx(ctx, tx, op.ID, op.VMOwnerEpoch, factsJSON); err != nil {
				return false, err
			}
			return false, nil
		}
		if !verifyAuthority {
			return true, nil
		}
		var epoch int64
		var holder string
		err = tx.QueryRowContext(ctx,
			`SELECT authority_epoch, holder
			 FROM project_authority_epochs
			 WHERE project = ? AND deleted_at IS NULL
			 ORDER BY authority_epoch DESC LIMIT 1`, op.Project).
			Scan(&epoch, &holder)
		if errors.Is(err, sql.ErrNoRows) {
			return false, ErrProjectAuthorityConflict
		}
		if err != nil {
			return false, err
		}
		if epoch != facts.AuthorityEpoch || holder != facts.AuthorityHost {
			return false, ErrProjectAuthorityConflict
		}
		return true, nil
	}
	stmts := []Statement{
		operationInsertStatement(op, wall, now, nil),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepPlanned, "", wall, now, nil),
		operationStepInsertStatement(op.ID, op.VMOwnerEpoch, OpStepReserved, factsJSON, wall, now, nil),
	}
	applied, err := c.ExecuteBatchGuarded(ctx, guard, stmts)
	if err != nil {
		return nil, false, err
	}
	got, err := GetOperation(ctx, c, op.ID)
	if err != nil {
		return nil, false, err
	}
	if got == nil {
		return nil, false, ErrProjectAuthorityConflict
	}
	if err := compareOperationClaim(*got, op); err != nil {
		return nil, false, err
	}
	return got, applied, nil
}

// ReleaseCapacityReservation appends a terminal failed step. Reservation
// accounting ignores terminal operations, so this is the durable compensation
// for an executor that cannot import or use an authority-minted claim.
func ReleaseCapacityReservation(ctx context.Context, c *Client, operationID string, ownerEpoch int64, detail string) error {
	return AppendOperationStep(ctx, c, OperationStepRecord{
		OperationID: operationID,
		OwnerEpoch:  ownerEpoch,
		StepName:    OpStepFailed,
		Facts:       detail,
	})
}
