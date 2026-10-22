package contract

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// Prefix is certified AND transactionally applied progress.
type Prefix struct {
	ClusterUID string
	Sequence   uint64
	Digest     string
}

type Request struct {
	Identity []byte
	Receipt  Receipt
}
type Projection struct {
	Continuity    *ContinuityProjection
	Execution     *ExecutionProjection
	Target        *TargetProjection
	KeyTransition *KeyTransitionProjection
	Binding       *BindingProjection
	Ownership     *OwnershipProjection
	Identity      *IdentityProjection
	Head          Prefix
	Existing      *Request
	Operation     *Receipt
	// ReplayOriginal distinguishes rebuilding the original admission from a
	// later duplicate. Semantic owners must reset/stage their derived tables
	// from certified history before replay, never read retained future state.
	ReplayOriginal bool
}
type Reduction struct {
	ContinuityEffect   *IdentityContinuity
	ExecutorEffect     *ExecutorGrant
	ProgressEffect     *ExecutionProgress
	TerminalEffect     *ExecutionTerminal
	ArtifactEffects    []ArtifactRecord
	TargetEffect       *TargetOperationRecord
	TargetReservations []TargetReservation
	EpochEffect        *KeyEpochRecord
	RecipientEffects   []KeyRecipientRecord
	WrappingEffect     *PayloadWrappingRecord
	WrappingPrevious   *HistoryReference
	ResourcePrevious   *ResourceRecord
	ResourceEffect     *ResourceRecord
	NameEffect         *NameRecord
	BindingEffects     []BindingRecord
	AdmissionEffect    *AdmissionRecord
	OwnerEffect        *OwnerRecord
	IdentityEffect     *IdentityRecord
	ClusterUID         string
	Scope              string
	Identity           []byte
	Receipt            Receipt
	SaveRequest        bool
}

func Scope(d Decision) string {
	if d.Command.Kind == IdentityContinuityCommand {
		b, _ := json.Marshal([]string{d.Command.ClusterUID, d.Command.ProjectUID, "identity-continuity", d.Command.ResourceUID, strconv.FormatUint(d.Command.Generation, 10)})
		return string(b)
	}
	if targetCommand(d.Command.Kind) {
		b, _ := json.Marshal([]string{d.Command.ClusterUID, d.Command.ProjectUID, "ordinary-target", d.Command.PrincipalID})
		return string(b)
	}
	if d.Command.Kind == "initialize_cluster" {
		return "internal:bootstrap"
	}
	if d.Command.Kind == "read_barrier" {
		return "internal:barrier"
	}
	b, _ := json.Marshal([]string{d.Command.ClusterUID, d.Command.ProjectUID, d.Command.OwnerID})
	return string(b)
}

// Reduce is the single strict pure dispatcher for supported durable decisions.
// It performs no I/O, clock reads, randomness or runtime effects.
func Reduce(p Projection, d Decision) (Reduction, error) {
	if e := ValidateSupportedDecision(d); e != nil {
		return Reduction{}, e
	}
	a, e := DecodeAssignment(d)
	if e != nil {
		return Reduction{}, e
	}
	identity, e := CanonicalCommand(d.Command)
	if e != nil {
		return Reduction{}, e
	}
	out := Reduction{ClusterUID: p.Head.ClusterUID, Scope: Scope(d), Identity: identity, SaveRequest: true,
		Receipt: Receipt{RequestID: d.Command.RequestID, OperationID: a.OperationID, ResourceUID: a.ClusterUID, Sequence: d.Sequence, State: "succeeded"}}
	if p.Existing != nil {
		out.SaveRequest = false
		if p.Existing.Receipt.Sequence > d.Sequence {
			return out, codedError(CodeUnavailable)
		}
		if !bytes.Equal(identity, p.Existing.Identity) {
			if p.ReplayOriginal {
				return out, codedError(CodeUnavailable)
			}
			out.Receipt.Code = CodeIdempotencyConflict
			out.Receipt.State = "rejected"
			return out, nil
		}
		if !p.ReplayOriginal {
			out.Receipt = p.Existing.Receipt
			return out, nil
		}
		// Recompute original outcomes using immutable Assignment and rebuilt
		// predecessor projections; compare against the retained receipt below.
	}
	if p.Operation != nil && (!p.ReplayOriginal || p.Operation.Sequence != d.Sequence) {
		out.Receipt.OperationID = ""
		out.Receipt.Code = CodeValidation
		out.Receipt.State = "rejected"
	} else {
		switch d.Command.Kind {
		case IdentityContinuityCommand:
			if err := reduceContinuity(&out, p, d, a); err != nil {
				return out, err
			}
		case "claim_executor", "record_progress", "complete_operation", "retire_artifact":
			if err := reduceExecution(&out, p, d, a); err != nil {
				return out, err
			}
		case LegacyRebuildCommand, OrdinaryCreateCommand:
			if err := reduceTarget(&out, p, d, a); err != nil {
				return out, err
			}
		case "rewrap_payload", "activate_key_epoch":
			if err := reduceKeyTransition(&out, p, d, a); err != nil {
				return out, err
			}
		case "adopt_resource", "transfer_owner":
			if err := reduceOwnership(&out, p, d, a); err != nil {
				return out, err
			}
		case "admit_create":
			if err := reduceCreateBinding(&out, p, d, a); err != nil {
				return out, err
			}
		case "initialize_cluster":
			if p.Head.Sequence != 0 || d.Command.ClusterUID != "" {
				return out, codedError(CodeValidation)
			}
			out.ClusterUID = a.ClusterUID
		case "ensure_owner", "acquire_session", "handoff_session":
			if err := reduceOwner(&out, p, d, a); err != nil {
				return out, err
			}
		case "assign_identity":
			if err := reduceIdentity(&out, p, d, a); err != nil {
				return out, err
			}
		case "read_barrier":
			if p.Head.Sequence == 0 || d.Command.ClusterUID != p.Head.ClusterUID || a.ClusterUID != p.Head.ClusterUID {
				return out, codedError(CodeValidation)
			}
		}
	}
	if p.ReplayOriginal && out.Receipt != p.Existing.Receipt {
		if executionKind(d.Command.Kind) {
			return Reduction{}, codedError(CodeUnavailable)
		}
		return out, codedError(CodeUnavailable)
	}
	return out, nil
}
