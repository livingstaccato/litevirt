package automation

import (
	"bytes"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type engineError struct{ code string }

func (e engineError) Error() string { return "automation: " + e.code }
func (e engineError) Code() string  { return e.code }
func fail(code string) error        { return engineError{code} }

type assignment = contract.Assignment

func validateCommand(c Command) error { return contract.ValidateSupportedCommand(c) }

// reduce is the single strict dispatcher. Future tasks add real semantic
// handlers here; missing handlers block replay and cannot acquire a new slot.
// It performs no I/O, randomness, clock reads or runtime effects.
func reduce(p corrosion.AutomationProjection, d Decision) (corrosion.AutomationReduction, error) {
	if e := contract.ValidateSupportedDecision(d); e != nil {
		return corrosion.AutomationReduction{}, e
	}
	a, e := contract.DecodeAssignment(d)
	if e != nil {
		return corrosion.AutomationReduction{}, e
	}
	identity, e := CanonicalCommand(d.Command)
	if e != nil {
		return corrosion.AutomationReduction{}, e
	}
	out := corrosion.AutomationReduction{ClusterUID: p.Head.ClusterUID, Scope: corrosion.AutomationScope(d), Identity: identity, SaveRequest: true,
		Receipt: Receipt{RequestID: d.Command.RequestID, OperationID: a.OperationID, ResourceUID: a.ClusterUID, Sequence: d.Sequence, State: "succeeded"}}
	if p.Existing != nil {
		out.SaveRequest = false
		if p.Existing.Receipt.Sequence > d.Sequence {
			return out, fail(CodeUnavailable)
		}
		if !bytes.Equal(identity, p.Existing.Identity) {
			if p.ReplayOriginal {
				return out, fail(CodeUnavailable)
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
		case "initialize_cluster":
			if p.Head.Sequence != 0 || d.Command.ClusterUID != "" {
				return out, fail(CodeValidation)
			}
			out.ClusterUID = a.ClusterUID
		case "read_barrier":
			if p.Head.Sequence == 0 || d.Command.ClusterUID != p.Head.ClusterUID || a.ClusterUID != p.Head.ClusterUID {
				return out, fail(CodeValidation)
			}
		}
	}
	if p.ReplayOriginal && out.Receipt != p.Existing.Receipt {
		return out, fail(CodeUnavailable)
	}
	return out, nil
}
