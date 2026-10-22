package corrosion

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// automationHistoryInput contains one bounded value and already-read causal
// facts. It grants no provenance and has no database or reducer callback.
type automationHistoryInput struct {
	Projection AutomationProjection
	Value      ClaimValue
	Digest     string
	Expected   *contract.Receipt
}

func evaluateAutomationHistory(in automationHistoryInput) (AutomationReduction, AutomationPrefix, error) {
	var zero AutomationReduction
	head := in.Projection.Head
	d, err := automationDecision(in.Value)
	if err != nil {
		return zero, head, err
	}
	if err := validateAutomationPredecessor(head, d); err != nil {
		return zero, head, err
	}
	key, err := AutomationClaimKey(d.Sequence)
	if err != nil {
		return zero, head, err
	}
	if err = validateAutomationValue(key, in.Value); err != nil {
		return zero, head, err
	}
	digest, err := in.Value.Digest()
	if err != nil || digest != in.Digest {
		return zero, head, fmt.Errorf("automation history digest mismatch")
	}
	result, err := contract.Reduce(in.Projection, d)
	if err != nil {
		return result, head, err
	}
	if err = validateAutomationReceipt(result.Receipt, in.Expected); err != nil {
		return result, head, err
	}
	return result, AutomationPrefix{ClusterUID: result.ClusterUID, Sequence: d.Sequence, Digest: digest}, nil
}

func validateAutomationReceipt(actual contract.Receipt, expected *contract.Receipt) error {
	if expected != nil && actual != *expected {
		return fmt.Errorf("automation replay receipt drift")
	}
	return nil
}

// Existing callback APIs can refuse application, but cannot choose different
// successful semantics. Production callbacks delegate to contract.Reduce.
func validateAutomationCallback(actual, callback AutomationReduction) error {
	if !reflect.DeepEqual(actual.ExecutorEffect, callback.ExecutorEffect) || !reflect.DeepEqual(actual.ProgressEffect, callback.ProgressEffect) || !reflect.DeepEqual(actual.TerminalEffect, callback.TerminalEffect) || !reflect.DeepEqual(actual.ArtifactEffects, callback.ArtifactEffects) || !reflect.DeepEqual(actual.TargetEffect, callback.TargetEffect) || !reflect.DeepEqual(actual.TargetReservations, callback.TargetReservations) || !reflect.DeepEqual(actual.EpochEffect, callback.EpochEffect) || !reflect.DeepEqual(actual.RecipientEffects, callback.RecipientEffects) || !reflect.DeepEqual(actual.WrappingEffect, callback.WrappingEffect) || !reflect.DeepEqual(actual.WrappingPrevious, callback.WrappingPrevious) || !reflect.DeepEqual(actual.ResourcePrevious, callback.ResourcePrevious) || !reflect.DeepEqual(actual.ResourceEffect, callback.ResourceEffect) || !reflect.DeepEqual(actual.NameEffect, callback.NameEffect) || !reflect.DeepEqual(actual.BindingEffects, callback.BindingEffects) || !reflect.DeepEqual(actual.AdmissionEffect, callback.AdmissionEffect) || !reflect.DeepEqual(actual.IdentityEffect, callback.IdentityEffect) || !reflect.DeepEqual(actual.OwnerEffect, callback.OwnerEffect) || actual.ClusterUID != callback.ClusterUID || actual.Scope != callback.Scope || !bytes.Equal(actual.Identity, callback.Identity) || actual.Receipt != callback.Receipt || actual.SaveRequest != callback.SaveRequest {
		return fmt.Errorf("automation reducer result drift")
	}
	return nil
}

func validateAutomationRequest(scope, request, operation string, identity []byte, receipt, original contract.Receipt, d contract.Decision) error {
	canonical, err := contract.CanonicalCommand(d.Command)
	if err != nil {
		return err
	}
	if original != receipt || request != d.Command.RequestID || scope != AutomationScope(d) || operation != receipt.OperationID || !bytes.Equal(canonical, identity) {
		return fmt.Errorf("source immutable request drift")
	}
	return nil
}

func validateAutomationTrustedValue(sequence uint64, value ClaimValue, digest, anchorDigest string) error {
	if digest != anchorDigest {
		return fmt.Errorf("automation parent anchor mismatch")
	}
	key, err := AutomationClaimKey(sequence)
	if err != nil {
		return err
	}
	if err = validateAutomationValue(key, value); err != nil {
		return err
	}
	actual, err := value.Digest()
	if err != nil || actual != digest {
		return fmt.Errorf("automation parent digest mismatch")
	}
	return nil
}

func validateAutomationPredecessor(head AutomationPrefix, d contract.Decision) error {
	if d.Sequence != head.Sequence+1 || d.ParentDigest != head.Digest {
		return fmt.Errorf("automation predecessor unavailable")
	}
	return nil
}
