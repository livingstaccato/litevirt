package corrosion

// Frozen 11b incoming-value oracle. Its decoders never call the candidate
// acceptance summary. Contract codec and alternative types remain protected.
import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
)

func invocation11bDecision(v ClaimValue) (contract.Decision, error) {
	if v.Automation == nil || v.Proof != nil || v.Config != nil || v.LUN != nil || v.LeaseTerm != nil || v.SourceHost != "" {
		return contract.Decision{}, fmt.Errorf("invalid automation alternative")
	}
	d, err := contract.DecodeDecision(v.Automation.Envelope)
	if err != nil {
		return d, fmt.Errorf("invalid automation envelope")
	}
	if invocation11bOuterSize(v.Automation.Envelope) > uint64(MaxAutomationClaimBytes) {
		return d, fmt.Errorf("automation value exceeds storage limit")
	}
	return d, nil
}

// invocation11bOuterSize is exact only for the shape protected by the alternative
// guard in invocation11bDecision and TestAutomationOuterSizeShape. A future field,
// tag or marshaler change requires re-proving this contract or restoring Marshal.
// Convert before arithmetic: even MaxInt64 slice length fits the uint64 result.

func invocation11bOuterSize(envelope []byte) uint64 {
	if envelope == nil {
		return uint64(len(`{"automation":{"envelope":null}}`))
	}
	return uint64(len(`{"automation":{"envelope":""}}`)) + ((uint64(len(envelope))+2)/3)*4
}

func invocation11bKeyClass(v ClaimValue) bool {
	d, err := invocation11bDecision(v)
	if err != nil {
		return false
	}
	a, err := contract.DecodeAssignment(d)
	return err == nil && a.Version == contract.CustodyAssignmentVersion && (d.Command.Kind == contract.CustodyImportCommand || d.Command.Kind == "activate_key_epoch")
}

// ClaimAcceptKeyEvidence consumes the actual stored acceptance obtained from an
// authenticated source. It is a key-class proof, never owner authorization.

func invocation11bDigest(v ClaimValue) (string, error) {
	// Exact automation branch of 11b ClaimValue.Digest. Non-automation alternatives
	// are compared separately through the protected legacy entry, never optimized.
	if _, err := invocation11bDecision(v); err != nil {
		return "", err
	}
	h := sha256.New()
	claimField(h, "litevirt-automation-decision-v1")
	claimField(h, string(v.Automation.Envelope))
	return hex.EncodeToString(h.Sum(nil)), nil
}
