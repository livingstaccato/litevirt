package corrosion

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
)

// ValidateAutomationState validates recovery data without live admission checks.
// Historical imports preserve accepted decisions even when activation changed.
func ValidateAutomationState(st ClaimVoterState) error {
	// Structured values must be checked before any outbound representation can
	// erase an empty-but-present legacy Proof. Historical pure Proof domains
	// remain unchanged; Digest already defines these structured union rules.
	if v := st.Value; v != nil && (v.Automation != nil || v.LeaseTerm != nil) {
		if _, err := v.Digest(); err != nil {
			return fmt.Errorf("corrupt structured claim state: %w", err)
		}
	}
	if !st.Key.IsAutomation() {
		if st.Value != nil && st.Value.Automation != nil {
			return fmt.Errorf("automation state at another kind")
		}
		return nil
	}
	bad := func() error { return fmt.Errorf("corrupt automation claim state") }
	if st.Key.Validate() != nil || st.ConfigGeneration < 0 || validateAutomationBallot(st.Promised, true) != nil || validateAutomationBallot(st.Accepted, true) != nil {
		return bad()
	}
	if CompareBallots(st.Promised, st.Accepted) < 0 {
		return bad()
	}
	if st.Accepted.IsZero() {
		if st.Value != nil || st.ValueDigest != "" || st.Accept != nil {
			return bad()
		}
		return nil
	}
	if st.Value == nil || validateAutomationValue(st.Key, *st.Value) != nil {
		return bad()
	}
	d, err := st.Value.Digest()
	if err != nil || d != st.ValueDigest {
		return bad()
	}
	if a := st.Accept; a != nil {
		if a.Key != st.Key || !a.Ballot.Equal(st.Accepted) || a.ValueDigest != d || a.ConfigGeneration != st.ConfigGeneration || len(a.Voter) > contract.MaxStringBytes || len(a.VoterIncarnation) > contract.MaxStringBytes || len(a.CertPEM) > 64<<10 || len(a.Signature) > 256 {
			return bad()
		}
		if err := validateClaimAcceptSignature(*a, a.Key, a.Ballot, a.ConfigGeneration, a.ValueDigest); err != nil {
			return bad()
		}

	}
	return nil
}

// validateRetainedClaimState validates retained full-key promise/acceptance
// facts independently of live chosen-slot admission or incoming authority.
func validateRetainedClaimState(st ClaimVoterState) error {
	if err := st.Key.Validate(); err != nil {
		return err
	}
	if err := ValidateAutomationState(st); err != nil {
		return err
	}
	if validateAutomationBallot(st.Promised, true) != nil || validateAutomationBallot(st.Accepted, true) != nil || CompareBallots(st.Promised, st.Accepted) < 0 || st.ConfigGeneration < 0 {
		return fmt.Errorf("corrupt source claim ballots")
	}
	if st.Accepted.IsZero() {
		if st.Value != nil || st.ValueDigest != "" || st.Accept != nil {
			return fmt.Errorf("source value without acceptance")
		}
		return nil
	}
	if st.Value == nil {
		return fmt.Errorf("source accepted value missing")
	}

	if st.Accept != nil {
		// Legacy ImportClaimsAndAdopt can advance a row's promised generation
		// while preserving its authentic older acceptance. Verify the original
		// signed domain unchanged; automation's stricter generation equality is
		// already enforced by scanClaimRow/ValidateAutomationState.
		if st.Accept.ConfigGeneration < 0 || st.Accept.ConfigGeneration > st.ConfigGeneration {
			return fmt.Errorf("invalid retained accept generation")
		}
		if err := validateRetainedAutomationAccept(*st.Accept, st.Key, st.Accepted, st.Accept.ConfigGeneration, st.ValueDigest); err != nil {
			return err
		}
	}
	digest, err := st.Value.Digest()
	if err != nil || digest != st.ValueDigest {
		return fmt.Errorf("source accepted digest mismatch")
	}
	if st.Key.IsVoterConfig() {
		if st.Value.Config == nil || st.Value.Config.Generation != st.Key.OwnerEpoch+1 {
			return fmt.Errorf("invalid retained membership acceptance")
		}
	} else if refusal, _ := validateGenerationClaimValue(st.Key, st.Value); refusal != "" {
		return fmt.Errorf("invalid source accepted value")
	}
	if st.Key.IsAutomation() {
		d, err := automationDecision(*st.Value)
		if err != nil {
			return err
		}
		if contract.ValidateSupportedDecision(d) != nil {
			return fmt.Errorf("unsupported source accepted schema or secret coverage")
		}
	}

	return nil
}

// A losing accepted value need not equal chosen history at its own slot.
// Its certified predecessor and stream UID still have to match the baseline.
func validateRetainedAutomationParent(d contract.Decision, head AutomationPrefix, parent string, found bool) error {
	if contract.ValidateSupportedDecision(d) != nil {
		return fmt.Errorf("unsupported source accepted schema or secret coverage")
	}
	if d.Sequence > head.Sequence+1 {
		return fmt.Errorf("source accepted predecessor missing")
	}
	if d.Sequence > 1 {
		if !found || parent != d.ParentDigest || d.Command.ClusterUID != head.ClusterUID {
			return fmt.Errorf("source accepted parent mismatch")
		}
	} else if d.ParentDigest != "" {
		return fmt.Errorf("source accepted genesis parent mismatch")
	}
	return nil
}

// This is a corruption check on an ALREADY owned durable anchor/accept, not a
// verifier for incoming authority. It neither accepts a new root nor supplies
// a time/CRL bypass to ClaimVerifier. Publication must authenticate the current
// source separately; only its original local anchored provenance permits reuse.
func validateRetainedAutomationAccept(a ClaimAccept, key ClaimKey, ballot Ballot, generation int64, digest string) error {
	if a.Key != key || !a.Ballot.Equal(ballot) || a.ConfigGeneration != generation || a.ValueDigest != digest || len(a.CertPEM) > 64<<10 || len(a.Signature) > 256 || a.Voter == "" || a.VoterIncarnation == "" {
		return fmt.Errorf("corrupt retained accept binding")
	}
	return validateClaimAcceptSignature(a, key, ballot, generation, digest)
}

// Verify only the bounded certificate/signature and original signed domain.
// Callers retain their distinct binding/legacy shape rules; this grants no
// current trust, membership, time or provenance authority.
func validateClaimAcceptSignature(a ClaimAccept, key ClaimKey, ballot Ballot, generation int64, digest string) error {
	if len(a.CertPEM) > 64<<10 || len(a.Signature) > 256 {
		return fmt.Errorf("corrupt retained accept binding")
	}
	cert, err := parseCertPEM([]byte(a.CertPEM))
	if err != nil || cert.Subject.CommonName != a.Voter {
		return fmt.Errorf("corrupt retained signer")
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || !ecdsa.VerifyASN1(pub, acceptPayload(key, generation, ballot, digest, a.Voter, a.VoterIncarnation), a.Signature) {
		return fmt.Errorf("corrupt retained accept signature")
	}
	return nil
}
