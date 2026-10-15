package corrosion

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

const ClaimKindAutomation = "automation"
const RefusalAutomationUnavailable = "automation_unavailable"

// MaxAutomationClaimBytes bounds the complete value_json, including base64
// expansion, below the recovery client's 4 MiB per-message receive limit.
const MaxAutomationClaimBytes = 2 << 20

// AutomationClaimValue contains a complete versioned decision, never retry
// identity bytes. Certificates and ballots are deliberately outside this value.
type AutomationClaimValue struct {
	Envelope []byte `json:"envelope"`
}

// AutomationClaimKey uses the literal stream name "cluster" before and after
// initialization, so concurrent initializers contend for the same first slot.
func AutomationClaimKey(sequence uint64) (ClaimKey, error) {
	if sequence > math.MaxInt64 {
		return ClaimKey{}, fmt.Errorf("invalid automation key")
	}
	k := ClaimKey{TargetKind: ClaimKindAutomation, TargetName: "cluster", OwnerEpoch: int64(sequence)}
	return k, k.Validate()
}
func (k ClaimKey) IsAutomation() bool { return k.TargetKind == ClaimKindAutomation }

func validateAutomationKey(k ClaimKey) error {
	if k.TargetName != "cluster" || k.OwnerEpoch <= 0 || k.Attempt != 0 || k.Incarnation != "" {
		return fmt.Errorf("invalid automation key")
	}
	return nil
}

func automationDecision(v ClaimValue) (contract.Decision, error) {
	if v.Automation == nil || v.Proof != nil || v.Config != nil || v.LUN != nil || v.SourceHost != "" {
		return contract.Decision{}, fmt.Errorf("invalid automation alternative")
	}
	d, err := contract.DecodeDecision(v.Automation.Envelope)
	if err != nil {
		return d, fmt.Errorf("invalid automation envelope")
	}
	b, err := json.Marshal(v)
	if err != nil || len(b) > MaxAutomationClaimBytes {
		return d, fmt.Errorf("automation value exceeds storage limit")
	}
	return d, nil
}

func validateAutomationValue(k ClaimKey, v ClaimValue) error {
	if err := k.Validate(); err != nil {
		return err
	}
	d, err := automationDecision(v)
	if err != nil {
		return err
	}
	if !k.IsAutomation() || d.Sequence != uint64(k.OwnerEpoch) {
		return fmt.Errorf("automation value does not match key")
	}
	return nil
}

func validateAutomationBallot(b Ballot, zeroOK bool) error {
	if zeroOK && b.IsZero() {
		return nil
	}
	if b.Round == 0 || b.Round > math.MaxInt64 || b.Coordinator == "" || len(b.Coordinator) > contract.MaxStringBytes || !utf8.ValidString(b.Coordinator) || len(b.Nonce) > 256 {
		return fmt.Errorf("invalid automation ballot")
	}
	return nil
}

func (c *Client) admitAutomationTx(ctx context.Context, tx *LocalTx, key ClaimKey, b Ballot, gen int64, v *ClaimValue) (string, error) {
	if !key.IsAutomation() {
		return "", nil
	}
	if err := key.Validate(); err != nil {
		return RefusalInvalidValue, nil
	}
	if err := validateAutomationBallot(b, false); err != nil {
		return RefusalInvalidValue, nil
	}
	if v != nil {
		d, err := automationDecision(*v)
		if err != nil || contract.ValidateSupportedDecision(d) != nil {
			return RefusalInvalidValue, nil
		}
	}

	cfg, err := automationAuthorityTx(ctx, tx, c.hostName, gen)
	if errors.Is(err, errAutomationAuthority) || cfg == nil && err == nil {
		return RefusalAutomationUnavailable, nil
	}
	if err != nil {
		return "", err
	}
	head, err := automationHeadTx(ctx, tx)
	if err != nil {
		return "", err
	}
	sequence := uint64(key.OwnerEpoch)
	if sequence > head.Sequence+1 {
		return RefusalAutomationUnavailable, nil
	}
	if sequence == head.Sequence+1 && head.Sequence > 0 {
		digest, found, err := automationTrustedDigestTx(ctx, tx, head.Sequence)
		if err != nil {
			return "", err
		}
		if !found || digest != head.Digest {
			return RefusalAutomationUnavailable, nil
		}
	}

	if sequence <= head.Sequence {
		digest, found, err := automationTrustedDigestTx(ctx, tx, sequence)
		if err != nil {
			return "", err
		}
		if !found {
			return RefusalAutomationUnavailable, nil
		}
		if v != nil {
			actual, err := v.Digest()
			if err != nil || actual != digest {
				return RefusalInvalidValue, nil
			}
		}
	} else if v != nil {
		d, err := automationDecision(*v)
		if err != nil || d.ParentDigest != head.Digest {
			return RefusalInvalidValue, nil
		}
		if sequence == 1 {
			rows, err := tx.Query(ctx, `SELECT bootstrap_principal,bootstrap_request FROM local_automation_authority WHERE id=1`)
			if err != nil {
				return "", err
			}
			if len(rows) != 1 || d.Command.PrincipalID != rows[0].String("bootstrap_principal") || d.Command.RequestID != rows[0].String("bootstrap_request") {
				return RefusalAutomationUnavailable, nil
			}
		} else if d.Command.ClusterUID != head.ClusterUID {
			return RefusalInvalidValue, nil
		}
	}
	if err := requireAutomationFull(ctx, tx); err != nil {
		return "", err
	}
	return "", nil
}

func requireAutomationFull(ctx context.Context, tx *LocalTx) error {
	rows, err := tx.Query(ctx, "PRAGMA synchronous")
	if err != nil {
		return err
	}
	if len(rows) != 1 || len(rows[0].Values) != 1 || rows[0].Values[0] != int64(SynchronousFull) && rows[0].Values[0] != int64(3) {
		return fmt.Errorf("automation requires synchronous FULL on its transaction")
	}
	return nil
}

// ValidateAutomationState validates recovery data without live admission checks.
// Historical imports preserve accepted decisions even when activation changed.
func ValidateAutomationState(st ClaimVoterState) error {
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
		cert, err := parseCertPEM([]byte(a.CertPEM))
		if err != nil || cert.Subject.CommonName != a.Voter {
			return bad()
		}
		pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !ecdsa.VerifyASN1(pub, acceptPayload(a.Key, a.ConfigGeneration, a.Ballot, a.ValueDigest, a.Voter, a.VoterIncarnation), a.Signature) {
			return bad()
		}
	}
	return nil
}

func (c *Client) claimCommitSeams(key ClaimKey) *localCommitSeams {
	if key.IsAutomation() {
		return c.automationSeams
	}
	return nil
}

func decodeClaimValue(key ClaimKey, s string, v *ClaimValue) error {
	if !key.IsAutomation() {
		return json.Unmarshal([]byte(s), v)
	}
	if len(s) > MaxAutomationClaimBytes {
		return fmt.Errorf("corrupt automation claim value")
	}
	if err := json.Unmarshal([]byte(s), v); err != nil {
		return fmt.Errorf("corrupt automation claim value")
	}
	b, err := json.Marshal(v)
	if err != nil || string(b) != s {
		return fmt.Errorf("noncanonical automation claim value")
	}
	return nil
}
