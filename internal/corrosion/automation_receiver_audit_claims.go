package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"math"
)

// Coverage names every retained value and original request identity, including
// losing acceptances. Supported control commands have no secret/equality epoch;
// that conclusion follows from validating every payload, never a custody stub.
func (s receiverAuditStore) claimsAndCoverage(ctx context.Context, head AutomationPrefix) (string, int64, error) {
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-payload-coverage/v1"), []byte(s.evidenceIdentity()))
	var payloads int64
	cover := func(component int, ordinal int64, parts ...[]byte) error {
		if payloads == math.MaxInt64 {
			return errors.New("payload coverage overflow")
		}
		payloads++
		sourceHash(h, automationCutInteger(int64(component)), automationCutInteger(ordinal))
		sourceHash(h, parts...)
		return nil
	}
	for _, component := range []int{3, 4} {
		err := s.ordinals(ctx, component, func(ordinal int64) error {
			sequence, err := s.claimSequence(ctx, component, ordinal)
			if err != nil {
				return err
			}
			parent, found, err := s.claimParent(ctx, sequence)
			if err != nil {
				return err
			}
			return s.claimCoverage(ctx, component, ordinal, head, parent, found, cover)
		})
		if err != nil {
			return "", 0, err
		}
	}
	for _, component := range []int{5, 7} {
		err := s.walk(ctx, component, func(ordinal int64, row Row) error {
			if component == 5 {
				value, _, err := receiverHistoryValue(row)
				if err != nil {
					return err
				}
				d, err := automationDecision(value)
				if err != nil {
					return err
				}
				if err = s.coverageDecision(d); err != nil {
					return err
				}
				return cover(component, ordinal, []byte(row.String("digest")))
			}
			// Bidirectional parity already binds each identity to a supported
			// causal history command; no unsupported identity can enter coverage.
			return cover(component, ordinal, row.Bytes("identity"), []byte(row.String("receipt_json")))
		})
		if err != nil {
			return "", 0, err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), payloads, nil
}

// No custody or equality provider exists in C. Inspect every real supported
// retained command, including losers, before claiming payload coverage.
func (s receiverAuditStore) coverageDecision(d contract.Decision) error {
	if s.localID == "" && s.ownedCutID == "" {
		return nil
	}
	assignment, err := contract.DecodeAssignment(d)
	if err != nil {
		return err
	}
	if assignment.Binding != nil && assignment.Binding.PayloadID != "" {
		return errors.New("required secret/equality coverage unavailable")
	}
	if len(d.Command.Ciphertext) != 0 || len(d.Command.SecretIntentTag) != 0 || d.Command.SecretKeyEpoch != "" {
		return errors.New("required secret/equality coverage unavailable")
	}
	return nil
}

// The sequence is a read hint only. The claim is read and fully validated again
// after the independently authenticated parent value has left its read scope.
func (s receiverAuditStore) claimSequence(ctx context.Context, component int, ordinal int64) (uint64, error) {
	row, err := s.record(ctx, component, ordinal)
	if err != nil {
		return 0, err
	}
	if row.String("target_kind") != ClaimKindAutomation || row.Int64("accepted_round") == 0 {
		return 0, nil
	}
	key := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), Incarnation: row.String("incarnation"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
	st, err := scanClaimRow(key, row)
	if err != nil {
		return 0, err
	}
	if st.Value == nil {
		return 0, nil
	}
	d, err := automationDecision(*st.Value)
	return d.Sequence, err
}
func (s receiverAuditStore) claimParent(ctx context.Context, sequence uint64) (string, bool, error) {
	if sequence <= 1 {
		return "", false, nil
	}
	row, err := s.sequence(ctx, 5, int64(sequence-1))
	if err != nil {
		return "", false, err
	}
	value, _, err := receiverHistoryValue(row)
	if err != nil {
		return "", false, err
	}
	anchor, err := s.sequence(ctx, 6, int64(sequence-1))
	if err != nil {
		return "", false, err
	}
	if err = validateAutomationTrustedValue(sequence-1, value, row.String("digest"), anchor.String("digest")); err != nil {
		return "", false, err
	}
	return row.String("digest"), true, nil
}
func (s receiverAuditStore) claimCoverage(ctx context.Context, component int, ordinal int64, head AutomationPrefix, parent string, found bool, cover func(int, int64, ...[]byte) error) error {
	row, err := s.record(ctx, component, ordinal)
	if err != nil {
		return err
	}
	key := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), Incarnation: row.String("incarnation"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
	st, err := scanClaimRow(key, row)
	if err != nil {
		return err
	}
	if err = validateRetainedClaimState(st); err != nil {
		return err
	}
	if st.ConfigGeneration > s.publication.manifest.Cut.Generation {
		return errors.New("claim generation beyond frozen standing")
	}
	if st.Accept != nil {
		g := st.Accept.ConfigGeneration
		if g == 0 && key.IsVoterConfig() {
			g = 1
		}
		cfg, err := s.membership(ctx, g)
		if err != nil {
			return err
		}
		m, ok := cfg.Member(st.Accept.Voter)
		if !ok || m.Incarnation != st.Accept.VoterIncarnation {
			return errors.New("retained acceptance original member lifetime differs")
		}
	}
	if st.Value == nil {
		return nil
	}
	if key.IsAutomation() {
		d, err := automationDecision(*st.Value)
		if err != nil {
			return err
		}
		if err = s.coverageDecision(d); err != nil {
			return err
		}
		if err = validateRetainedAutomationParent(d, head, parent, found); err != nil {
			return err
		}
	}
	return cover(component, ordinal, []byte(st.ValueDigest))
}
