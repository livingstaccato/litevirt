package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
)

// Coverage names every retained value and original request identity, including
// losing acceptances. Supported control commands have no secret/equality epoch;
// that conclusion follows from validating every payload, never a custody stub.
func (s receiverAuditStore) claimsAndCoverage(ctx context.Context, head AutomationPrefix) (string, int64, error) {
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-payload-coverage/v1"), []byte(s.id))
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
		err := s.walk(ctx, component, func(ordinal int64, row Row) error {
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
				var parent string
				found := false
				if d.Sequence > 1 {
					row, err := s.sequence(ctx, 5, int64(d.Sequence-1))
					if err != nil {
						return err
					}
					value, _, err := receiverHistoryValue(row)
					if err != nil {
						return err
					}
					anchor, err := s.sequence(ctx, 6, int64(d.Sequence-1))
					if err != nil {
						return err
					}
					if err = validateAutomationTrustedValue(d.Sequence-1, value, row.String("digest"), anchor.String("digest")); err != nil {
						return err
					}
					parent = row.String("digest")
					found = true
				}
				if err = validateRetainedAutomationParent(d, head, parent, found); err != nil {
					return err
				}
			}
			return cover(component, ordinal, []byte(st.ValueDigest))
		})
		if err != nil {
			return "", 0, err
		}
	}
	for _, component := range []int{5, 7} {
		err := s.walk(ctx, component, func(ordinal int64, row Row) error {
			if component == 5 {
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
