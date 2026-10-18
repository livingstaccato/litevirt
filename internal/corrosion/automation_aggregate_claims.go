package corrosion

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

type aggregateCopyRef struct {
	Kind, ID  string
	Component int
	Ordinal   int64
}
type aggregateEvidenceStore struct {
	kind, id string
	store    receiverAuditStore
}

// These results contain only bounded logical keys, ballots and freshly
// computed full-byte commitments. No Row, ClaimValue, certificate or payload
// escapes the decoding scope, so the next original can be read independently.
type aggregateClaimSummary struct {
	Key                ClaimKey
	Promised, Accepted Ballot
	fingerprint        string
	sequence           uint64
	needsCoverage      bool
}
type aggregateHistorySummary struct {
	fingerprint, receipt, digest string
	ballot                       Ballot
	needsCoverage                bool
}

func aggregateFullValue(value *ClaimValue) (string, bool, uint64, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", false, 0, err
	}
	fingerprint := sourceDigest([]byte("litevirt/aggregate-full-value/v1"), raw)
	if value == nil || value.Automation == nil {
		return fingerprint, false, 0, nil
	}
	decision, err := automationDecision(*value)
	if err != nil {
		return "", false, 0, err
	}
	assignment, err := contract.DecodeAssignment(decision)
	if err != nil {
		return "", false, 0, err
	}
	c := decision.Command
	required := len(c.Ciphertext) > 0 || len(c.SecretIntentTag) > 0 || c.SecretKeyEpoch != "" || (assignment.Binding != nil && assignment.Binding.PayloadID != "")
	return fingerprint, required, decision.Sequence, nil
}
func aggregateClaimAt(ctx context.Context, s receiverAuditStore, component int, ordinal int64) (aggregateClaimSummary, error) {
	var out aggregateClaimSummary
	row, err := s.record(ctx, component, ordinal)
	if err != nil {
		return out, err
	}
	key := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), Incarnation: row.String("incarnation"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
	st, err := scanClaimRow(key, row)
	if err != nil {
		return out, err
	}
	if err = validateRetainedClaimState(st); err != nil {
		return out, err
	}
	out.Key, out.Promised, out.Accepted = key, st.Promised, st.Accepted
	out.fingerprint, out.needsCoverage, out.sequence, err = aggregateFullValue(st.Value)
	return out, err
}
func aggregateHistoryAt(ctx context.Context, s receiverAuditStore, sequence int64) (aggregateHistorySummary, error) {
	var out aggregateHistorySummary
	row, err := s.sequence(ctx, 5, sequence)
	if err != nil {
		return out, err
	}
	value, _, err := receiverHistoryValue(row)
	if err != nil {
		return out, err
	}
	out.fingerprint, out.needsCoverage, _, err = aggregateFullValue(&value)
	if err != nil {
		return out, err
	}
	certificate, err := sourceCertificate(row.String("certificate"))
	if err != nil {
		return out, err
	}
	out.ballot = certificate.Ballot
	out.receipt = sourceDigest([]byte("litevirt/aggregate-original-receipt/v1"), []byte(row.String("receipt_json")))
	out.digest = row.String("digest")
	return out, nil
}

func aggregateReadCopy(ctx context.Context, stores []aggregateEvidenceStore, raw []byte) (aggregateClaimSummary, error) {
	var ref aggregateCopyRef
	if len(raw) == 0 || len(raw) > 1024 {
		return aggregateClaimSummary{}, errors.New("aggregate copy reference exceeds bound")
	}
	if err := receiverAuditJSON(raw, &ref); err != nil {
		return aggregateClaimSummary{}, err
	}
	if (ref.Component != 3 && ref.Component != 4) || ref.Ordinal <= 0 {
		return aggregateClaimSummary{}, errors.New("aggregate copy reference domain differs")
	}
	for _, s := range stores {
		if s.kind == ref.Kind && s.id == ref.ID {
			return aggregateClaimAt(ctx, s.store, ref.Component, ref.Ordinal)
		}
	}
	return aggregateClaimSummary{}, errors.New("aggregate copy reference is not an original input")
}

// Inventory was reconstructed from immutable originals before this loop. The
// outer frame carries an ordinal only, not a visitor Row retaining a body.
func aggregateClaimOrdinals(ctx context.Context, s receiverAuditStore, component int, visit func(int64) error) error {
	if component < 3 || component > 4 || len(s.publication.manifest.Cut.Inventory) != 9 {
		return errors.New("aggregate claim inventory differs")
	}
	count := s.publication.manifest.Cut.Inventory[component-3].Records
	if count < 0 {
		return errors.New("aggregate negative claim inventory")
	}
	for position := int64(0); position < count; position++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := visit(position + 1); err != nil {
			return err
		}
	}
	return nil
}

func aggregateClaimIdentity(component int, key ClaimKey) []byte {
	raw, _ := json.Marshal(struct {
		Domain    string
		Component int
		Key       ClaimKey
	}{"litevirt/aggregate-claim-key/v1", component, key})
	return raw
}

func aggregateClaimsTx(ctx context.Context, tx *LocalTx, bundle string, input aggregateEvidenceStore, stores []aggregateEvidenceStore, local aggregateLocalAudit) error {
	return aggregateLocalOriginsTx(ctx, tx, local, func(originFor func(int, int64) ([]byte, error)) error {
		for _, component := range []int{3, 4} {
			err := aggregateClaimOrdinals(ctx, input.store, component, func(ordinal int64) error {
				state, err := aggregateClaimAt(ctx, input.store, component, ordinal)
				if err != nil {
					return err
				}
				key := state.Key
				if !key.IsGenerationScoped() {
					return nil
				}
				identity := aggregateClaimIdentity(component, key)
				if len(identity) > 4*maxSourceFieldBytes {
					return errors.New("aggregate claim identity exceeds bound")
				}
				ref, _ := json.Marshal(aggregateCopyRef{input.kind, input.id, component, ordinal})
				origin := []byte{}
				if input.kind == "local" && !state.Accepted.IsZero() {
					origin, err = originFor(component, ordinal)
					if err != nil {
						return err
					}
				}
				promisedNonce, acceptedNonce := state.Promised.Nonce, state.Accepted.Nonce
				if promisedNonce == nil {
					promisedNonce = []byte{}
				}
				if acceptedNonce == nil {
					acceptedNonce = []byte{}
				}
				if _, err = tx.Exec(ctx, `INSERT INTO local_automation_aggregate_copies(bundle,origin_kind,origin_id,component,ordinal,claim_key,promised_round,promised_coord,promised_nonce,accepted_round,accepted_coord,accepted_nonce,origin_ref) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, bundle, input.kind, input.id, component, ordinal, identity, state.Promised.Round, state.Promised.Coordinator, promisedNonce, state.Accepted.Round, state.Accepted.Coordinator, acceptedNonce, origin); err != nil {
					return err
				}
				// Every accepted ballot enters this index, even when a prior or later
				// higher ballot wins. Configuration/Accept metadata does not split a key.
				if !state.Accepted.IsZero() {
					rows, err := tx.Query(ctx, `SELECT first_ref FROM local_automation_aggregate_conflicts WHERE bundle=? AND claim_key=? AND round=? AND coord=? AND nonce=? AND typeof(first_ref)='blob' AND length(CAST(first_ref AS BLOB)) BETWEEN 1 AND 1024 LIMIT 1`, bundle, identity, state.Accepted.Round, state.Accepted.Coordinator, acceptedNonce)
					if err != nil {
						return err
					}
					if len(rows) == 0 {
						if _, err = tx.Exec(ctx, `INSERT INTO local_automation_aggregate_conflicts(bundle,claim_key,round,coord,nonce,first_ref) VALUES(?,?,?,?,?,?)`, bundle, identity, state.Accepted.Round, state.Accepted.Coordinator, acceptedNonce, ref); err != nil {
							return err
						}
					} else {
						previous, err := aggregateReadCopy(ctx, stores, rows[0].Bytes("first_ref"))
						if err != nil {
							return err
						}
						if !previous.Accepted.Equal(state.Accepted) || previous.Key != key || previous.fingerprint != state.fingerprint {
							return errors.New("contradictory exact claim ballot")
						}
					}
				}
				rows, err := tx.Query(ctx, `SELECT promise_ref,accepted_ref FROM local_automation_aggregate_maxima WHERE bundle=? AND claim_key=? AND typeof(promise_ref)='blob' AND length(CAST(promise_ref AS BLOB)) BETWEEN 1 AND 1024 AND typeof(accepted_ref)='blob' AND length(CAST(accepted_ref AS BLOB)) BETWEEN 0 AND 1024 LIMIT 1`, bundle, identity)
				if err != nil {
					return err
				}
				promise, accepted := ref, []byte{}
				if !state.Accepted.IsZero() {
					accepted = ref
				}
				if len(rows) == 0 {
					_, err = tx.Exec(ctx, `INSERT INTO local_automation_aggregate_maxima(bundle,claim_key,promise_ref,accepted_ref) VALUES(?,?,?,?)`, bundle, identity, promise, accepted)
					return err
				}
				promise, accepted = rows[0].Bytes("promise_ref"), rows[0].Bytes("accepted_ref")
				previous, err := aggregateReadCopy(ctx, stores, promise)
				if err != nil {
					return err
				}
				if CompareBallots(state.Promised, previous.Promised) > 0 {
					promise = ref
				}
				var previousAccepted Ballot
				if len(accepted) > 0 {
					previous, err = aggregateReadCopy(ctx, stores, accepted)
					if err != nil {
						return err
					}
					previousAccepted = previous.Accepted
				}
				if CompareBallots(state.Accepted, previousAccepted) > 0 {
					accepted = ref
				}
				_, err = tx.Exec(ctx, `UPDATE local_automation_aggregate_maxima SET promise_ref=?,accepted_ref=? WHERE bundle=? AND claim_key=?`, promise, accepted, bundle, identity)
				return err
			})
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func aggregateCompatibleHistory(ctx context.Context, s, baseline receiverAuditStore) error {
	for sequence := uint64(1); sequence <= s.publication.manifest.Cut.Head.Sequence; sequence++ {
		current, err := aggregateHistoryAt(ctx, s, int64(sequence))
		if err != nil {
			return err
		}
		other, err := aggregateHistoryAt(ctx, baseline, int64(sequence))
		if err != nil {
			return err
		}
		// Fresh full decision/UID/assignment and ORIGINAL receipt commitments are
		// independent of valid differing certificate metadata, which stays retained.
		if current.digest != other.digest || current.fingerprint != other.fingerprint || current.receipt != other.receipt {
			return errors.New("incompatible aggregate certified history")
		}
	}
	return nil
}

// No custody/equality provider exists here. Required coverage is derived from
// every validated original, including losers, never a stored verified boolean.
func aggregateCoverage(ctx context.Context, s receiverAuditStore) error {
	for _, component := range []int{3, 4} {
		err := aggregateClaimOrdinals(ctx, s, component, func(ordinal int64) error {
			summary, err := aggregateClaimAt(ctx, s, component, ordinal)
			if err != nil {
				return err
			}
			if summary.needsCoverage {
				return errors.New("required secret/equality coverage unavailable")
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	for sequence := uint64(1); sequence <= s.publication.manifest.Cut.Head.Sequence; sequence++ {
		summary, err := aggregateHistoryAt(ctx, s, int64(sequence))
		if err != nil {
			return err
		}
		if summary.needsCoverage {
			return errors.New("required secret/equality coverage unavailable")
		}
	}
	return nil
}

func aggregateAcceptedBaselineTx(ctx context.Context, tx *LocalTx, bundle string, stores []aggregateEvidenceStore, baseline receiverAuditStore, head AutomationPrefix) error {
	return aggregateWalkTable(ctx, tx, aggregateMaximaTable, bundle, func(row Row) error {
		raw := row.Bytes("accepted_ref")
		if len(raw) == 0 {
			return nil
		}
		state, err := aggregateReadCopy(ctx, stores, raw)
		if err != nil {
			return err
		}
		if !state.Key.IsAutomation() || state.sequence > head.Sequence {
			return nil
		}
		original, err := aggregateHistoryAt(ctx, baseline, int64(state.sequence))
		if err != nil {
			return err
		}
		// A chosen decision need not remain in any current claim row. Every lower
		// accepted loser stays evidence even when its value differs from the chosen.
		if CompareBallots(state.Accepted, original.ballot) < 0 {
			return nil
		}
		if state.fingerprint != original.fingerprint {
			return errors.New("aggregate accepted maximum conflicts with certified baseline")
		}
		return nil
	})
}
