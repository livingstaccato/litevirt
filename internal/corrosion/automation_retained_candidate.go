package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

type retainedCandidateRef struct {
	Object           int64
	Component        int
	Ordinal          int64
	Key              ClaimKey
	Accepted         Ballot
	ValueDigest      string
	AcceptanceDigest string
}

// Exact original inclusion is independent of this receiver's selected maxima.
// A reference is inert and remains subordinate to the complete bundle audit.
func (s receiverAuditStore) retainedCandidate(ctx context.Context, object int64, key ClaimKey, ballot Ballot, full []byte, recordDigest string) (retainedCandidateRef, error) {
	var out retainedCandidateRef
	if object <= 0 || key.Validate() != nil || !key.IsGenerationScoped() || validateAutomationBallot(ballot, false) != nil ||
		len(full) == 0 || len(full) > maxAutomationCutRecordBytes || !receiverDigest(recordDigest) || s.localID != "" {
		return out, errors.New("retained candidate identity or native origin unavailable")
	}
	keyRaw, _ := json.Marshal(key)
	if len(keyRaw) > 4*maxSourceFieldBytes {
		return out, errors.New("retained candidate key exceeds bound")
	}
	// The existing claim index selects an exact original acceptance, including
	// losing copies. No aggregate maximum is an eligibility whitelist.
	rows, err := s.query(ctx, `SELECT typeof(component) AS ct,typeof(ordinal) AS ot,CASE WHEN typeof(component)='integer' THEN component END AS component,CASE WHEN typeof(ordinal)='integer' THEN ordinal END AS ordinal FROM local_automation_receiver_refs WHERE audit=? AND claim_key=? AND accepted_round=? AND accepted_coord=? AND accepted_nonce=? ORDER BY component,ordinal LIMIT 1`, s.id, keyRaw, int64(ballot.Round), ballot.Coordinator, ballot.Nonce)
	if err != nil {
		return out, err
	}
	if len(rows) != 1 || rows[0].String("ct") != "integer" || rows[0].String("ot") != "integer" ||
		(rows[0].Int("component") != 3 && rows[0].Int("component") != 4) || rows[0].Int64("ordinal") <= 0 {
		return out, errors.New("exact retained acceptance not indexed")
	}
	component, ordinal := rows[0].Int("component"), rows[0].Int64("ordinal")
	row, err := s.record(ctx, component, ordinal)
	if err != nil {
		return out, err
	}
	actual := ClaimKey{TargetKind: row.String("target_kind"), TargetName: row.String("target_name"), Incarnation: row.String("incarnation"), OwnerEpoch: row.Int64("owner_epoch"), Attempt: row.Int64("attempt")}
	state, err := scanClaimRow(actual, row)
	if err != nil {
		return out, err
	}
	if err = validateRetainedClaimState(state); err != nil {
		return out, err
	}
	if actual != key || !state.Accepted.Equal(ballot) || state.Value == nil || state.Accept == nil {
		return out, errors.New("retained original acceptance differs")
	}
	canonical, err := json.Marshal(state.Value)
	if err != nil || !bytes.Equal(canonical, full) {
		return out, errors.New("retained full candidate bytes differ")
	}
	original, err := encodeAutomationCutRecord(automationCutSections[component-3].name, ordinal, row)
	if err != nil {
		return out, err
	}
	if sourceDigest([]byte("litevirt/retained-acceptance-record/v1"), original) != recordDigest {
		return out, errors.New("retained original record commitment differs")
	}
	out = retainedCandidateRef{object, component, ordinal, key, state.Accepted, sourceDigest([]byte("litevirt/aggregate-full-value/v1"), canonical), recordDigest}
	return out, nil
}

func (r retainedAggregateRebuild) candidate(ctx context.Context, tx *LocalTx, directory retainedDirectoryReader, identity retainedHolderBody, full []byte) (_ retainedCandidateRef, retErr error) {
	var out retainedCandidateRef
	if !receiverDigest(r.id) || identity.ValueDigest != sourceDigest([]byte("litevirt/aggregate-full-value/v1"), full) {
		return out, errors.New("retained candidate full commitment differs")
	}
	var selected *receiverAuditStore
	for i := range r.sources {
		store := &r.sources[i].store
		if store.source == identity.OriginalSource {
			selected = store
			break
		}
	}
	kind, original := "source", ""
	if selected != nil {
		original = selected.publication.id
	} else {
		if r.local.store.source != identity.OriginalSource || r.local.retained == nil {
			return out, errors.New("retained candidate origin is outside original aggregate")
		}
		raw, _ := json.Marshal(identity.Key)
		rows, err := tx.Query(ctx, `SELECT component,ordinal FROM local_automation_receiver_refs WHERE audit=? AND claim_key=? AND accepted_round=? AND accepted_coord=? AND accepted_nonce=? ORDER BY component,ordinal LIMIT 1`, r.local.store.id, raw, int64(identity.Accepted.Round), identity.Accepted.Coordinator, identity.Accepted.Nonce)
		if err != nil {
			return out, err
		}
		if len(rows) != 1 {
			return out, errors.New("retained local acceptance missing")
		}
		// Reuse C's exact signed acceptance comparison between the old local row and
		// its native original, before treating that native record as included.
		if err = aggregateLocalOriginsTx(ctx, tx, r.local, func(origin func(int, int64) ([]byte, error)) error {
			_, err := origin(rows[0].Int("component"), rows[0].Int64("ordinal"))
			return err
		}); err != nil {
			return out, err
		}
		owned, err := retainedLocalOwnedStoreTx(ctx, tx, r.local)
		if err != nil {
			return out, err
		}
		defer func() { retErr = errors.Join(retErr, aggregateCleanScratchTx(ctx, tx, owned.id)) }()
		selected = &owned
		kind, original = "native", owned.publication.manifest.Cut.ID
	}
	cut := selected.publication.manifest.Cut
	if cut.Source != identity.OriginalSource || cut.Incarnation != identity.OriginalIncarnation || cut.ID != identity.OriginalCut || selected.publication.manifest.Root != identity.OriginalRoot {
		return out, errors.New("retained candidate original publication differs")
	}
	_, address, err := directory.find(ctx, tx, kind, original)
	if err != nil {
		return out, err
	}
	if address.namespace != selected.attempt {
		return out, errors.New("retained candidate address differs")
	}
	parts := strings.Split(address.namespace, ":")
	object, err := strconv.ParseInt(parts[len(parts)-1], 10, 64)
	if err != nil {
		return out, err
	}
	return selected.retainedCandidate(ctx, object, identity.Key, identity.Accepted, full, identity.AcceptanceDigest)
}
