package corrosion

import (
	"bytes"
	"context"
	"errors"
)

// This context contains only original data and a closed immutable address.
// It is never a receiver attempt, current capability, or adopted-origin assertion.
type retainedLocalContext struct {
	original  receiverAuditContext
	directory retainedDirectoryReader
}

func retainedLocalOwnedStoreTx(ctx context.Context, tx *LocalTx, local aggregateLocalAudit) (receiverAuditStore, error) {
	var empty receiverAuditStore
	if local.retained == nil || local.attempt != nil {
		return empty, errors.New("retained local origin context unavailable")
	}
	original := local.retained.original
	if original.facts.Old == nil {
		return empty, errors.New("retained local old membership unavailable")
	}
	var metadata automationCutMetadata
	var raw []byte
	var root string
	// Resolve the original UNIQUE(generation,incarnation) selection from the
	// bounded old snapshot, never the current receiver's native cut owner table.
	section := 16
	layout := aggregateLocalTables()[section]
	err := walkAutomationStoredFrames(ctx, tx, "local_automation_local_rows", "local_id=? AND section=?", []any{local.store.localID, section}, "section", maxAggregateLocalRecordBytes, func(_ int, n int64, body []byte) error {
		row, err := decodeAutomationFramedRow(layout.descriptor(), n, body, maxAggregateLocalRecordBytes)
		if err != nil {
			return err
		}
		m, err := readAutomationCutMetadata(row)
		if err != nil {
			return err
		}
		if row.Int64("generation") != original.request.Generation || row.String("incarnation") != original.facts.Incarnation {
			return nil
		}
		if m.Generation != row.Int64("generation") || m.Incarnation != row.String("incarnation") {
			return errors.New("retained native selected row identity differs")
		}
		if metadata.ID != "" {
			return errors.New("retained native generation/lifetime is not unique")
		}
		metadata = m
		raw = row.Bytes("metadata")
		root = row.String("root")
		return nil
	})
	if err != nil {
		return empty, err
	}
	if metadata.ID == "" || metadata.Source != local.store.source || metadata.MembersHash != original.facts.Old.MembersHash {
		return empty, errors.New("retained owned cut native lifetime differs")
	}
	descriptor, address, err := local.retained.directory.find(ctx, tx, "native", metadata.ID)
	if err != nil {
		return empty, err
	}
	encoded, err := address.read(ctx, tx, 0, 1)
	if err != nil {
		return empty, err
	}
	if descriptor.Source != metadata.Source || descriptor.Incarnation != metadata.Incarnation || !bytes.Equal(encoded, raw) {
		return empty, errors.New("retained native original metadata differs")
	}
	if err = address.walk(ctx, tx, descriptor, nil); err != nil {
		return empty, err
	}
	namespace := local.store.id + ":owned-origin"
	if err = aggregateLocalFreshScratch(ctx, tx, namespace); err != nil {
		return empty, err
	}
	rows, err := tx.Query(ctx, `SELECT 1 AS present FROM local_automation_receiver_refs WHERE audit=? LIMIT 1`, namespace)
	if err != nil {
		return empty, err
	}
	if len(rows) != 0 {
		return empty, errors.New("retained owned scratch index already exists")
	}
	// The closed native adapter reads the separately retained original frames.
	// Its only transport distinction is absence of a published lineage digest;
	// the complete native standing, history and coverage checks remain shared.
	owned := receiverAuditStore{tx: tx, attempt: address.namespace, source: metadata.Source, id: namespace, evidenceID: metadata.ID, retainedNative: true, publication: receiverPublication{manifest: sourceManifest{Cut: metadata, Incarnation: metadata.Incarnation, OldValue: sourceConfigDigest(original.facts.Old), Root: root}}}
	if _, err = owned.index(ctx); err != nil {
		return empty, err
	}
	if _, err = owned.lineageContext(ctx, original); err != nil {
		return empty, err
	}
	if _, _, err = owned.history(ctx); err != nil {
		return empty, err
	}
	if _, _, err = owned.claimsAndCoverage(ctx, metadata.Head); err != nil {
		return empty, err
	}
	return owned, nil
}
