package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

func auditRetainedLocal(ctx context.Context, tx *LocalTx, original receiverAuditContext, h retainedAggregateHeader, a retainedFrameAddress, d retainedObjectDescriptor, directory retainedDirectoryReader, namespace string) (aggregateLocalAudit, error) {
	out := aggregateLocalAudit{id: h.LocalID, dependency: h.LocalDependency}
	if h.Attempt != original.id || h.Host != original.request.Target || h.Incarnation != original.facts.Incarnation || d.OriginalIdentity != h.LocalID || d.Source != h.Host || d.Incarnation != h.Incarnation || d.Kind != "local" || h.LayoutDigest != d.LayoutDigest {
		return out, errors.New("retained local semantic context differs")
	}
	if err := aggregateLocalFreshScratch(ctx, tx, namespace); err != nil {
		return out, err
	}
	refs, err := tx.Query(ctx, `SELECT 1 AS present FROM local_automation_receiver_refs WHERE audit=? LIMIT 1`, namespace)
	if err != nil {
		return out, err
	}
	if len(refs) != 0 {
		return out, errors.New("retained local scratch index already exists")
	}
	layout, err := retainedLocalTablesForDigest(h.LayoutDigest)
	if err != nil {
		return out, err
	}
	observation := aggregateLocalObservation{retained: true, layoutDigest: h.LayoutDigest}
	err = a.walk(ctx, tx, d, func(section int, n int64, raw []byte) error {
		row, err := decodeAutomationFramedRow(layout[section].descriptor(), n, raw, maxAggregateLocalRecordBytes)
		if err != nil {
			return err
		}
		return observation.observe(&out, section, n, row)
	})
	if err != nil {
		return out, err
	}
	if err = observation.audit(ctx, tx, original, h.Host, namespace, a.localID, true, &out); err != nil {
		return out, err
	}
	if out.coverage != h.LocalCoverage {
		return out, errors.New("retained local coverage differs")
	}
	out.retained = &retainedLocalContext{original, directory}
	return out, nil
}

// Ordinary local audits retain their live snapshot behavior. Transferred local
// audits compare the exact retained projection to the same shared reducer at
// its original cursor; receiver ACTIVE state never supplies the old projection.
func (s receiverAuditStore) compareLocalSemantic(ctx context.Context, stage string) error {
	if s.localProjectionID == "" {
		return aggregateLocalCompareSemantic(ctx, s.tx, stage)
	}
	layout, err := retainedLocalTablesForDigest(s.localLayoutDigest)
	if err != nil {
		return err
	}
	for _, d := range aggregateLocalTables()[18 : 18+len(automationSemanticTables)] {
		section := -1
		for i, original := range layout {
			if original.table == d.table {
				if original != d {
					return errors.New("retained semantic descriptor differs")
				}
				section = i
				break
			}
		}
		if section < 0 {
			// A missing historical section supplies zero original rows, never
			// permission to skip current replay. history calls this comparison
			// at the authenticated original cursor in its isolated stage.
			missing := false
			switch d.table {
			case "local_automation_target_operations", "local_automation_target_reservations":
				missing = s.localLayoutDigest == retainedLocalLayout83Digest()
			case "local_automation_executors", "local_automation_execution_progress", "local_automation_execution_artifacts", "local_automation_execution_terminals":
				missing = s.localLayoutDigest == retainedLocalLayout83Digest() || s.localLayoutDigest == retainedLocalLayout85Digest()
			}
			if !missing {
				return errors.New("retained semantic layout incomplete")
			}
		}
		digest := func(stored bool) (string, error) {
			h := sha256.New()
			sourceHash(h, []byte(d.table))
			var count int64
			visit := func(n int64, row Row) error {
				if n != count+1 {
					return errors.New("retained semantic ordinal differs")
				}
				row.Values[0] = ""
				raw, err := encodeAggregateLocalRecord(d.descriptor().name, n, row)
				if err != nil {
					return err
				}
				sourceHash(h, raw)
				count = n
				return nil
			}
			var err error
			if stored && section >= 0 {
				err = walkAutomationStoredFrames(ctx, s.tx, "local_automation_local_rows", "local_id=? AND section=?", []any{s.localProjectionID, section}, "section", maxAggregateLocalRecordBytes, func(section int, n int64, raw []byte) error {
					row, err := decodeAutomationFramedRow(d.descriptor(), n, raw, maxAggregateLocalRecordBytes)
					if err != nil {
						return err
					}
					return visit(n, row)
				})
			} else if !stored {
				err = walkAggregateLocalTable(ctx, s.tx, d, stage, visit)
			}
			sourceHash(h, []byte("end"), automationCutInteger(count))
			return hex.EncodeToString(h.Sum(nil)), err
		}
		original, err := digest(true)
		if err != nil {
			return err
		}
		replayed, err := digest(false)
		if err != nil {
			return err
		}
		if original != replayed {
			return fmt.Errorf("retained automation projection differs from certified history: %s", d.table)
		}
	}
	return nil
}
