package corrosion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// These v1 sections inventory retained certified history, claims and membership.
// Node-local lifecycle/credential observations (v74) are deliberately excluded:
// they are neither transferable certified facts nor proof of cluster non-use.
// Lifecycle source-proof transfer, use/retirement/custody authority and active
// import each require an explicit inventory/provenance design, not this cut.
// rowid is SQLite's indexed immutable scan cursor while this transaction owns
// the snapshot. It is never a network cursor or part of an accepted key.
type automationCutSection struct{ name, table, columns string }

var automationCutSections = []automationCutSection{
	{"claims", "local_recovery_claims", "target_kind,target_name,owner_epoch,attempt," + claimRowCols},
	{"incarnation_claims", "local_incarnation_claims", "target_kind,target_name,incarnation,owner_epoch,attempt," + claimRowCols},
	{"history", "local_automation_history", "sequence,digest,value_json,certificate,receipt_json,anchor_sequence"},
	{"anchors", "local_automation_anchors", "sequence,digest,generation,members_hash,certificate"},
	{"requests", "local_automation_requests", "scope,request_id,identity,receipt_json,operation_id"},
	{"authority", "local_automation_authority", "id,generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance"},
	{"adoptions", "local_voter_adoption", "generation,imported_from,adopted_at"},
	{"seals", "local_voter_seals", "generation,reason,sealed_at"},
	{"membership", "voter_configs", "generation,members_json,members_hash,change,certificate,created_by,created_at,deleted_at"},
}

// walkAutomationCutRows holds at most one bounded row. The first query reads
// lengths, not payloads: corrupt oversized SQL fields cannot allocate an
// unbounded buffer before the codec can refuse them. No OFFSET or all-row sort.
func automationCutRowSize(section automationCutSection) string {
	cols := strings.Split(strings.ReplaceAll(strings.ReplaceAll(section.columns, "\n", ""), "\t", ""), ",")
	sizes := make([]string, 0, len(cols))
	for _, col := range cols {
		sizes = append(sizes, "COALESCE(length(CAST("+strings.TrimSpace(col)+" AS BLOB)),0)")
	}
	return strings.Join(sizes, "+")
}

func walkAutomationCutRowIDs(ctx context.Context, tx *LocalTx, section automationCutSection, visit func(int64) error) error {
	size := automationCutRowSize(section)
	var after int64
	invalid, err := tx.Query(ctx, "SELECT rowid FROM "+section.table+" WHERE rowid<=0 LIMIT 1")
	if err != nil {
		return err
	}
	if len(invalid) != 0 {
		return fmt.Errorf("invalid source row cursor")
	}
	for {
		rows, err := tx.Query(ctx, "SELECT rowid AS cursor,("+size+") AS bytes FROM "+section.table+" WHERE rowid>? ORDER BY rowid LIMIT 1", after)
		if err != nil || len(rows) == 0 {
			return err
		}
		after = rows[0].Int64("cursor")
		if rows[0].Int64("bytes") > maxAutomationCutRecordBytes {
			return fmt.Errorf("oversized automation source row in %s", section.name)
		}
		if err = visit(after); err != nil {
			return err
		}
	}
}

func automationCutRowTx(ctx context.Context, tx *LocalTx, section automationCutSection, rowid int64) (Row, error) {
	rows, err := tx.Query(ctx, "SELECT "+section.columns+" FROM "+section.table+" WHERE rowid=? LIMIT 1", rowid)
	if err != nil {
		return Row{}, err
	}
	if len(rows) != 1 {
		return Row{}, fmt.Errorf("source row disappeared")
	}
	return rows[0], nil
}
func walkAutomationCutRows(ctx context.Context, tx *LocalTx, section automationCutSection, visit func(Row) error) error {
	return walkAutomationCutRowIDs(ctx, tx, section, func(rowid int64) error {
		row, err := automationCutRowTx(ctx, tx, section, rowid)
		if err != nil {
			return err
		}
		return visit(row)
	})
}

// FreezeAutomationCut creates only inert LOCAL content, not an authenticated
// transfer, adoption proof, or public readiness. The engine passes its existing
// strict reducer; storage independently audits the owned rows. There is no
// caller-provided anchor/completion assertion and no published read API.
func (c *Client) FreezeAutomationCut(ctx context.Context, generation int64, reduce AutomationReducer) (id string, err error) {
	if generation <= 0 {
		return "", fmt.Errorf("invalid cut generation")
	}
	err = c.executeLocal(ctx, func(tx *LocalTx) error {
		if err := requireAutomationFull(ctx, tx); err != nil {
			return err
		}

		// Bound the existing standing reader's variable-sized fields before it
		// materializes them. Ordinary membership storage predates this exporter.
		oversized, e := tx.Query(ctx, `SELECT generation FROM voter_configs WHERE generation=(SELECT MAX(generation) FROM local_voter_adoption) AND (length(CAST(members_json AS BLOB))>? OR length(CAST(certificate AS BLOB))>? OR (`+automationCutRowSize(automationCutSections[8])+`)>?) LIMIT 1`, maxAutomationCutMetadataBytes, MaxAutomationRecordBytes, maxAutomationCutRecordBytes)
		if e != nil {
			return e
		}
		if len(oversized) != 0 {
			return fmt.Errorf("source membership exceeds cut bounds")
		}
		oversized, e = tx.Query(ctx, `SELECT id FROM local_voter_incarnation WHERE length(CAST(incarnation AS BLOB))>4096 LIMIT 1`)
		if e != nil {
			return e
		}
		if len(oversized) != 0 {
			return fmt.Errorf("source incarnation exceeds cut bounds")
		}
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		if st.adopted < generation {
			return fmt.Errorf("source has not adopted cut generation")
		}
		// An existing cut is immutable, including when later adoption has rewritten
		// fixed-stream claim rows. A re-imaged incarnation cannot reuse it.
		rows, err := tx.Query(ctx, `SELECT id,metadata,root FROM local_automation_cuts WHERE generation=? AND incarnation=? AND length(metadata)<=? AND length(id)=32 AND length(root)=64 LIMIT 1`, generation, st.incarnation, maxAutomationCutMetadataBytes)
		if err != nil {
			return err
		}
		if len(rows) == 1 {
			m, err := readAutomationCutMetadata(rows[0])
			if err != nil {
				return err
			}
			if m.Source != c.hostName || m.Generation != generation || m.Incarnation != st.incarnation {
				return fmt.Errorf("cut identity mismatch")
			}
			if err = verifyAutomationCutRecordsTx(ctx, tx, m); err != nil {
				return err
			}
			id = m.ID
			return nil
		}
		if st.adopted != generation || !st.sealed || !st.cfg.Explicit() {
			return fmt.Errorf("source must be sealed in the actual old generation")
		}
		// Inspect the actual transaction, not the cached binary schema. Older
		// binaries can open newer additive databases, but cannot inventory unknown
		// provenance. Archived cuts above retain their own codec/source schema.
		rows, err = tx.Query(ctx, `SELECT version FROM schema_state WHERE id=1`)
		if err != nil {
			return err
		}
		if len(rows) != 1 || !supportedAutomationCutDescriptor(rows[0].Int("version"), automationCutCodec) {
			return fmt.Errorf("unsupported automation cut source schema")
		}
		switch rows[0].Int("version") {
		case 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88:
			if err := automationVerifySemanticSchemaTx(ctx, tx); err != nil {
				return err
			}
		}
		// Existing replay helpers perform nested anchor/request/membership reads.
		// Bound every source row before invoking them, without loading payloads.
		// This scan is only for a new cut; archived bytes never rescan live state.
		for _, section := range automationCutSections {
			oversized, err := tx.Query(ctx, `SELECT rowid FROM `+section.table+` WHERE (`+automationCutRowSize(section)+`)>? LIMIT 1`, maxAutomationCutRecordBytes)
			if err != nil {
				return err
			}
			if len(oversized) != 0 {
				return fmt.Errorf("oversized automation source row in %s", section.name)
			}
		}
		member, ok := st.cfg.Member(c.hostName)
		if !ok || member.Incarnation != st.incarnation || automationElectorateBudget(st.cfg.Members) != nil || st.cfg.MembersHash != MembersHash(st.cfg.Members) {
			return fmt.Errorf("source membership mismatch")
		}
		h, err := auditAutomationCutTx(ctx, tx, reduce)
		if err != nil {
			return err
		}
		var nonce [16]byte
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		id = hex.EncodeToString(nonce[:])
		m := automationCutMetadata{Codec: automationCutCodec, SourceSchema: rows[0].Int("version"), ID: id, Source: c.hostName, Incarnation: st.incarnation, Generation: generation, MembersHash: st.cfg.MembersHash, Head: h}
		for sectionIndex, section := range automationCutSections {
			inv := automationCutInventory{Section: section.name, Codec: automationCutCodec}
			hash := sha256.New()
			// Even an empty section has a domain/version-bound digest.
			prefix, _ := automationCutFrame("section/v1", []byte(section.name))
			hash.Write(prefix)
			err = walkAutomationCutRows(ctx, tx, section, func(row Row) error {
				if sectionIndex < 2 {
					if err := auditAutomationCutClaimTx(ctx, tx, row, h); err != nil {
						return err
					}
				}
				record, err := encodeAutomationCutRecord(section.name, inv.Records+1, row)
				if err != nil {
					return err
				}
				if err = addAutomationCutSize(&inv, len(record)); err != nil {
					return err
				}
				hash.Write(record)
				_, err = tx.Exec(ctx, `INSERT INTO local_automation_cut_records (cut_id,section,ordinal,record) VALUES (?,?,?,?)`, id, sectionIndex, inv.Records, record)
				return err
			})
			if err != nil {
				return err
			}
			inv.Digest = hex.EncodeToString(hash.Sum(nil))
			m.Inventory = append(m.Inventory, inv)
		}
		metadata, root, err := automationCutRoot(m)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_cuts (id,generation,incarnation,metadata,root) VALUES (?,?,?,?,?)`, id, generation, st.incarnation, metadata, root)
		return err
	}, c.automationSeams)
	if err != nil {
		return "", err
	}
	return id, nil
}
func readAutomationCutMetadata(row Row) (automationCutMetadata, error) {
	var m automationCutMetadata
	b := row.Bytes("metadata")
	if len(b) > maxAutomationCutMetadataBytes || json.Unmarshal(b, &m) != nil {
		return m, fmt.Errorf("corrupt cut metadata")
	}
	encoded, root, err := automationCutRoot(m)
	if err != nil || string(encoded) != string(b) || root != row.String("root") || m.ID != row.String("id") || !supportedAutomationCutDescriptor(m.SourceSchema, m.Codec) || len(m.Inventory) != len(automationCutSections) {
		return m, fmt.Errorf("corrupt cut inventory")
	}
	for i, inv := range m.Inventory {
		if inv.Section != automationCutSections[i].name || inv.Codec != automationCutCodec || inv.Records < 0 || inv.Bytes < 0 || len(inv.Digest) != 64 {
			return m, fmt.Errorf("corrupt cut section")
		}
	}
	return m, nil
}

func verifyAutomationCutRecordsTx(ctx context.Context, tx *LocalTx, m automationCutMetadata) error {
	for section, inv := range m.Inventory {
		hash := sha256.New()
		prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
		hash.Write(prefix)
		var ordinal, total int64
		for {
			rows, err := tx.Query(ctx, `SELECT ordinal,length(record) AS size FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal>? ORDER BY ordinal LIMIT 1`, m.ID, section, ordinal)
			if err != nil {
				return err
			}
			if len(rows) == 0 {
				break
			}
			if rows[0].Int64("ordinal") != ordinal+1 || rows[0].Int64("size") > maxAutomationCutRecordBytes {
				return fmt.Errorf("corrupt immutable cut record")
			}
			ordinal++
			rows, err = tx.Query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? LIMIT 1`, m.ID, section, ordinal)
			if err != nil {
				return err
			}
			if len(rows) != 1 {
				return fmt.Errorf("missing immutable cut record")
			}
			record := rows[0].Bytes("record")
			if total > inv.Bytes-int64(len(record)) {
				return fmt.Errorf("cut byte inventory mismatch")
			}
			total += int64(len(record))
			hash.Write(record)
		}
		if ordinal != inv.Records || total != inv.Bytes || hex.EncodeToString(hash.Sum(nil)) != inv.Digest {
			return fmt.Errorf("cut inventory mismatch")
		}
	}
	rows, err := tx.Query(ctx, `SELECT section FROM local_automation_cut_records WHERE cut_id=? AND (section<0 OR section>=? OR ordinal<=0) LIMIT 1`, m.ID, len(m.Inventory))
	if err != nil {
		return err
	}
	if len(rows) != 0 {
		return fmt.Errorf("unknown cut section or invalid ordinal")
	}
	return nil
}
