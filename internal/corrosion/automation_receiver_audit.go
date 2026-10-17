package corrosion

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// AuditSource validates one complete retained source and publishes only durable
// INERT audit data. Success is not a quorum, current completion proof, candidate
// permission, active import or custody. Every call authenticates the current
// source/receiver and rereads the exact original spool; no caller supplies facts.
// D must freshly authenticate completion and revalidate all exact evidence and
// local dependencies in its FULL owner before granting any live authority.
func (r *AutomationReceiver) AuditSource(ctx context.Context, a *AutomationReceiverAttempt, source string) error {
	if err := r.lock(ctx); err != nil {
		return err
	}
	defer r.mu.Unlock()
	authorization, err := r.authorizeSource(ctx, a, source)
	if err != nil {
		return err
	}
	defer authorization.discard()
	rows, err := r.client.sourceExportQuery(ctx, `SELECT publication FROM local_automation_receiver_sources WHERE attempt=? AND source=? AND typeof(publication)='text' AND length(CAST(publication AS BLOB))=64 LIMIT 1`, a.id, source)
	if err != nil {
		return err
	}
	if len(rows) != 1 {
		return errors.New("source audit publication missing")
	}
	request := AutomationExportRequest{Intent: a.request, Publication: rows[0].String("publication"), Component: 3}
	publication, err := r.authenticatePublication(ctx, a, source, request, AutomationExportPage{}, authorization.peer)
	if err != nil {
		return err
	}
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, authorization.source, authorization.target)
	if err != nil {
		return err
	}
	defer lease.Release()
	// This B-only inert snapshot can take O(history) time. The source was really
	// observed at invocation, but zero deliberately makes NO completion-time
	// peer-observation freshness assertion. Ingress's 10s guard stays unchanged.
	// The actual FULL/current binding, source admission, context, membership and
	// source+receiver PKI lease guards still enclose this atomic publication.
	return r.transaction(ctx, a, lease, time.Time{}, func(tx *LocalTx) error {
		if err := r.currentTx(ctx, tx, a); err != nil {
			return err
		}
		current, err := sourceReadHost(ctx, tx, source)
		if err != nil || current != authorization.host {
			return errors.New("audit source admission changed")
		}
		rows, err := tx.Query(ctx, `SELECT id FROM local_automation_receiver_jobs WHERE id=? AND job=? AND revision=? AND typeof(revision)='integer' LIMIT 1`, a.id, a.request.Job, a.request.Revision)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return errors.New("audit exact job revision differs")
		}
		if err = receiverAuditInventory(ctx, tx, a, source, publication); err != nil {
			return err
		}
		id := sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(source), []byte(publication.id), []byte(publication.manifest.Root))
		s := receiverAuditStore{tx: tx, attempt: a.id, source: source, id: id, publication: publication}
		// A retry rebuilds from empty causal state. Failure rolls back these
		// deletes and all partial work; the transport spool is never mutated.
		if _, err = tx.Exec(ctx, `DELETE FROM local_automation_receiver_requests WHERE audit=?`, id); err != nil {
			return err
		}
		if _, err = tx.Exec(ctx, `DELETE FROM local_automation_receiver_refs WHERE audit=?`, id); err != nil {
			return err
		}
		records, err := s.index(ctx)
		if err != nil {
			return err
		}
		lineage, err := s.lineage(ctx, a)
		if err != nil {
			return err
		}
		head, requests, err := s.history(ctx)
		if err != nil {
			return err
		}
		coverage, payloads, err := s.claimsAndCoverage(ctx, head)
		if err != nil {
			return err
		}
		raw, _ := json.Marshal(head)
		result, err := tx.Exec(ctx, `INSERT INTO local_automation_receiver_audits(id,attempt,source,publication,root,head,lineage,coverage,records,payloads,requests) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET head=excluded.head,lineage=excluded.lineage,coverage=excluded.coverage,records=excluded.records,payloads=excluded.payloads,requests=excluded.requests WHERE local_automation_receiver_audits.attempt=excluded.attempt AND local_automation_receiver_audits.source=excluded.source AND local_automation_receiver_audits.publication=excluded.publication AND local_automation_receiver_audits.root=excluded.root`, id, a.id, source, publication.id, publication.manifest.Root, raw, lineage, coverage, records, payloads, requests)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("existing inert audit identity differs")
		}
		return nil
	})
}

func receiverAuditInventory(ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt, source string, p receiverPublication) error {
	metadata, root, err := automationCutRoot(p.manifest.Cut)
	if err != nil || root != p.manifest.Root {
		return errors.New("audit original root differs")
	}
	rows, err := tx.Query(ctx, `SELECT metadata FROM local_automation_receiver_sources WHERE attempt=? AND source=? AND publication=? AND authenticated=1 AND typeof(metadata)='blob' AND length(CAST(metadata AS BLOB))=? LIMIT 1`, a.id, source, p.id, len(metadata))
	if err != nil {
		return err
	}
	if len(rows) != 1 || !bytes.Equal(rows[0].Bytes("metadata"), metadata) {
		return errors.New("audit metadata/progress binding differs")
	}
	// Exact inventory is recomputed, not inferred from authenticated/terminal.
	if err = receiverVerifyInventory(ctx, tx, a.id, source, p); err != nil {
		return err
	}
	if err = receiverVerifyComponentKeys(ctx, tx, a.id, source, "local_automation_receiver_components"); err != nil {
		return err
	}
	for component := uint32(0); component < 12; component++ {
		rows, err = tx.Query(ctx, `SELECT state FROM local_automation_receiver_components WHERE attempt=? AND source=? AND component=? AND terminal=1 AND cursor='' AND typeof(state)='blob' AND length(CAST(state AS BLOB)) BETWEEN 1 AND ? LIMIT 1`, a.id, source, component, receiverStateBytes)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return errors.New("complete audit terminal missing")
		}
		var state sourceExportCursor
		if err = receiverAuditJSON(rows[0].Bytes("state"), &state); err != nil {
			return err
		}
		var records, total int64
		var digest [32]byte
		if component < 3 {
			total = p.metadataBytes[component]
			records = (total + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes
			digest = p.metadataDigests[component]
		} else {
			inv := p.manifest.Cut.Inventory[component-3]
			records = inv.Records
			total = inv.Bytes
			raw, err := hex.DecodeString(inv.Digest)
			if err != nil {
				return err
			}
			copy(digest[:], raw)
		}
		h, err := state.hash()
		if err != nil {
			return err
		}
		binding := sourceExportBinding(AutomationExportRequest{Intent: a.request, Publication: p.id, Component: component})
		if state.Binding != binding || state.TotalRecords != records || state.Position != records || state.TotalBytes != total || state.Bytes != total || state.Digest != digest || !bytes.Equal(h.Sum(nil), digest[:]) {
			return errors.New("audit transport progress differs from stored inventory")
		}
	}
	return nil
}
