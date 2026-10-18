package corrosion

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

type aggregateSource struct {
	member        VoterMember
	authorization receiverSourceAuthorization
	publication   receiverPublication
	audit         string
	store         receiverAuditStore
	head          AutomationPrefix
	coverage      string
}

type aggregateRosterEntry struct {
	Source, Incarnation, Audit, Publication, Root, Cut, Coverage string
}

// auditAggregate constructs inert evidence only. A caller cannot turn its
// durable ID into current process authority, adoption or permission to import.
func (r *AutomationReceiver) auditAggregate(ctx context.Context, a *AutomationReceiverAttempt) (string, error) {
	return r.auditAggregateEvidence(ctx, a, nil)
}

// The optional private capture is populated only by this concrete complete
// verifier inside its successful FULL transaction. It is never durable authority.
func (r *AutomationReceiver) auditAggregateEvidence(ctx context.Context, a *AutomationReceiverAttempt, capture *receiverAggregateEvidence) (string, error) {
	if err := r.lock(ctx); err != nil {
		return "", err
	}
	defer r.mu.Unlock()
	if a == nil || a.self != a || a.owner != r {
		return "", errors.New("foreign receiver attempt")
	}
	// This is a bounded roster, not an in-memory history or claim journal.
	sources := make([]aggregateSource, 0, len(a.request.Sources))
	defer func() {
		for _, s := range sources {
			s.authorization.discard()
		}
	}()
	for _, member := range a.request.Sources {
		rows, err := r.client.sourceExportQuery(ctx, `SELECT 1 AS present FROM local_automation_receiver_audits WHERE attempt=? AND source=? LIMIT 1`, a.id, member.Name)
		if err != nil {
			return "", err
		}
		if len(rows) == 0 {
			continue
		}
		// Probe before loading a publication or any audit body. A malformed audit
		// is a refusal, never permission to silently reduce the fixed roster.
		rows, err = r.client.sourceExportQuery(ctx, `SELECT typeof(id) AS it,length(CAST(id AS BLOB)) AS il,typeof(publication) AS pt,length(CAST(publication AS BLOB)) AS pl FROM local_automation_receiver_audits WHERE attempt=? AND source=? LIMIT 1`, a.id, member.Name)
		if err != nil {
			return "", err
		}
		if len(rows) != 1 || rows[0].String("it") != "text" || rows[0].Int64("il") != 64 || rows[0].String("pt") != "text" || rows[0].Int64("pl") != 64 {
			return "", errors.New("aggregate source audit identity malformed")
		}
		rows, err = r.client.sourceExportQuery(ctx, `SELECT id,publication FROM local_automation_receiver_audits WHERE attempt=? AND source=? AND typeof(id)='text' AND length(CAST(id AS BLOB))=64 AND typeof(publication)='text' AND length(CAST(publication AS BLOB))=64 LIMIT 1`, a.id, member.Name)
		if err != nil {
			return "", err
		}
		if len(rows) != 1 {
			return "", errors.New("aggregate source audit disappeared")
		}
		authorization, err := r.authorizeSource(ctx, a, member.Name)
		if err != nil {
			return "", err
		}
		s := aggregateSource{member: member, authorization: authorization, audit: rows[0].String("id")}
		sources = append(sources, s)
		publication, err := r.authenticatePublication(ctx, a, member.Name, AutomationExportRequest{Intent: a.request, Publication: rows[0].String("publication"), Component: 3}, AutomationExportPage{}, authorization.peer)
		if err != nil {
			return "", err
		}
		sources[len(sources)-1].publication = publication
	}
	target, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		return "", err
	}
	defer target.Discard()
	validations := []*pki.HostCertificateValidation{target}
	for _, s := range sources {
		validations = append(validations, s.authorization.source, s.authorization.target)
	}
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, validations...)
	if err != nil {
		return "", err
	}
	defer lease.Release()
	var result string
	// Zero deliberately does not assert completion-time network freshness. D
	// must obtain its own current proof and perform the local FULL rehash.
	err = r.transaction(ctx, a, lease, time.Time{}, func(tx *LocalTx) error {
		if err := aggregateVerifySchemaTx(ctx, tx); err != nil {
			return err
		}
		if err := r.currentTx(ctx, tx, a); err != nil {
			return err
		}
		return aggregatePreparedReadsTx(tx, func(reads *aggregatePreparedReads) error {
			defer func() {
				for i := range sources {
					sources[i].store.prepared = nil
				}
			}()
			var scratch []string // At most one per member plus the local contribution.
			for i := range sources {
				s := &sources[i]
				current, err := sourceReadHost(ctx, tx, s.member.Name)
				if err != nil || current != s.authorization.host {
					return errors.New("aggregate source admission changed")
				}
				namespace, err := aggregateScratchTx(ctx, tx)
				if err != nil {
					return err
				}
				scratch = append(scratch, namespace)
				s.store = receiverAuditStore{tx: tx, prepared: reads, attempt: a.id, source: s.member.Name, id: namespace, evidenceID: s.audit, publication: s.publication}
				if err = aggregateRevalidateSourceTx(ctx, tx, a, s); err != nil {
					return err
				}
			}
			required := MajorityOf(len(a.facts.Old.Members))
			if len(sources) < required {
				return fmt.Errorf("complete old electorate observed %d required %d", len(sources), required)
			}
			if len(sources) != len(a.request.Sources) {
				return errors.New("fixed source roster incomplete")
			}
			namespace, err := aggregateScratchTx(ctx, tx)
			if err != nil {
				return err
			}
			scratch = append(scratch, namespace)
			local, err := auditAggregateLocalTx(ctx, tx, a, r.client, namespace)
			if err != nil {
				return err
			}
			local.store.prepared = reads
			head, baseline := local.head, local.store
			for _, s := range sources {
				if s.head.Sequence > head.Sequence {
					head, baseline = s.head, s.store
				}
			}
			if err = aggregateCompatibleHistory(ctx, local.store, baseline); err != nil {
				return err
			}
			if err = aggregateCoverage(ctx, local.store); err != nil {
				return err
			}
			roster := make([]aggregateRosterEntry, 0, len(sources))
			for _, s := range sources {
				if err = aggregateCompatibleHistory(ctx, s.store, baseline); err != nil {
					return err
				}
				if err = aggregateCoverage(ctx, s.store); err != nil {
					return err
				}
				roster = append(roster, aggregateRosterEntry{s.member.Name, s.member.Incarnation, s.audit, s.publication.id, s.publication.manifest.Root, s.publication.manifest.Cut.ID, s.coverage})
			}
			rosterRaw, _ := json.Marshal(roster)
			headRaw, _ := json.Marshal(head)
			coverage := sourceDigest([]byte("litevirt/aggregate-coverage/v1"), []byte(local.coverage), rosterRaw)
			id := sourceDigest([]byte("litevirt/receiver-aggregate/v1"), []byte(a.id), a.binding, []byte(local.id), []byte(local.dependency), headRaw, []byte(coverage), rosterRaw)
			// Build maxima in a fresh namespace. A retry cannot temporarily overwrite
			// even a winning or losing row of an already published immutable aggregate.
			temporary, err := aggregateTemporaryTx(ctx, tx)
			if err != nil {
				return err
			}
			stores := make([]aggregateEvidenceStore, 0, len(sources)+1)
			for _, s := range sources {
				stores = append(stores, aggregateEvidenceStore{"source", s.audit, s.store})
			}
			stores = append(stores, aggregateEvidenceStore{"local", local.id, local.store})
			for _, s := range stores {
				if err = aggregateClaimsTx(ctx, tx, temporary, s, stores, local); err != nil {
					return err
				}
			}
			if err = aggregateAcceptedBaselineTx(ctx, tx, temporary, stores, baseline, head); err != nil {
				return err
			}
			if err = aggregatePublishTx(ctx, tx, temporary, id, a.id, local.id, headRaw, coverage, rosterRaw, roster); err != nil {
				return err
			}
			for _, namespace := range scratch {
				if err = aggregateCleanScratchTx(ctx, tx, namespace); err != nil {
					return err
				}
			}
			if capture != nil {
				digest, err := r.currentDependencyDigestTx(ctx, tx, a)
				if err != nil {
					return err
				}
				*capture = receiverAggregateEvidence{aggregate: id, digest: digest}
			}
			result = id
			return nil
		})
	})
	if err != nil {
		return "", err
	}
	return result, nil
}

func aggregateRevalidateSourceTx(ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt, s *aggregateSource) error {
	p := s.publication
	expected := sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(s.member.Name), []byte(p.id), []byte(p.manifest.Root))
	if expected != s.audit {
		return errors.New("aggregate original source audit identity differs")
	}
	if err := receiverCheckPublicationRows(ctx, tx, a.id, s.member.Name, p); err != nil {
		return err
	}
	if err := receiverAuditInventory(ctx, tx, a, s.member.Name, p); err != nil {
		return err
	}
	records, err := s.store.index(ctx)
	if err != nil {
		return err
	}
	lineage, err := s.store.lineage(ctx, a)
	if err != nil {
		return err
	}
	head, requests, err := s.store.history(ctx)
	if err != nil {
		return err
	}
	coverage, payloads, err := s.store.claimsAndCoverage(ctx, head)
	if err != nil {
		return err
	}
	raw, _ := json.Marshal(head)
	// Predicates inspect SQL types and byte lengths before selecting the body.
	rows, err := tx.Query(ctx, `SELECT head FROM local_automation_receiver_audits WHERE id=? AND attempt=? AND source=? AND publication=? AND root=? AND typeof(head)='blob' AND length(CAST(head AS BLOB))=? AND typeof(lineage)='text' AND length(CAST(lineage AS BLOB))=64 AND lineage=? AND typeof(coverage)='text' AND length(CAST(coverage AS BLOB))=64 AND coverage=? AND typeof(records)='integer' AND records=? AND typeof(payloads)='integer' AND payloads=? AND typeof(requests)='integer' AND requests=? LIMIT 1`, s.audit, a.id, s.member.Name, p.id, p.manifest.Root, len(raw), lineage, coverage, records, payloads, requests)
	if err != nil {
		return err
	}
	if len(rows) != 1 || !bytes.Equal(rows[0].Bytes("head"), raw) {
		return errors.New("aggregate immutable source audit differs")
	}
	s.head, s.coverage = head, coverage
	return nil
}

func aggregateScratchTx(ctx context.Context, tx *LocalTx) (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	id := "aggregate-scratch:" + hex.EncodeToString(nonce[:])
	for _, table := range []string{"local_automation_receiver_refs", "local_automation_receiver_requests"} {
		rows, err := tx.Query(ctx, "SELECT 1 AS present FROM "+table+" WHERE audit=? LIMIT 1", id)
		if err != nil {
			return "", err
		}
		if len(rows) != 0 {
			return "", errors.New("aggregate scratch collision")
		}
	}
	for _, d := range automationSemanticTables {
		rows, err := tx.Query(ctx, "SELECT 1 AS present FROM "+d.table+" WHERE stage=? LIMIT 1", "receiver-audit:"+id)
		if err != nil {
			return "", err
		}
		if len(rows) != 0 {
			return "", errors.New("aggregate stage collision")
		}
	}
	return id, nil
}
func aggregateCleanScratchTx(ctx context.Context, tx *LocalTx, id string) error {
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_receiver_requests WHERE audit=?`, id); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM local_automation_receiver_refs WHERE audit=?`, id); err != nil {
		return err
	}
	return automationResetSemanticProjectionTx(ctx, tx, "receiver-audit:"+id)
}
func aggregateTemporaryTx(ctx context.Context, tx *LocalTx) (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	id := "aggregate-build:" + hex.EncodeToString(nonce[:])
	for _, table := range []string{"local_automation_aggregate_copies", "local_automation_aggregate_maxima", "local_automation_aggregate_conflicts", "local_automation_aggregate_sources"} {
		rows, err := tx.Query(ctx, "SELECT 1 AS present FROM "+table+" WHERE bundle=? LIMIT 1", id)
		if err != nil {
			return "", err
		}
		if len(rows) != 0 {
			return "", errors.New("aggregate build collision")
		}
	}
	return id, nil
}
