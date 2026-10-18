package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"

	"github.com/litevirt/litevirt/internal/pki"
)

type retainedPrivateProof struct {
	Delivery   string
	Envelope   []byte
	Completion retainedCompletion
}

// A durable tuple is never authority. This storage-derived path freshly checks
// the real receiver/current donor and reconstructs all originals under the same
// owner/lease/FULL primitive before registering a private single-use handle.
func (r *AutomationReceiver) lookupRetainedCandidate(ctx context.Context, previous *AutomationReceiverAttempt, delivery string, key ClaimKey, ballot Ballot, full []byte) (_ *AutomationCurrentProof, err error) {
	if previous == nil || previous.self != previous || previous.owner != r || !receiverDigest(delivery) {
		return nil, errors.New("foreign retained receiver attempt")
	}
	a, err := r.Begin(ctx, previous.request, previous)
	if err != nil {
		return nil, err
	}
	if err = r.lock(ctx); err != nil {
		return nil, err
	}
	defer r.mu.Unlock()
	read, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	holder, found, err := retainedDeliveryTx(ctx, &LocalTx{tx: read}, delivery)
	rollback := read.Rollback()
	if err != nil {
		return nil, err
	}
	if rollback != nil {
		return nil, rollback
	}
	if !found {
		return nil, errors.New("retained delivery unavailable")
	}
	b := holder.body
	if key != b.Key || !ballot.Equal(b.Accepted) || len(full) == 0 || len(full) > maxAutomationCutRecordBytes || sourceDigest([]byte("litevirt/aggregate-full-value/v1"), full) != b.ValueDigest {
		return nil, errors.New("retained requested candidate differs from delivery")
	}
	authorization, err := r.authorizeRetainedHolder(ctx, a, holder)
	if err != nil {
		return nil, err
	}
	p := &AutomationCurrentProof{owner: r, attempt: a, sources: []receiverSourceAuthorization{authorization}, caps: []*pki.HostCertificateValidation{authorization.source, authorization.target}, observed: authorization.observed, used: &atomic.Bool{}, abandoned: &atomic.Bool{}}
	p.self = p
	if r.proofs == nil {
		r.proofs = make(map[*AutomationCurrentProof]bool)
	}
	r.proofs[p] = true
	defer func() {
		if err != nil {
			delete(r.proofs, p)
			for _, cap := range p.caps {
				cap.Discard()
			}
			p.caps = nil
		}
	}()
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, p.caps...)
	if err != nil {
		return nil, err
	}
	guard := retainedTransactionGuard{holder, authorization.host}
	err = r.transactionGuarded(ctx, a, lease, p.observed, p, nil, &guard, func(tx *LocalTx) error {
		if err := aggregateVerifySchemaTx(ctx, tx); err != nil {
			return err
		}
		stored, found, err := retainedDeliveryTx(ctx, tx, holder.id)
		if err != nil {
			return err
		}
		if !found || !bytes.Equal(stored.raw, holder.raw) {
			return errors.New("retained delivery changed before audit")
		}
		digest, directory, err := retainedDeliveryEvidenceTx(ctx, tx, holder)
		if err != nil {
			return err
		}
		rebuilt, err := verifyRetainedGraph(ctx, tx, holder.body, directory, a.view)
		if err != nil {
			return err
		}
		// The current selected nonleaf intervals survive reconstruction into the
		// existing immutable proof binding and both final COMMIT/consume guards.
		if rebuilt.notBefore.IsZero() || rebuilt.notAfter.IsZero() || !rebuilt.notBefore.Before(rebuilt.notAfter) {
			return errors.New("retained original live interval unavailable")
		}
		if rebuilt.notBefore.After(a.notBefore) {
			a.notBefore = rebuilt.notBefore
		}
		if rebuilt.notAfter.Before(a.notAfter) {
			a.notAfter = rebuilt.notAfter
		}
		candidate, err := rebuilt.candidate(ctx, tx, directory, holder.body, full)
		if err != nil {
			return err
		}
		coverage := sourceDigest([]byte("litevirt/retained-complete-coverage/v1"), []byte(holder.body.DirectoryRoot), []byte(rebuilt.id), []byte(rebuilt.claims))
		completion := retainedCompletion{digest, candidate, coverage}
		if err = rebuilt.clean(ctx, tx); err != nil {
			return err
		}
		if err = pinRetainedCompletionTx(ctx, tx, holder.id, completion); err != nil {
			return err
		}
		// Completion is immutable inert evidence. Current local observations and
		// every persisted input are bound independently, after scratch cleanup.
		dependency, err := r.currentDependencyDigestTx(ctx, tx, a)
		if err != nil {
			return err
		}
		p.evidence = receiverAggregateEvidence{rebuilt.id, dependency}
		p.retained = &retainedPrivateProof{holder.id, append([]byte(nil), holder.raw...), completion}
		p.binding = p.exactBinding()
		return nil
	})
	lease.Release()
	p.caps = nil
	if err != nil {
		return nil, err
	}
	// Consumed lease validations are never revived; obtain new capabilities from
	// the SAME verified trust view for the later inert single-use handoff.
	p.caps, err = renewRetainedHolderCapabilities(ctx, a, holder)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = p.currentTime(); err != nil {
		return nil, err
	}
	return p, nil
}
func (r *AutomationReceiver) revalidateRetainedTx(ctx context.Context, tx *LocalTx, p *AutomationCurrentProof) error {
	if p.retained == nil {
		return errors.New("retained private proof variant unavailable")
	}
	h, found, err := retainedDeliveryTx(ctx, tx, p.retained.Delivery)
	if err != nil {
		return err
	}
	if !found || !bytes.Equal(h.raw, p.retained.Envelope) || h.body.Attempt != p.attempt.id || h.body.AggregateDigest != p.evidence.aggregate {
		return errors.New("retained proof delivery binding changed")
	}
	completion, found, err := retainedCompletionTx(ctx, tx, h.id)
	if err != nil {
		return err
	}
	if !found || !sameRetainedCompletion(completion, p.retained.Completion) {
		return errors.New("retained proof completion tuple changed")
	}
	return nil
}
func (r *AutomationReceiver) consumeRetained(ctx context.Context, p *AutomationCurrentProof) error {
	if p == nil || p.retained == nil {
		return errors.New("retained current proof required")
	}
	return r.consumeCurrent(ctx, p)
}
func (p *AutomationCurrentProof) retainedBinding() []byte {
	if p.retained == nil {
		return nil
	}
	raw, _ := json.Marshal(p.retained)
	return raw
}

// Renew only after the initial lease has released its registrations. This is
// the existing same-snapshot capability handoff, not retained-proof issuance.
func renewRetainedHolderCapabilities(ctx context.Context, a *AutomationReceiverAttempt, holder retainedHolder) ([]*pki.HostCertificateValidation, error) {
	cap, err := a.view.ValidateHostCertificate(ctx, holder.signed.Chain, holder.body.Donor)
	if err != nil {
		return nil, err
	}
	target, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		cap.Discard()
		return nil, err
	}
	return []*pki.HostCertificateValidation{cap, target}, nil
}
