package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// AutomationCurrentProof is process-owned, single-use authority for the private
// FULL handoff. Serialized audit rows cannot construct it. Its fields and the
// registry are private; copying its value does not copy its authority.
type AutomationCurrentProof struct {
	retained        *retainedPrivateProof
	self            *AutomationCurrentProof
	used, abandoned *atomic.Bool
	owner           *AutomationReceiver
	attempt         *AutomationReceiverAttempt
	evidence        receiverAggregateEvidence
	sources         []receiverSourceAuthorization
	publications    []receiverPublication
	caps            []*pki.HostCertificateValidation
	observed        time.Time
	binding         string
}

func (p *AutomationCurrentProof) exactBinding() string {
	if p == nil || p.attempt == nil {
		return ""
	}
	a := p.attempt
	raw, _ := json.Marshal(struct {
		Attempt, Aggregate, Digest  string
		Binding                     []byte
		Request                     AutomationSourceRequest
		Facts                       receiverFacts
		At, Before, After, Observed time.Time
	}{a.id, p.evidence.aggregate, p.evidence.digest, a.binding, a.request, a.facts, a.at, a.notBefore, a.notAfter, p.observed})
	parts := [][]byte{[]byte("litevirt/receiver-current-private/v1"), raw}
	for i, s := range p.sources {
		b, _ := json.Marshal(struct {
			Host     sourceHost
			Peer     sourceTarget
			Observed time.Time
		}{s.host, s.peer, s.observed})
		parts = append(parts, b)
		if i < len(p.publications) {
			q := p.publications[i]
			b, _ = json.Marshal(struct {
				ID            string
				Manifest      sourceManifest
				Chain         [][]byte
				Before, After time.Time
			}{q.id, q.manifest, q.chain, q.notBefore, q.notAfter})
			parts = append(parts, b)
		}
	}
	if p.retained != nil {
		parts = append(parts, []byte("litevirt/retained-private-variant/v1"), p.retainedBinding())
	}
	return sourceDigest(parts...)
}

func (p *AutomationCurrentProof) Discard() {
	if p == nil || p.self != p || p.owner == nil {
		return
	}
	p.used.Store(true)
	r := p.owner
	r.mu.Lock()
	delete(r.proofs, p)
	caps := p.caps
	p.caps = nil
	r.mu.Unlock()
	for _, cap := range caps {
		cap.Discard()
	}
}

// Close invalidates every registered proof. A consumer serializes on this same
// owner and keeps responsibility for its lease through transaction terminal.
func (r *AutomationReceiver) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.closed = true
	var caps []*pki.HostCertificateValidation
	for p := range r.proofs {
		p.used.Store(true)
		caps = append(caps, p.caps...)
		p.caps = nil
		delete(r.proofs, p)
	}
	r.mu.Unlock()
	if r.client != nil {
		r.client.automationSourceMu.Lock()
		delete(r.client.automationReceivers, r)
		r.client.automationSourceMu.Unlock()
	}
	for _, cap := range caps {
		cap.Discard()
	}
}

// VerifyCurrent runs the real B/C verifier before obtaining fresh current peer
// observations. The final FULL pass rehashes all of that verifier's actual
// inputs under one real PKI lease. Inert work has no completion-time waiver.
func (r *AutomationReceiver) VerifyCurrent(ctx context.Context, previous *AutomationReceiverAttempt) (_ *AutomationCurrentProof, err error) {
	if previous == nil || previous.self != previous || previous.owner != r {
		return nil, errors.New("foreign receiver attempt")
	}
	// Reauthenticate membership and the actual served receiver before inert work.
	a, err := r.Begin(ctx, previous.request, previous)
	if err != nil {
		return nil, err
	}
	var evidence receiverAggregateEvidence
	if _, err = r.auditAggregateEvidence(ctx, a, &evidence); err != nil {
		return nil, err
	}
	if err = r.lock(ctx); err != nil {
		return nil, err
	}
	defer r.mu.Unlock()
	p := &AutomationCurrentProof{owner: r, attempt: a, evidence: evidence, used: &atomic.Bool{}, abandoned: &atomic.Bool{}}
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
	for _, member := range a.request.Sources {
		authorization, e := r.authorizeSource(ctx, a, member.Name)
		if e != nil {
			return nil, e
		}
		p.sources = append(p.sources, authorization)
		p.caps = append(p.caps, authorization.source, authorization.target)
		if p.observed.IsZero() || authorization.observed.Before(p.observed) {
			p.observed = authorization.observed
		}
		rows, e := r.client.sourceExportQuery(ctx, `SELECT publication FROM local_automation_receiver_audits WHERE attempt=? AND source=? AND typeof(publication)='text' AND length(CAST(publication AS BLOB))=64 LIMIT 1`, a.id, member.Name)
		if e != nil {
			return nil, e
		}
		if len(rows) != 1 {
			return nil, errors.New("current original source audit unavailable")
		}
		publication, e := r.authenticatePublication(ctx, a, member.Name, AutomationExportRequest{Intent: a.request, Publication: rows[0].String("publication"), Component: 3}, AutomationExportPage{}, authorization.peer)
		if e != nil {
			return nil, e
		}
		p.publications = append(p.publications, publication)
		if publication.notBefore.After(a.notBefore) {
			a.notBefore = publication.notBefore
		}
		if publication.notAfter.Before(a.notAfter) {
			a.notAfter = publication.notAfter
		}
	}
	p.binding = p.exactBinding()
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, p.caps...)
	if err != nil {
		return nil, err
	}
	err = r.transactionCurrent(ctx, a, lease, p.observed, p, receiverCurrentInertTx)
	// Transaction terminal strictly precedes release, including error paths.
	lease.Release()
	p.caps = nil
	if err != nil {
		return nil, err
	}
	// Release consumed every validation. Register again against the SAME verified
	// HostTrust. A policy/revision change refuses; never recapture stale authority.
	for _, s := range p.sources {
		cap, e := a.view.ValidateHostCertificate(ctx, s.peer.Chain, s.peer.Host.Name)
		if e != nil {
			return nil, e
		}
		p.caps = append(p.caps, cap)
	}
	cap, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		return nil, err
	}
	p.caps = append(p.caps, cap)
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = p.currentTime(); err != nil {
		return nil, err
	}
	return p, nil
}

func receiverCurrentInertTx(*LocalTx) error { return nil }

func (p *AutomationCurrentProof) currentTime() error {
	now := time.Now()
	a := p.attempt
	if now.Before(a.at) || now.Before(a.notBefore) || !now.Before(a.notAfter) {
		return errors.New("current counted signer expired")
	}
	if p.observed.IsZero() || now.Before(p.observed) || now.Sub(p.observed) >= sourceTargetObservationLifetime {
		return errors.New("current source observation expired")
	}
	return nil
}

func (r *AutomationReceiver) revalidateCurrentTx(ctx context.Context, tx *LocalTx, p *AutomationCurrentProof) error {
	if p == nil || p.self != p || p.owner != r || !r.proofs[p] || p.binding == "" || p.binding != p.exactBinding() {
		return errors.New("inactive or changed current proof binding")
	}
	if err := p.currentTime(); err != nil {
		return err
	}
	for _, s := range p.sources {
		host, err := sourceReadHost(ctx, tx, s.peer.Host.Name)
		if err != nil {
			return err
		}
		if host != s.host {
			return errors.New("current source admission changed")
		}
	}
	if p.retained != nil {
		if err := r.revalidateRetainedTx(ctx, tx, p); err != nil {
			return err
		}
	}
	digest, err := r.currentDependencyDigestTx(ctx, tx, p.attempt)
	if err != nil {
		return err
	}
	if digest != p.evidence.digest {
		return errors.New("current complete dependency binding changed")
	}
	return p.currentTime()
}

// consumeCurrent is the concrete private finalizer handoff. Task5d will place
// its concrete import/adoption owner here; this stage commits an inert FULL
// transaction and cannot claim active import. There is no caller callback.
func (r *AutomationReceiver) consumeCurrent(ctx context.Context, p *AutomationCurrentProof) (err error) {
	if p == nil || p.self != p || p.owner != r || p.used == nil || !p.used.CompareAndSwap(false, true) {
		return errors.New("inactive or foreign current proof")
	}
	if err = r.lock(ctx); err != nil {
		// The attempt is already consumed, even when canceled before owner entry.
		// Cleanup is deferred to the next owner operation/Discard/Close: acquiring
		// another operation's live lease solely for cleanup must not defeat cancel.
		p.abandoned.Store(true)
		return err
	}
	defer r.mu.Unlock()
	defer func() {
		delete(r.proofs, p)
		for _, cap := range p.caps {
			cap.Discard()
		}
		p.caps = nil
	}()
	if !r.proofs[p] || p.binding != p.exactBinding() {
		return errors.New("inactive or foreign current proof")
	}
	if err = p.currentTime(); err != nil {
		return err
	}
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, p.caps...)
	if err != nil {
		return err
	}
	defer lease.Release()
	return r.transactionCurrent(ctx, p.attempt, lease, p.observed, p, receiverCurrentInertTx)
}

func (r *AutomationReceiver) discardAbandonedLocked() {
	for p := range r.proofs {
		if p.abandoned.Load() {
			delete(r.proofs, p)
			for _, cap := range p.caps {
				cap.Discard()
			}
			p.caps = nil
		}
	}
}
