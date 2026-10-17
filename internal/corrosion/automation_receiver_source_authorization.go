package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/litevirt/litevirt/internal/pki"
	"time"
)

type receiverSourceAuthorization struct {
	host           sourceHost
	peer           sourceTarget
	observed       time.Time
	source, target *pki.HostCertificateValidation
}

func (a receiverSourceAuthorization) discard() {
	if a.source != nil {
		a.source.Discard()
	}
	if a.target != nil {
		a.target.Discard()
	}
}

// Called only while the receiver owner is locked. Both ingress and inert audit
// use the actual membership/SQLite incarnation/admission/current PKI owner.
func (r *AutomationReceiver) authorizeSource(ctx context.Context, a *AutomationReceiverAttempt, source string) (out receiverSourceAuthorization, err error) {
	if a == nil || a.self != a || a.owner != r {
		return out, errors.New("foreign receiver attempt")
	}
	var member VoterMember
	for _, m := range a.request.Sources {
		if m.Name == source {
			member = m
			break
		}
	}
	if member.Name == "" {
		return out, errors.New("receiver source is not in fixed old roster")
	}
	// Read-only authorization before metadata/body loading or network acquisition.
	if err = r.client.sourceExportReadLock(ctx); err != nil {
		return out, err
	}
	tx, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		r.client.mu.RUnlock()
		return out, err
	}
	local := &LocalTx{tx: tx}
	err = r.currentTx(ctx, local, a)
	var host sourceHost
	if err == nil {
		host, err = sourceReadHost(ctx, local, source)
	}
	if err == nil {
		var facts receiverFacts
		facts, _, _, err = r.factsTx(ctx, local, a.request, nil)
		if err == nil && !sameReceiverFacts(facts, a.facts) {
			err = errors.New("receiver current dependencies changed")
		}
	}
	tx.Rollback()
	r.client.mu.RUnlock()
	if err != nil {
		return out, err
	}
	out.observed = time.Now()
	var peer sourceTarget
	if source == r.client.hostName {
		fp := sha256.Sum256(a.pair.Certificate[0])
		peer = sourceTarget{Host: host, Incarnation: a.facts.Incarnation, Chain: a.pair.Certificate, Fingerprint: hex.EncodeToString(fp[:]), Local: true}
	} else {
		_, peer, err = sourceQueryPeer(ctx, r.dir, host, a.request.Generation, false)
		if err != nil {
			return out, err
		}
	}
	if peer.Incarnation != member.Incarnation {
		return out, errors.New("receiver source current incarnation differs")
	}
	if err = sourceAdmission(a.view, host, peer.Chain[0]); err != nil {
		return out, err
	}
	sourceCap, err := a.view.ValidateHostCertificate(ctx, peer.Chain, source)
	if err != nil {
		return out, err
	}

	targetCap, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		sourceCap.Discard()
		return out, err
	}

	out.host = host
	out.peer = peer
	out.source = sourceCap
	out.target = targetCap
	return out, nil
}
