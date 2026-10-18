package corrosion

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// An initial real current lease authorizes the explicit storage-owned repair
// action. It is released before any retained-floor reconciliation or signing.
// The eventual insertion must acquire a NEW lease after all floors and recapture.
func (r *AutomationReceiver) authorizeEstablishmentOwner(ctx context.Context, a *AutomationReceiverAttempt) error {
	if a == nil || a.self != a || a.owner != r || a.view == nil || a.pair == nil {
		return errors.New("receiver establishment missing current owner")
	}
	cap, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		return err
	}
	defer cap.Discard()
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, cap)
	if err != nil {
		return err
	}
	defer lease.Release()
	if err = r.client.sourceExportReadLock(ctx); err != nil {
		return err
	}
	defer r.client.mu.RUnlock()
	tx, err := r.client.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	local := &LocalTx{tx: tx}
	if err = r.currentTx(ctx, local, a); err != nil {
		return err
	}
	facts, _, _, err := r.factsTx(ctx, local, a.request, nil)
	if err != nil {
		return err
	}
	if !sameReceiverFacts(facts, a.facts) {
		return errors.New("receiver establishment current authorization differs")
	}
	now := time.Now()
	if now.Before(a.at) || now.Before(a.notBefore) || !now.Before(a.notAfter) {
		return errors.New("receiver establishment current signer expired")
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return lease.Check()
}

// This is explicit current-owner reestablishment of floor ownership NOW. It is
// not startup's authentication path, does not silently bless legacy rows, and
// cannot reconstruct an old proof, completion, nonce, membership or readiness.
// The receiver owner must serialize this operation and its later FULL insert.
func (r *AutomationReceiver) reconcileLegacyOriginals(ctx context.Context, a *AutomationReceiverAttempt) (string, error) {
	state, err := r.reconcileLegacyState(ctx, a)
	return state.originals, err
}
func (r *AutomationReceiver) reconcileLegacyState(ctx context.Context, a *AutomationReceiverAttempt) (receiverEstablishmentState, error) {
	commitment, err := r.verifyInventoryCommitment(ctx, true)
	if err != nil {
		return receiverEstablishmentState{}, err
	}
	if err = r.authorizeEstablishmentOwner(ctx, a); err != nil {
		return receiverEstablishmentState{}, err
	}
	root := a.view.RootDigest()
	domain := hex.EncodeToString(root[:])
	if commitment != nil && (commitment.manifest.Incarnation != a.facts.Incarnation || commitment.manifest.Root != domain) {
		return receiverEstablishmentState{}, errors.New("receiver establishment current identity differs from inventory")
	}
	return r.reconcileReceiverFloors(ctx, true, commitment, a.facts.Incarnation, domain)
}

// Call after all signed floors have been reconciled and the actual owner has
// recaptured/reverified current membership. Prepared public artifacts remain
// bounded one at a time on disk; originalsDigest must match the reconciliation
// pass AND the later leased FULL snapshot before any atomic insertion.
func (r *AutomationReceiver) prepareLegacyEstablishments(ctx context.Context, a *AutomationReceiverAttempt, originalsDigest string) (*receiverEstablishedSpool, error) {
	if err := r.authorizeEstablishmentOwner(ctx, a); err != nil {
		return nil, err
	}
	spool, err := newReceiverEstablishedSpool()
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*receiverEstablishedSpool, error) { spool.close(); return nil, err }
	scanned, err := r.scanEstablishmentOriginals(ctx, func(binding *receiverPredecessor, digest string, raw []byte, _ *pki.HostTrustEvidence) error {
		old, found, err := r.lookupEstablishedArtifact(ctx, binding.id, digest)
		if err != nil {
			return err
		}
		var artifact []byte
		if found {
			authenticated, e := decodeReceiverEstablished(old, binding, raw, r.client.hostName)
			if e != nil {
				return e
			}
			artifact, err = r.prepareEstablishmentChain(ctx, a, binding, raw, authenticated.originalChain)
		} else {
			artifact, err = r.prepareEstablishmentFor(ctx, a, binding, raw)
		}
		if err != nil {
			return err
		}
		return spool.add(ctx, binding.id, digest, artifact)
	})
	if err != nil {
		return fail(err)
	}
	if scanned != originalsDigest {
		return fail(errors.New("receiver establishment originals changed during reconciliation/preparation"))
	}
	if err = spool.seal(); err != nil {
		return fail(err)
	}
	return spool, nil
}
