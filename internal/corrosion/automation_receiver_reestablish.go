package corrosion

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/litevirt/litevirt/internal/pki"
)

// Reestablish is an explicit storage-owned repair of durable floor ownership.
// It authenticates the actual current receiver, covers every retained original,
// and atomically installs signed artifacts under a fresh real FULL lease. It
// returns no attempt or proof and establishes no historical completion/readiness.
// Missing required installed signed floors need supported PKI repair first.
func (r *AutomationReceiver) Reestablish(ctx context.Context, intent AutomationSourceRequest) error {
	if err := r.lock(ctx); err != nil {
		return err
	}
	defer r.mu.Unlock()
	normalized, err := sourceRequest(intent)
	if err != nil {
		return err
	}
	predecessor, err := r.observePredecessor(ctx)
	if err != nil {
		return err
	}
	authorize := func() (*AutomationReceiverAttempt, error) {
		a, err := r.authorizeReceiverAttempt(ctx, normalized, nil)
		if err != nil {
			return nil, err
		}
		old := predecessor.value
		root := a.view.RootDigest()
		request, _ := json.Marshal(normalized)
		retained, _ := json.Marshal(old.Intent)
		// Renewed ordinary signatures may change current authorization bytes. They
		// cannot change the original chosen values, job, local lifetime or domain.
		if !bytes.Equal(request, retained) || old.Root != hex.EncodeToString(root[:]) || old.Facts.Incarnation != a.facts.Incarnation || old.Facts.Adopted != a.facts.Adopted || sourceConfigDigest(old.Facts.Old) != sourceConfigDigest(a.facts.Old) || sourceConfigDigest(old.Facts.Next) != sourceConfigDigest(a.facts.Next) {
			return nil, errors.New("receiver reestablishment differs from exact current job/local identity")
		}
		a.id, a.binding = predecessor.id, bytes.Clone(predecessor.binding)
		return a, nil
	}
	commitment, err := r.verifyInventoryCommitment(ctx, true)
	if err != nil {
		return err
	}
	var before receiverEstablishmentState
	if commitment != nil {
		before, err = r.reconcileReceiverFloors(ctx, true, commitment, commitment.manifest.Incarnation, commitment.manifest.Root)
		if err != nil {
			return err
		}
	}
	a, err := authorize()
	if err != nil {
		return err
	}
	if commitment == nil {
		before, err = r.reconcileLegacyState(ctx, a)
		if err != nil {
			return err
		}
	}
	// Reconciliation can strengthen the owner revision; only a new genuine
	// capture and current membership validation can authorize the new insertion.
	a, err = authorize()
	if err != nil {
		return err
	}
	spool, err := r.prepareLegacyEstablishments(ctx, a, before.originals)
	if err != nil {
		return err
	}
	defer spool.close()
	evidence, err := a.view.PublicEvidence()
	if err != nil {
		return err
	}
	artifact, err := r.prepareEstablishment(ctx, a, evidence)
	if err != nil {
		return err
	}
	inventory, err := r.prepareInventoryCommitment(ctx, a)
	if err != nil {
		return err
	}
	digest := a.view.EvidenceDigest()
	cap, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		return err
	}
	defer cap.Discard()
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, cap)
	if err != nil {
		return err
	}
	err = r.transactionEstablished(ctx, a, lease, &receiverEstablishmentCommit{before: before, inventory: inventory}, func(tx *LocalTx) error {
		if err := spool.replay(ctx, func(attempt, digest string, raw []byte) error {
			_, err := tx.Exec(ctx, `INSERT INTO local_automation_receiver_established(attempt,digest,artifact) VALUES(?,?,?) ON CONFLICT(attempt,digest) DO UPDATE SET artifact=excluded.artifact`, attempt, digest, raw)
			return err
		}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT OR IGNORE INTO local_automation_receiver_validations(attempt,digest,evidence) VALUES(?,?,?)`, a.id, hex.EncodeToString(digest[:]), evidence); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT OR IGNORE INTO local_automation_receiver_established(attempt,digest,artifact) VALUES(?,?,?)`, a.id, hex.EncodeToString(digest[:]), artifact)
		return err
	})
	// SQL terminal first. Discard/registry cleanup never enters a held PKI lease.
	lease.Release()
	if err != nil {
		return err
	}
	for proof := range r.proofs {
		proof.used.Store(true)
		delete(r.proofs, proof)
		for _, cap := range proof.caps {
			cap.Discard()
		}
		proof.caps = nil
	}
	return nil
}
