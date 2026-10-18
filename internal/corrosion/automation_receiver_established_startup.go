package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"hash"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

type receiverEstablishmentState struct{ originals, artifacts string }
type receiverEstablishmentCommit struct {
	before, after receiverEstablishmentState
	inventory     *receiverPreparedInventory
}

func receiverEstablishedTable() aggregateLocalTable {
	return aggregateLocalTable{"local_automation_receiver_established", "attempt,digest,artifact", "attempt,digest", "ttb", false}
}
func receiverArtifactHasher() hash.Hash {
	h := sha256.New()
	d := receiverEstablishedTable()
	sourceHash(h, []byte("litevirt/receiver-establishment-artifacts/v1"), []byte(d.table), []byte(d.columns), []byte(d.keys))
	return h
}
func receiverArtifactFinish(h hash.Hash, count int64) string {
	sourceHash(h, []byte("end"), automationCutInteger(count))
	return hex.EncodeToString(h.Sum(nil))
}
func (r *AutomationReceiver) lookupEstablishedArtifact(ctx context.Context, attempt, digest string) ([]byte, bool, error) {
	rows, err := r.client.sourceExportQuery(ctx, `SELECT CASE WHEN typeof(attempt)='text' AND typeof(digest)='text' AND typeof(artifact)='blob' AND length(artifact) BETWEEN 1 AND ? THEN artifact END AS artifact FROM local_automation_receiver_established WHERE attempt=? AND digest=?`, maxReceiverEstablishedBytes, attempt, digest)
	if err != nil {
		return nil, false, err
	}
	if len(rows) == 0 {
		return nil, false, nil
	}
	if len(rows) != 1 || len(rows[0].Bytes("artifact")) == 0 {
		return nil, true, errors.New("receiver establishment malformed artifact")
	}
	return rows[0].Bytes("artifact"), true, nil
}
func (r *AutomationReceiver) readEstablishedArtifact(ctx context.Context, attempt, digest string) ([]byte, error) {
	raw, found, err := r.lookupEstablishedArtifact(ctx, attempt, digest)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("receiver establishment missing; explicit current-owner reestablishment required")
	}
	return raw, nil
}

// Startup reads and authenticates every original before reconciling its signed
// floors under the existing local PKI owner. No retained row creates current
// authority. Missing legacy artifacts require the explicit storage repair path.
func (r *AutomationReceiver) reconcileEstablished(ctx context.Context) (receiverEstablishmentState, error) {
	commitment, err := r.verifyInventoryCommitment(ctx, false)
	if err != nil {
		return receiverEstablishmentState{}, err
	}
	incarnation, root := "", ""
	if commitment != nil {
		incarnation, root = commitment.manifest.Incarnation, commitment.manifest.Root
	}
	return r.reconcileReceiverFloors(ctx, false, commitment, incarnation, root)
}

// Authenticate ALL bounded originals and artifacts before entering the PKI
// owner. A second streaming pass reconciles their floors; exact inventory and
// raw-state comparisons prevent the passes from blessing a changed subset.
func (r *AutomationReceiver) reconcileReceiverFloors(ctx context.Context, allowMissing bool, commitment *receiverInventoryCommitment, incarnation, root string) (receiverEstablishmentState, error) {
	before, err := r.scanReceiverFloors(ctx, allowMissing, false, incarnation, root)
	if err != nil {
		return before, err
	}
	check := func() error {
		if commitment == nil {
			return nil
		}
		actual, err := r.inventoryRoot(ctx, nil)
		if err != nil {
			return err
		}
		if actual != commitment.manifest.Inventory {
			return errors.New("receiver establishment complete inventory changed during authentication")
		}
		return nil
	}
	if err = check(); err != nil {
		return receiverEstablishmentState{}, err
	}
	if commitment != nil {
		if err = pki.ReconcileCompletedHostTrust(ctx, r.dir, r.client.hostName, commitment.signer); err != nil {
			return receiverEstablishmentState{}, err
		}
	}
	after, err := r.scanReceiverFloors(ctx, allowMissing, true, incarnation, root)
	if err != nil {
		return receiverEstablishmentState{}, err
	}
	if before != after {
		return receiverEstablishmentState{}, errors.New("receiver establishment originals/artifacts changed during floor reconciliation")
	}
	if err = check(); err != nil {
		return receiverEstablishmentState{}, err
	}
	return after, nil
}
func (r *AutomationReceiver) scanReceiverFloors(ctx context.Context, allowMissing, reconcile bool, incarnation, root string) (receiverEstablishmentState, error) {
	var state receiverEstablishmentState
	h := receiverArtifactHasher()
	var count int64
	originals, err := r.scanEstablishmentOriginals(ctx, func(binding *receiverPredecessor, digest string, original []byte, e *pki.HostTrustEvidence) error {
		if (incarnation != "" && binding.value.Facts.Incarnation != incarnation) || (root != "" && binding.value.Root != root) {
			return errors.New("receiver establishment local identity/domain differs")
		}
		raw, found, err := r.lookupEstablishedArtifact(ctx, binding.id, digest)
		if err != nil {
			return err
		}
		floors := []*pki.HostTrustEvidence{e}
		if found {
			artifact, err := decodeReceiverEstablished(raw, binding, original, r.client.hostName)
			if err != nil {
				return err
			}
			count++
			receiverInventoryHashRow(h, receiverEstablishedTable(), count, Row{Columns: []string{"attempt", "digest", "artifact"}, Values: []any{binding.id, digest, raw}})
			if artifact.signer.Digest() != e.Digest() {
				floors = append(floors, artifact.signer)
			}
		} else {
			if !allowMissing {
				return errors.New("receiver establishment missing; explicit current-owner reestablishment required")
			}
			if _, err = e.RecordedLocalHost(r.client.hostName); err != nil {
				return err
			}
		}
		if reconcile {
			for _, floor := range floors {
				if err = pki.ReconcileCompletedHostTrust(ctx, r.dir, r.client.hostName, floor); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return state, err
	}
	rows, err := r.client.sourceExportQuery(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_established`)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") != count {
		return state, errors.New("receiver establishment orphan artifact coverage")
	}
	state.originals, state.artifacts = originals, receiverArtifactFinish(h, count)
	return state, nil
}
func receiverArtifactDigestTx(ctx context.Context, tx *LocalTx) (string, error) {
	if err := receiverEstablishedSchemaTx(ctx, tx); err != nil {
		return "", err
	}
	h := receiverArtifactHasher()
	var count int64
	err := walkAggregateBoundedTable(ctx, tx, receiverEstablishedTable(), "", currentEvidenceLimit, maxReceiverEstablishedBytes+128, func(n int64, row Row) error {
		count = n
		receiverInventoryHashRow(h, receiverEstablishedTable(), n, row)
		return nil
	})
	if err != nil {
		return "", err
	}
	return receiverArtifactFinish(h, count), nil
}
func receiverEstablishmentStateTx(ctx context.Context, tx *LocalTx) (receiverEstablishmentState, error) {
	var s receiverEstablishmentState
	var err error
	s.originals, err = receiverOriginalDigestTx(ctx, tx)
	if err != nil {
		return s, err
	}
	s.artifacts, err = receiverArtifactDigestTx(ctx, tx)
	return s, err
}
func (s receiverEstablishmentState) checkTx(ctx context.Context, tx *LocalTx) error {
	actual, err := receiverEstablishmentStateTx(ctx, tx)
	if err != nil {
		return err
	}
	if s.originals == "" || s.artifacts == "" || actual != s {
		return errors.New("receiver establishment complete originals or artifacts changed")
	}
	return nil
}
func (r *AutomationReceiver) transactionEstablished(ctx context.Context, a *AutomationReceiverAttempt, lease *pki.HostCertificateLease, guard *receiverEstablishmentCommit, fn func(*LocalTx) error) error {
	return r.transactionGuarded(ctx, a, lease, time.Time{}, nil, guard, nil, func(tx *LocalTx) error {
		if err := guard.before.checkTx(ctx, tx); err != nil {
			return err
		}
		if err := fn(tx); err != nil {
			return err
		}
		if guard.inventory == nil {
			return errors.New("receiver establishment inventory not prepared")
		}
		actual, err := receiverInventoryRootTx(ctx, tx)
		if err != nil {
			return err
		}
		if actual != guard.inventory.root {
			return errors.New("receiver establishment prospective inventory differs")
		}
		result, err := tx.Exec(ctx, `UPDATE local_automation_receiver_current SET established_inventory=? WHERE id=1 AND attempt=?`, guard.inventory.raw, a.id)
		if err != nil {
			return err
		}
		n, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("receiver establishment inventory selection changed")
		}
		guard.after, err = receiverEstablishmentStateTx(ctx, tx)
		return err
	})
}

func receiverEstablishedSchemaTx(ctx context.Context, tx *LocalTx) error {
	rows, err := tx.Query(ctx, `PRAGMA table_xinfo(local_automation_receiver_established)`)
	if err != nil {
		return err
	}
	if len(rows) != 3 {
		return errors.New("receiver establishment unsupported schema")
	}
	for i, name := range []string{"attempt", "digest", "artifact"} {
		kind, pk := "TEXT", int64(i+1)
		if i == 2 {
			kind, pk = "BLOB", 0
		}
		row := rows[i]
		if row.Int64("cid") != int64(i) || row.String("name") != name || row.String("type") != kind || row.Int64("notnull") != 1 || row.Int64("pk") != pk || row.Int64("hidden") != 0 || row.get("dflt_value") != nil {
			return errors.New("receiver establishment unsupported column shape")
		}
	}
	rows, err = tx.Query(ctx, `PRAGMA table_xinfo(local_automation_receiver_current)`)
	if err != nil {
		return err
	}
	if len(rows) != 3 {
		return errors.New("receiver inventory unsupported current schema")
	}
	for i, name := range []string{"id", "attempt", "established_inventory"} {
		kind, pk, notnull := "TEXT", int64(0), int64(1)
		if i == 0 {
			kind, pk, notnull = "INTEGER", 1, 0
		}
		if i == 2 {
			kind = "BLOB"
		}
		row := rows[i]
		if row.Int64("cid") != int64(i) || row.String("name") != name || row.String("type") != kind || row.Int64("pk") != pk || row.Int64("notnull") != notnull || row.Int64("hidden") != 0 {
			return errors.New("receiver inventory unsupported current column shape")
		}
		if (i < 2 && row.get("dflt_value") != nil) || (i == 2 && row.String("dflt_value") != "x''") {
			return errors.New("receiver inventory unsupported current default")
		}
	}
	return nil
}
