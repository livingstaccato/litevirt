package corrosion

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// Attempt progression and supersede (docs/design/recovery-claims.md §3.12).
//
// A claim key's attempt advances only when the destination of the decided
// value provably will never execute it. There are two kinds of evidence, and
// every voter checks it before it promises at attempt+1:
//
//   - an ABANDONMENT: the attempt-n destination, alive, signs that it has not
//     executed the proof and never will. It records the proof ID in the
//     node-local local_abandoned_proofs in the same transaction that checks
//     it has not started it, and from then on refuses to claim it — the check
//     sits in the same transaction as every later claim.
//   - its PERMANENT REMOVAL: the destination is fenced proof-grade, has no
//     live hosts row, and its certificate is revoked. The operator produces
//     all three with one command, `lv host rm --dead`. The revocation is what
//     closes the hazard: a revoked host can no longer authenticate to any
//     peer, so one that reboots from a stale replica cannot pass the
//     execution gate its certificate would otherwise let it try.

// ErrProofAbandoned is returned when a proof this node abandoned is claimed
// or advanced. It is permanent: an abandoned proof never executes here.
var ErrProofAbandoned = errors.New("this node abandoned the proof and will never execute it")

// ErrProofExecuted is returned by AbandonProof for a proof this node has
// already started to execute: an abandonment is only ever signed for a proof
// that never ran.
var ErrProofExecuted = errors.New("this node has started executing the proof; it cannot abandon it")

// ClaimAbandonment is a destination's signed statement that it has not
// executed, and never will, the proof a decided claim named (§3.12).
type ClaimAbandonment struct {
	Host      string   `json:"host"`
	ProofID   string   `json:"proof_id"`
	Key       ClaimKey `json:"key"`
	Reason    string   `json:"reason,omitempty"`
	CertPEM   string   `json:"cert_pem"`
	Signature []byte   `json:"signature"`
}

// Encode is the abandonment's wire form.
func (a ClaimAbandonment) Encode() (string, error) {
	b, err := json.Marshal(a)
	return string(b), err
}

// DecodeClaimAbandonment parses an abandonment.
func DecodeClaimAbandonment(s string) (ClaimAbandonment, error) {
	var a ClaimAbandonment
	if s == "" {
		return a, fmt.Errorf("no abandonment")
	}
	if err := json.Unmarshal([]byte(s), &a); err != nil {
		return a, fmt.Errorf("abandonment does not parse: %w", err)
	}
	return a, nil
}

const (
	claimAbandonDomain = "litevirt-recovery-abandon-v1"
	// claimAbandonDomainV2 signs an abandonment at an incarnation-scoped key
	// (see claimAcceptDomainV2).
	claimAbandonDomainV2 = "litevirt-recovery-abandon-v2"
)

func abandonPayload(host, proofID string, key ClaimKey) []byte {
	h := sha256.New()
	if key.Incarnation == "" {
		claimField(h, claimAbandonDomain)
	} else {
		claimField(h, claimAbandonDomainV2)
	}
	claimField(h, host)
	claimField(h, proofID)
	claimField(h, key.TargetKind)
	claimField(h, key.TargetName)
	if key.Incarnation != "" {
		claimField(h, key.Incarnation)
	}
	claimField(h, i64(key.OwnerEpoch))
	claimField(h, i64(key.Attempt))
	return h.Sum(nil)
}

// SignAbandonment signs this host's abandonment of proofID at key.
func (s *ClaimSigner) SignAbandonment(proofID string, key ClaimKey, reason string) (ClaimAbandonment, error) {
	if s == nil || s.key == nil {
		return ClaimAbandonment{}, fmt.Errorf("no claim signing key loaded")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, abandonPayload(s.name, proofID, key))
	if err != nil {
		return ClaimAbandonment{}, fmt.Errorf("sign abandonment: %w", err)
	}
	return ClaimAbandonment{Host: s.name, ProofID: proofID, Key: key, Reason: reason, CertPEM: s.certPEM, Signature: sig}, nil
}

// VerifyAbandonment checks that a is host's abandonment of proofID at key,
// signed with a CA-issued, unrevoked certificate naming host.
func (v *ClaimVerifier) VerifyAbandonment(a ClaimAbandonment, host, proofID string, key ClaimKey) error {
	if v == nil {
		return fmt.Errorf("no claim verifier loaded")
	}
	if a.Host != host || a.ProofID != proofID || a.Key != key {
		return fmt.Errorf("abandonment is %s's of proof %s at %s, not %s's of %s at %s",
			a.Host, a.ProofID, a.Key, host, proofID, key)
	}
	c, err := parseCertPEM([]byte(a.CertPEM))
	if err != nil {
		return err
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: v.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("abandonment certificate does not chain to the cluster CA: %w", err)
	}
	if c.Subject.CommonName != host {
		return fmt.Errorf("abandonment signed with %q's certificate", c.Subject.CommonName)
	}
	if pki.IsCertRevoked(v.pkiDir, c.SerialNumber) {
		return fmt.Errorf("abandonment certificate %s is revoked", c.SerialNumber.Text(16))
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("abandonment certificate key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, abandonPayload(host, proofID, key), a.Signature) {
		return fmt.Errorf("abandonment signature does not verify")
	}
	return nil
}

// proofStartSteps are the step checkpoints a promote records before and at
// StartDomain. A proof carrying either may already be running here.
var proofStartSteps = []string{"start_attempted", "started"}

// AbandonProof records, in one local transaction, that this node will never
// execute proofID — refusing if it may already have. It is safe to call
// again: an abandonment already recorded is simply re-signed.
//
// "May already have" is read off this node's own proof row: a completed
// proof, one claimed by another executor, a reschedule or relocate this node
// has claimed (its executor starts straight after the claim), or a promote
// that has recorded a start checkpoint. A promote this node claimed but whose
// build failed before the start checkpoint is abandonable — that is the
// promote→reschedule fallback §3.12 exists for — and the checkpoint append is
// guarded by the same table (AppendProofStepUnlessAbandoned), so the two
// cannot both succeed.
func (c *Client) AbandonProof(ctx context.Context, proofID string, key ClaimKey, reason string) error {
	if proofID == "" {
		return fmt.Errorf("abandon needs a proof id")
	}
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		rows, err := tx.Query(ctx, `SELECT 1 AS one FROM local_abandoned_proofs WHERE proof_id = ?`, proofID)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			return nil
		}
		rows, err = tx.Query(ctx, `SELECT action, status, executor_host, step_state FROM runtime_action_proofs
			WHERE id = ? AND deleted_at IS NULL`, proofID)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			r := rows[0]
			status, executor, action := r.String("status"), r.String("executor_host"), r.String("action")
			switch {
			case status == ProofCompleted:
				return fmt.Errorf("%w: proof %s is completed", ErrProofExecuted, proofID)
			case executor != "" && executor != c.hostName:
				return fmt.Errorf("%w: proof %s is held by %s", ErrProofExecuted, proofID, executor)
			case executor == c.hostName && action != ActionPromote:
				return fmt.Errorf("%w: this node has claimed %s proof %s", ErrProofExecuted, action, proofID)
			}
			for _, st := range proofStartSteps {
				if ProofStepDone(r.String("step_state"), st) {
					return fmt.Errorf("%w: proof %s recorded %q", ErrProofExecuted, proofID, st)
				}
			}
		}
		_, err = tx.Exec(ctx, `INSERT INTO local_abandoned_proofs
			(proof_id, target_kind, target_name, owner_epoch, attempt, reason, abandoned_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`,
			proofID, key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt, reason,
			time.Now().UTC().Format(time.RFC3339Nano))
		return err
	})
}

// ProofAbandoned reports whether this node abandoned proofID.
func (c *Client) ProofAbandoned(ctx context.Context, proofID string) (bool, error) {
	rows, err := c.Query(ctx, `SELECT 1 AS one FROM local_abandoned_proofs WHERE proof_id = ?`, proofID)
	return len(rows) > 0, err
}

// proofAbandonedTx is ProofAbandoned inside a guard's transaction.
func proofAbandonedTx(ctx context.Context, tx *sql.Tx, proofID string) (bool, error) {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM local_abandoned_proofs WHERE proof_id = ?`, proofID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// AppendProofStepUnlessAbandoned is AppendProofStep that refuses with
// ErrProofAbandoned when this node has abandoned the proof, decided in the same
// transaction as the append. A promote records its start checkpoint through
// it immediately before StartDomain, which is what makes "abandon only a proof
// that never started" exact.
func AppendProofStepUnlessAbandoned(ctx context.Context, c *Client, id, step string) error {
	now := c.NowTS()
	abandoned := false
	_, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		a, err := proofAbandonedTx(ctx, tx, id)
		if err != nil {
			return false, err
		}
		abandoned = a
		return !a, nil
	}, []Statement{{SQL: `UPDATE runtime_action_proofs
		    SET step_state = TRIM(COALESCE(step_state,'') || ' ' || ?), updated_at = ?
		  WHERE id = ? AND deleted_at IS NULL
		    AND status NOT IN ('completed','failed')
		    AND instr(' ' || COALESCE(step_state,'') || ' ', ' ' || ? || ' ') = 0`,
		Params: []interface{}{step, now, id, step}}})
	if err != nil {
		return err
	}
	if abandoned {
		return ErrProofAbandoned
	}
	return nil
}

// SupersedeEvidence is what a proposer presents with a Prepare at attempt n+1
// (§3.12): the certificate that decided attempt n, the value it decided, and —
// unless the destination has been permanently removed — the destination's
// signed abandonment of that value's proof.
type SupersedeEvidence struct {
	PriorCertificate string      `json:"prior_certificate"`
	PriorValue       *ClaimValue `json:"prior_value"`
	Abandonment      string      `json:"abandonment,omitempty"`
}

// HostProofGradeFence returns the newest proof-grade fencing_log row for host
// (an IPMI power-off or an operator's `lv host fence-confirm`), whatever its
// age: the supersede evidence and `lv host rm --dead` ask whether the host
// was ever proven off, alongside its removal and revocation.
func HostProofGradeFence(ctx context.Context, c *Client, host string) (FenceLogRecord, bool, error) {
	rows, err := c.Query(ctx, `SELECT id, host_name, method, result, timestamp, detail FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		return FenceLogRecord{}, false, err
	}
	var best FenceLogRecord
	var bestTS time.Time
	found := false
	for _, r := range rows {
		if !FenceProofGrade(r.String("method"), r.String("result")) {
			continue
		}
		ts, _ := time.Parse(time.RFC3339, r.String("timestamp"))
		if !found || ts.After(bestTS) {
			found, bestTS = true, ts
			best = FenceLogRecord{ID: r.String("id"), HostName: host, Method: r.String("method"),
				Result: r.String("result"), Detail: r.String("detail"), Timestamp: r.String("timestamp")}
		}
	}
	return best, found, nil
}

// RemovedHostEvidence checks, in this node's own replica, the three facts that
// make host's permanent removal supersede evidence (§3.12): it is fenced
// proof-grade, it has no live hosts row, and its certificate serial — read off
// its tombstoned row — is in the installed CRL. Any one missing refuses; replica
// lag delays a supersede and never admits one.
func RemovedHostEvidence(ctx context.Context, c *Client, pkiDir, host string) error {
	if _, ok, err := HostProofGradeFence(ctx, c, host); err != nil {
		return err
	} else if !ok {
		return fmt.Errorf("%s has no proof-grade fence recorded (IPMI power-off or `lv host fence-confirm %s`)", host, host)
	}
	if h, err := GetHost(ctx, c, host); err != nil {
		return err
	} else if h != nil {
		return fmt.Errorf("%s is still a member of the cluster (it has a live hosts row); `lv host rm --dead %s` removes it", host, host)
	}
	rows, err := c.Query(ctx, `SELECT cert_serial FROM hosts WHERE name = ? AND deleted_at IS NOT NULL`, host)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("%s has no removed hosts row here to read its certificate serial from", host)
	}
	serial := strings.ToLower(strings.ReplaceAll(rows[0].String("cert_serial"), ":", ""))
	if serial == "" || serial == "unknown" {
		return fmt.Errorf("%s's removed hosts row records no certificate serial", host)
	}
	revoked, err := pki.LoadCRL(filepath.Join(pkiDir, "crl.pem"))
	if err != nil {
		return fmt.Errorf("%s's certificate is not revoked here yet (no CRL installed: %v)", host, err)
	}
	for _, s := range revoked {
		if strings.EqualFold(strings.TrimLeft(s, "0"), strings.TrimLeft(serial, "0")) {
			return nil
		}
	}
	return fmt.Errorf("%s's certificate %s is not in this node's CRL yet", host, serial)
}
