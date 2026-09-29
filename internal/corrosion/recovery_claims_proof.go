package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// The recovery-claim certificate on a runtime-action proof
// (docs/design/recovery-claims.md §3.9, schema v60).
//
// The certificate is EVIDENCE for a proof, not part of what the proof is:
// ProofBindingEqual ignores it, a row may gain one after it was written, and a
// re-certification of the same value at a later voter generation may replace
// it (§4.6). What it may never do is certify a different value from the proof
// it sits on — every writer checks that before anything is persisted.

// SetRecoveryClaimGate injects the predicate that permits emitting the
// claim_certificate column's statement shapes, wired at daemon start to
// DurablyLatched(recovery_claim_v1). Unset, it fails CLOSED: those shapes are
// new in v60, and a previous-release peer that meets one fails its apply and
// stalls its replication stream. The token is ReplicationGated, so it cannot
// latch while any replication recipient runs such a build.
func (c *Client) SetRecoveryClaimGate(fn func() bool) { c.recoveryClaimGate.Store(&fn) }

// MayEmitClaimCertificate reports whether this node may put a claim_certificate
// statement on the wire.
func (c *Client) MayEmitClaimCertificate() bool {
	fn := c.recoveryClaimGate.Load()
	return fn != nil && *fn != nil && (*fn)()
}

// ErrClaimCertificateNotEmittable means a proof carries a certificate this
// node may not yet write (recovery_claim_v1 has not latched here). Retryable:
// the latch forms from the same peer set the coordinator's did.
var ErrClaimCertificateNotEmittable = errors.New("proof carries a claim certificate this node cannot yet emit; retry once recovery_claim_v1 latches")

// ClaimKeyForProof is the claim key a proof's certificate must decide, less
// its attempt, which the certificate itself names (§3.10 step 2).
func ClaimKeyForProof(p ActionProof, attempt int64) (ClaimKey, error) {
	epoch, err := strconv.ParseInt(p.OwnerEpoch, 10, 64)
	if err != nil {
		return ClaimKey{}, fmt.Errorf("proof %s carries owner epoch %q, which no claim key can name", p.ID, p.OwnerEpoch)
	}
	return ClaimKey{TargetKind: p.TargetKind, TargetName: p.TargetName, OwnerEpoch: epoch, Attempt: attempt}, nil
}

// CertificateAuthorizesProof decodes certJSON and checks that it certifies
// exactly p (§3.10 steps 1–3): its key names p's target and owner epoch, and
// its value digest is the digest of p's binding fields with the certificate's
// source host. It does NOT check signatures or the voter generation — that is
// VerifyClaimCertificate, which needs the verifier and the voter set. This is
// the part any writer can check with nothing but the two values in hand.
func CertificateAuthorizesProof(certJSON string, p ActionProof) (ClaimCertificate, error) {
	cert, err := DecodeClaimCertificate(certJSON)
	if err != nil {
		return cert, err
	}
	want, err := ClaimKeyForProof(p, cert.Key.Attempt)
	if err != nil {
		return cert, err
	}
	if cert.Key != want {
		return cert, fmt.Errorf("certificate decides %s, not %s", cert.Key, want)
	}
	proof := p
	proof.ClaimCertificate = ""
	digest, err := ClaimValue{Proof: &proof, SourceHost: cert.SourceHost}.Digest()
	if err != nil {
		return cert, err
	}
	if cert.ValueDigest != digest {
		return cert, fmt.Errorf("certificate certifies value %s, but proof %s with source %s digests to %s",
			short(cert.ValueDigest), p.ID, cert.SourceHost, short(digest))
	}
	return cert, nil
}

// VerifyClaimCertificate is the destination's check of the certificate on p
// (docs/design/recovery-claims.md §3.10), in order:
//
//  1. the certificate is present and parses;
//  2. it decides p's target at p's owner epoch (the caller has already
//     compared p's owner epoch with its own fresh row — the existing ABA
//     check — so this binds the certificate to the generation being left);
//  3. its value digest is the digest of p's binding fields with its source;
//  4. its voter generation is one this node has adopted, with members, and
//     not one a forced reconfiguration replaced; and a majority of DISTINCT
//     members of it signed at one ballot, each with the incarnation its entry
//     records;
//  5. every counted accept's certificate chains to the cluster CA, names the
//     voter, is not revoked, and its signature verifies.
//
// It reads nothing but this node's own replica and makes no RPC: execution
// stays independent of voter reachability beyond the quorum ExecutionGate
// already requires. Signatures are what make that safe — a certificate in a
// replicated row can be written by any peer, and without them a forged row
// could name any voters.
func VerifyClaimCertificate(ctx context.Context, c *Client, v *ClaimVerifier, p ActionProof) (ClaimCertificate, error) {
	if p.ClaimCertificate == "" {
		return ClaimCertificate{}, fmt.Errorf("proof %s carries no recovery-claim certificate", p.ID)
	}
	cert, err := CertificateAuthorizesProof(p.ClaimCertificate, p)
	if err != nil {
		return cert, err
	}
	adopted, err := AdoptedVoterGeneration(ctx, c)
	if err != nil {
		return cert, fmt.Errorf("read the adopted voter generation: %w", err)
	}
	if cert.ConfigGeneration < 1 || cert.ConfigGeneration > adopted {
		return cert, fmt.Errorf("certificate is at voter generation %d, which this node has not adopted (adopted %d)",
			cert.ConfigGeneration, adopted)
	}
	if forced, err := ReplacedByForcedGeneration(ctx, c, cert.ConfigGeneration); err != nil {
		return cert, err
	} else if forced > 0 {
		return cert, fmt.Errorf("certificate is at voter generation %d, which forced generation %d replaced; "+
			"it executes only once re-certified at %d or later", cert.ConfigGeneration, forced, forced)
	}
	cfg, err := GetVoterConfig(ctx, c, cert.ConfigGeneration)
	if err != nil {
		return cert, err
	}
	if !cfg.Explicit() {
		return cert, fmt.Errorf("voter generation %d has no members to have certified anything", cert.ConfigGeneration)
	}
	err = v.Verify(cert, CertExpectation{
		Key: cert.Key, ValueDigest: cert.ValueDigest, ConfigGeneration: cert.ConfigGeneration,
		Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members)),
	})
	return cert, err
}

// ClaimGatedAction reports whether a proof of this action transfers ownership
// to a new destination and so needs a recovery-claim certificate once
// recovery_claim_v1 is enforced (§9 Q7): reschedule, promote and relocate. LB
// apply and owner assert stay on their current gates — neither transfers
// ownership. A relocate an OWNER drives (container cold migration, the source
// alive and moving its own workload) is exempted by the caller, which is the
// one that can tell the two apart.
func ClaimGatedAction(action string) bool {
	switch action {
	case ActionReschedule, ActionPromote, ActionRelocate:
		return true
	}
	return false
}

// ClaimCertificateReplaces reports whether certificate next may take the place
// of current on one proof row. An empty current is replaced by anything that
// decodes; otherwise next must certify the same value and be at a LATER voter
// generation — the re-certification a forced reconfiguration requires (§4.6).
// Anything else leaves the row as it is.
func ClaimCertificateReplaces(current, next string) bool {
	if next == "" || next == current {
		return false
	}
	n, err := DecodeClaimCertificate(next)
	if err != nil {
		return false
	}
	if current == "" {
		return true
	}
	c, err := DecodeClaimCertificate(current)
	if err != nil {
		return true // a row whose certificate does not even parse certifies nothing
	}
	return n.ValueDigest == c.ValueDigest && n.Key == c.Key && n.ConfigGeneration > c.ConfigGeneration
}

// betterClaimCertificate is the merge's choice between two copies of one
// proof's certificate: the one that replaces the other, and otherwise the
// greater encoding, so two replicas holding different certificates for one
// decision settle on the same one (the voter_configs rule, §4.1).
func betterClaimCertificate(a, b string) string {
	switch {
	case a == b:
		return a
	case ClaimCertificateReplaces(a, b):
		return b
	case ClaimCertificateReplaces(b, a):
		return a
	case a == "":
		return b
	case b == "":
		return a
	case a > b:
		return a
	default:
		return b
	}
}

// updateProofCertificateSQL is the one statement that changes a proof's
// certificate after the row exists.
const updateProofCertificateSQL = `UPDATE runtime_action_proofs SET claim_certificate = ?, updated_at = ?
	WHERE id = ? AND deleted_at IS NULL`

// SetProofClaimCertificate records p.ClaimCertificate on the existing row for
// p.ID, under a guard that the row's binding is p's and that the certificate
// replaces the one it holds (ClaimCertificateReplaces). ErrNoRowsAffected when
// there is nothing to do or the guard refuses; ErrProofDiverges when the row
// binds something else.
func SetProofClaimCertificate(ctx context.Context, c *Client, p ActionProof) error {
	if p.ClaimCertificate == "" {
		return ErrNoRowsAffected
	}
	if _, err := CertificateAuthorizesProof(p.ClaimCertificate, p); err != nil {
		return fmt.Errorf("%w: %v", ErrProofDiverges, err)
	}
	if !c.MayEmitClaimCertificate() {
		return fmt.Errorf("%w (proof %s)", ErrClaimCertificateNotEmittable, p.ID)
	}
	var diverges bool
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		var existing ActionProof
		var cert string
		err := tx.QueryRow(
			`SELECT action, target_kind, target_name, dest_host, coordinator,
			        relocation_token, fence_epoch, owner_epoch, lease_term, lease_key, claim_certificate
			   FROM runtime_action_proofs WHERE id = ? AND deleted_at IS NULL`, p.ID).
			Scan(&existing.Action, &existing.TargetKind, &existing.TargetName,
				&existing.DestHost, &existing.Coordinator, &existing.RelocationToken,
				&existing.FenceEpoch, &existing.OwnerEpoch, &existing.LeaseTerm,
				&existing.LeaseKey, &cert)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !ProofBindingEqual(existing, p) {
			diverges = true
			return false, nil
		}
		return ClaimCertificateReplaces(cert, p.ClaimCertificate), nil
	}, []Statement{{SQL: updateProofCertificateSQL, Params: []interface{}{p.ClaimCertificate, c.NowTS(), p.ID}}})
	if err != nil {
		return err
	}
	if diverges {
		return ErrProofDiverges
	}
	if !applied {
		return ErrNoRowsAffected
	}
	return nil
}

// updateProofClaimCertificateLocal folds the merge's chosen certificate into
// the surviving local row (the step_state fold's twin, updateProofStepState).
func (c *Client) updateProofClaimCertificateLocal(tx *sql.Tx, tableName string, pkCols []string, pkIdx []int, incomingRow []interface{}, cert string) error {
	if len(pkCols) == 0 {
		return nil
	}
	where := make([]string, len(pkCols))
	args := make([]interface{}, 0, len(pkCols)+1)
	args = append(args, cert)
	for i, col := range pkCols {
		where[i] = col + " = ?"
		if i < len(pkIdx) && pkIdx[i] >= 0 && pkIdx[i] < len(incomingRow) {
			args = append(args, incomingRow[pkIdx[i]])
		}
	}
	q := "UPDATE " + tableName + " SET claim_certificate = ? WHERE " + strings.Join(where, " AND ")
	if _, err := tx.Exec(q, args...); err != nil {
		return fmt.Errorf("fold claim_certificate into local proof on %s: %w", tableName, err)
	}
	return nil
}
