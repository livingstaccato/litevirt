package corrosion

import (
	"context"
	"database/sql"
	"encoding/json"
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
// its attempt, which the certificate itself names (§3.10 step 2), and less
// its incarnation, which a proof does not carry: that is bound against the
// destination's own workload row (VerifyClaimCertificate). The key it returns
// is a legacy one; WithIncarnation scopes it.
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
	if !cert.Key.SameDecision(want) {
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
	if err := certificateIncarnationIsLive(ctx, c, cert.Key); err != nil {
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

// WorkloadIncarnation is the incarnation of the live workload row for
// (kind, name) in c's replica — its created_at (§10 item 37). ok is false
// when there is no live row, or when live rows of the name disagree about
// their incarnation (two containers' rows mid-heal), since then no single
// incarnation can be named.
func WorkloadIncarnation(ctx context.Context, c *Client, kind, name string) (string, bool, error) {
	var q string
	switch kind {
	case ClaimKindVM:
		q = `SELECT DISTINCT COALESCE(created_at, '') AS created_at FROM vms WHERE name = ? AND deleted_at IS NULL`
	case ClaimKindContainer:
		q = `SELECT DISTINCT COALESCE(created_at, '') AS created_at FROM containers WHERE name = ? AND deleted_at IS NULL`
	default:
		return "", false, fmt.Errorf("no workload rows for target kind %q", kind)
	}
	rows, err := c.Query(ctx, q, name)
	if err != nil || len(rows) != 1 || rows[0].String("created_at") == "" {
		return "", false, err
	}
	return rows[0].String("created_at"), true, nil
}

// certificateIncarnationIsLive is the destination's half of the incarnation
// binding (§10 item 37): a certificate at an incarnation-scoped key authorizes
// a proof only for the incarnation it names, so this node's own live row for
// the target must be that incarnation. A re-created workload whose row has
// replicated here is a different incarnation, and nothing a previous one
// decided runs for it.
//
// A legacy key names no incarnation and is accepted as before: it is what
// every certificate minted before claim_incarnation_v1 latched carries, and
// refusing them would strand every recovery decided across the upgrade.
func certificateIncarnationIsLive(ctx context.Context, c *Client, key ClaimKey) error {
	if key.Incarnation == "" {
		return nil
	}
	inc, ok, err := WorkloadIncarnation(ctx, c, key.TargetKind, key.TargetName)
	if err != nil {
		return fmt.Errorf("read the incarnation of %s/%s: %w", key.TargetKind, key.TargetName, err)
	}
	if !ok {
		return fmt.Errorf("certificate decides %s, and this node has no single live %s/%s row to bind it to",
			key, key.TargetKind, key.TargetName)
	}
	if inc != key.Incarnation {
		return fmt.Errorf("certificate decides incarnation %s of %s/%s, but the live row here is incarnation %s",
			key.Incarnation, key.TargetKind, key.TargetName, inc)
	}
	return nil
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

// SetClaimCertificateVerifier injects the verifier proof certificates are
// judged with before one replaces another (grpcapi.NewServer wires the
// server's claim verifier). Unset, or returning nil, nothing verifies, so a
// certificate a row already holds is never replaced.
func (c *Client) SetClaimCertificateVerifier(fn func() *ClaimVerifier) {
	c.claimCertVerifier.Store(&fn)
}

func (c *Client) claimCertificateVerifier() *ClaimVerifier {
	fn := c.claimCertVerifier.Load()
	if fn == nil || *fn == nil {
		return nil
	}
	return (*fn)()
}

// certificateVerifiesTx reports whether raw verifies on THIS node, reading
// through tx: it decodes, is at a generation this node has adopted that no
// adopted forced generation replaced, and carries a majority of that
// generation's members' valid signatures (VerifyClaimCertificate's checks
// minus the proof binding, which the callers compare separately). It is the
// judge of which of two certificates for one proof a row keeps.
func (c *Client) certificateVerifiesTx(tx *sql.Tx, raw string) bool {
	v := c.claimCertificateVerifier()
	if v == nil || raw == "" {
		return false
	}
	cert, err := DecodeClaimCertificate(raw)
	if err != nil || cert.ConfigGeneration < 1 {
		return false
	}
	var adopted, forced int64
	if err := tx.QueryRow(`SELECT COALESCE(MAX(generation), 0) FROM local_voter_adoption`).Scan(&adopted); err != nil ||
		cert.ConfigGeneration > adopted {
		return false
	}
	if err := tx.QueryRow(`SELECT COUNT(*) FROM voter_configs
		WHERE deleted_at IS NULL AND generation > ? AND generation <= ? AND change LIKE 'force:%'`,
		cert.ConfigGeneration, adopted).Scan(&forced); err != nil || forced > 0 {
		return false
	}
	var membersJSON string
	if err := tx.QueryRow(`SELECT members_json FROM voter_configs WHERE generation = ? AND deleted_at IS NULL`,
		cert.ConfigGeneration).Scan(&membersJSON); err != nil {
		return false
	}
	var members []VoterMember
	if err := json.Unmarshal([]byte(membersJSON), &members); err != nil || len(members) == 0 {
		return false
	}
	return v.Verify(cert, CertExpectation{Key: cert.Key, ValueDigest: cert.ValueDigest,
		ConfigGeneration: cert.ConfigGeneration, Electorate: members, Quorum: MajorityOf(len(members))}) == nil
}

// ClaimCertificateReplaces reports whether certificate next may take the place
// of current on one proof row, with verifies judging a certificate on this
// node (certificateVerifiesTx). An empty or unparseable current is replaced
// by anything that decodes: it certifies nothing, and a genuine certificate
// replaces a forged one later. Otherwise next must certify the same key and
// value AND verify here, and then replaces a current that does not verify
// here (a forgery, or one at a generation a forced change replaced), or one
// at an earlier generation — the re-certification a forced reconfiguration
// requires (§4.6). A certificate that does not verify never replaces one: an
// unsigned "generation 999" would otherwise overwrite a genuine certificate
// cluster-wide and every destination would refuse the recovery forever.
func ClaimCertificateReplaces(current, next string, verifies func(string) bool) bool {
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
	// The same decision, at the same incarnation — or a legacy certificate
	// re-certified at its incarnation-scoped key after claim_incarnation_v1
	// latched (the bridge, §10 item 37). Never the reverse, and never across
	// incarnations.
	sameKey := n.Key == c.Key || (c.Key.Incarnation == "" && n.Key.SameDecision(c.Key))
	if n.ValueDigest != c.ValueDigest || !sameKey || !verifies(next) {
		return false
	}
	return !verifies(current) || n.ConfigGeneration > c.ConfigGeneration
}

// betterClaimCertificate is the merge's choice between two copies of one
// proof's certificate: the one that replaces the other; otherwise the one
// that verifies here; otherwise the greater encoding. Nodes that have adopted
// the same generations and CRL therefore choose the same copy. Nodes that
// have not can choose differently for a while — the one behind cannot verify
// a certificate at a generation it has not adopted — but the rows then still
// differ, so the next anti-entropy pass merges them again, and once the
// lagging node has adopted it chooses the same copy.
func betterClaimCertificate(a, b string, verifies func(string) bool) string {
	switch {
	case a == b:
		return a
	case ClaimCertificateReplaces(a, b, verifies):
		return b
	case ClaimCertificateReplaces(b, a, verifies):
		return a
	case a == "":
		return b
	case b == "":
		return a
	}
	if va, vb := verifies(a), verifies(b); va != vb {
		if va {
			return a
		}
		return b
	}
	if a > b {
		return a
	}
	return b
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
		return ClaimCertificateReplaces(cert, p.ClaimCertificate, func(raw string) bool {
			return c.certificateVerifiesTx(tx, raw)
		}), nil
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

// UncertifiedPendingProofs lists the pending ownership-transfer proofs that
// carry no recovery-claim certificate: reschedules and relocations minted
// before recovery claims were enforced (the latch forming, genesis, or
// `lv cluster voter init` after a reset). Under enforcement a destination
// refuses every one (recovery_claim_unproven), so the lease holder claims each
// for its own value (failover's certifyUncertified) and reports it while it
// waits (ha.claim.uncertified). One query, so the two read one set.
func UncertifiedPendingProofs(ctx context.Context, c *Client) ([]ProofRecord, error) {
	rows, err := c.Query(ctx, `SELECT id FROM runtime_action_proofs
		WHERE deleted_at IS NULL AND status = 'prepared' AND claim_certificate = ''
		  AND action IN ('reschedule', 'relocate') ORDER BY id`)
	if err != nil {
		return nil, err
	}
	var out []ProofRecord
	for _, r := range rows {
		pr, ok, err := GetActionProof(ctx, c, r.String("id"))
		if err != nil {
			return nil, err
		}
		if ok && pr.ClaimCertificate == "" {
			out = append(out, pr)
		}
	}
	return out, nil
}

// UncertifiedProofSource is the old owner a claim for an uncertified proof
// names: the host its proof-grade fence binding (fence_epoch) records, the
// owner the proof was minted to evict. ok=false when the proof carries none;
// no claim can then name an owner for the voters to probe, so none is made.
// It is never inferred from timestamps or from whichever host is fenced now:
// a lagging coordinator could forge "minted before", and a wrong source is a
// probe of the wrong host.
func UncertifiedProofSource(p ActionProof) (string, bool) {
	ref, ok := ParseFenceEpoch(p.FenceEpoch)
	if !ok || ref.Host == "" {
		return "", false
	}
	return ref.Host, true
}
