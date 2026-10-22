package corrosion

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// MaxAutomationRecordBytes includes the complete value AND quorum certificate.
// Readiness must bound electorate/certificate capacity before admission.
const MaxAutomationRecordBytes = 3 << 20

var errAutomationAuthority = errors.New("automation authority unavailable")

// automationProofCorruptionError marks validation of a present stored proof.
// Database and context errors must remain unwrapped at the read boundary.
type automationProofCorruptionError struct{ cause error }

func (e *automationProofCorruptionError) Error() string { return e.cause.Error() }
func (e *automationProofCorruptionError) Unwrap() error { return e.cause }

// AutomationPrefix is certified AND transactionally applied progress.
type AutomationPrefix = contract.Prefix

// AutomationRecord transports one bounded complete decision and its certificate.
// Membership and trust roots are always selected locally, never by this record.
type AutomationRecord struct {
	Value       ClaimValue
	Certificate ClaimCertificate
}
type AutomationRequest = contract.Request
type AutomationProjection = contract.Projection
type AutomationReduction = contract.Reduction
type AutomationReducer func(AutomationProjection, contract.Decision) (AutomationReduction, error)

const automationHeadSQL = `SELECT cluster_uid, sequence, digest FROM local_automation_prefix WHERE id=1`

func automationHeadTx(ctx context.Context, tx *LocalTx) (AutomationPrefix, error) {
	rows, e := tx.Query(ctx, automationHeadSQL)
	if e != nil || len(rows) == 0 {
		return AutomationPrefix{}, e
	}
	r := rows[0]
	return AutomationPrefix{ClusterUID: r.String("cluster_uid"), Sequence: uint64(r.Int64("sequence")), Digest: r.String("digest")}, nil
}
func (c *Client) AutomationHead(ctx context.Context) (h AutomationPrefix, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error { var err error; h, err = automationHeadTx(ctx, tx); return err })
	return
}

// Established membership/custody and fresh projection authority are separate.
// The admission owner may use this helper for historical recertification only
// after retained certified H and the exact anchored digest are checked.
func automationEstablishedAuthorityTx(ctx context.Context, tx *LocalTx, self string, gen int64) (*VoterConfig, error) {
	st, e := readStandingTx(ctx, tx, self)
	if e != nil {
		return nil, e
	}
	if st.adopted != gen || st.cfg == nil || !st.cfg.Explicit() || len(st.cfg.Members) < 3 || automationElectorateBudget(st.cfg.Members) != nil {
		return nil, errAutomationAuthority
	}
	rows, e := tx.Query(ctx, `SELECT generation,members_hash,incarnation,bootstrap_principal,bootstrap_request,provenance FROM local_automation_authority WHERE id=1`)
	if e != nil {
		return nil, e
	}
	if len(rows) != 1 {
		return nil, errAutomationAuthority
	}
	r := rows[0]
	// There is deliberately no production writer until verified cutover/custody
	// evidence is supplied by Task5 and the later feature prerequisites.
	if r.Int64("generation") != gen || r.String("members_hash") != MembersHash(st.cfg.Members) || r.String("incarnation") != st.incarnation || r.String("provenance") == "" {
		return nil, errAutomationAuthority
	}
	return st.cfg, nil
}
func automationAuthorityTx(ctx context.Context, tx *LocalTx, self string, gen int64) (*VoterConfig, error) {
	cfg, err := automationEstablishedAuthorityTx(ctx, tx, self, gen)
	if err != nil {
		return nil, err
	}
	if err := automationProjectionAuthorityTx(ctx, tx); err != nil {
		return nil, err
	}
	return cfg, nil
}
func (c *Client) AutomationMembership(ctx context.Context) (cfg *VoterConfig, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		st, err := readStandingTx(ctx, tx, c.hostName)
		if err != nil {
			return err
		}
		cfg, err = automationAuthorityTx(ctx, tx, c.hostName, st.adopted)
		return err
	})
	return
}
func (c *Client) AutomationRecord(ctx context.Context, seq uint64) (out AutomationRecord, found bool, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if seq == 0 {
			h, err := automationHeadTx(ctx, tx)
			if err != nil {
				return err
			}
			seq = h.Sequence
		}
		if seq == 0 {
			return nil
		}
		rs, err := tx.Query(ctx, `SELECT value_json,certificate FROM local_automation_history WHERE sequence=? LIMIT 1`, seq)
		if err != nil || len(rs) == 0 {
			return err
		}
		if err = json.Unmarshal([]byte(rs[0].String("value_json")), &out.Value); err != nil {
			return err
		}
		out.Certificate, err = DecodeClaimCertificate(rs[0].String("certificate"))
		found = err == nil
		return err
	})
	return
}
func AutomationScope(d contract.Decision) string { return contract.Scope(d) }
func automationRequestTx(ctx context.Context, tx *LocalTx, scope, request string) (*AutomationRequest, error) {
	rs, e := tx.Query(ctx, `SELECT identity,receipt_json FROM local_automation_requests WHERE scope=? AND request_id=? LIMIT 1`, scope, request)
	if e != nil || len(rs) == 0 {
		return nil, e
	}
	out := &AutomationRequest{Identity: rs[0].Bytes("identity")}
	e = json.Unmarshal([]byte(rs[0].String("receipt_json")), &out.Receipt)
	return out, e
}
func (c *Client) AutomationRequest(ctx context.Context, scope, request string) (out *AutomationRequest, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var err error
		out, err = automationRequestTx(ctx, tx, scope, request)
		return err
	})
	return
}

// AutomationApply verifies fresh authority before creating a durable local
// anchor. The transaction rechecks adopted membership and all affected keys.
func (c *Client) AutomationApply(ctx context.Context, r AutomationRecord, v *ClaimVerifier, reduce AutomationReducer) (contract.Receipt, error) {
	return c.AutomationApplyOwned(ctx, &r, v, reduce)
}

// AutomationApplyOwned transfers a certified historical transition to the
// existing durable recovery owner before opening referenced originals. Callers
// must release their other full-record/decoded aliases before entering. A value
// caller of AutomationApply still owns its external input; this internal bound
// does not claim to collect memory retained by an external caller.
// Before handoff errors leave owned untouched. After handoff an error leaves
// owned empty. The authenticated recovery job remains retryable until completion;
// after completion, the original record is instead owned by durable history.
// Success restores the record for callers that forward its certificate.
func (c *Client) AutomationApplyOwned(ctx context.Context, owned *AutomationRecord, v *ClaimVerifier, reduce AutomationReducer) (contract.Receipt, error) {
	if owned == nil {
		return contract.Receipt{}, fmt.Errorf("missing owned automation record")
	}
	r := *owned
	if err := validateAutomationRecordSize(r); err != nil {
		return contract.Receipt{}, err
	}
	d, e := automationDecision(r.Value)
	if e != nil {
		return contract.Receipt{}, e
	}
	digest, e := r.Value.Digest()
	if e != nil {
		return contract.Receipt{}, e
	}
	cfg, e := c.AutomationMembership(ctx)
	if e != nil {
		return contract.Receipt{}, e
	}
	key, _ := AutomationClaimKey(d.Sequence)
	if e = v.Verify(r.Certificate, CertExpectation{Key: key, ValueDigest: digest, ConfigGeneration: cfg.Generation, Electorate: cfg.Members, Quorum: MajorityOf(len(cfg.Members))}); e != nil {
		return contract.Receipt{}, e
	}
	if r.Value.Automation != nil {
		automationObserveKeyBody(ctx, d.Sequence, r.Value.Automation.Envelope)
	}
	request, e := automationPrepareKeyLookup(ctx, d, r.Certificate)
	if e != nil {
		return contract.Receipt{}, e
	}
	if request != nil {
		if request.configDigest != cfg.MembersHash {
			return contract.Receipt{}, fmt.Errorf("key transition differs from original certified config")
		}
		head, e := c.AutomationHead(ctx)
		if e != nil {
			return contract.Receipt{}, e
		}
		if d.Sequence > head.Sequence {
			if e = validateAutomationPredecessor(head, d); e != nil {
				return contract.Receipt{}, e
			}
			sequence := d.Sequence
			if e = c.AutomationBeginRecovery(ctx, r, v); e != nil {
				return contract.Receipt{}, e
			}
			if e = c.automationMatchingRecovery(ctx, sequence, digest, cfg.Generation, cfg.MembersHash); e != nil {
				return contract.Receipt{}, e
			}
			// The durable owner now survives cancellation, rollback and a closed DB.
			// Drop all copies in this frame and the controlled caller before resolving.
			*owned = AutomationRecord{}
			r = AutomationRecord{}
			d = contract.Decision{}
			if e = c.AutomationFinishRecovery(ctx, reduce, 2); e != nil {
				return contract.Receipt{}, e
			}
			var receipt contract.Receipt
			e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				rows, e := tx.Query(ctx, `SELECT receipt_json FROM local_automation_history WHERE sequence=? AND digest=? LIMIT 1`, sequence, digest)
				if e != nil {
					return e
				}
				if len(rows) != 1 {
					return fmt.Errorf("completed owned record missing")
				}
				return json.Unmarshal([]byte(rows[0].String("receipt_json")), &receipt)
			})
			if e != nil {
				return contract.Receipt{}, e
			}
			restored, found, e := c.AutomationRecord(ctx, sequence)
			if e != nil {
				return contract.Receipt{}, e
			}
			if !found {
				return contract.Receipt{}, fmt.Errorf("completed owned record unavailable")
			}
			*owned = restored
			return receipt, nil
		}
	}
	return c.automationApply(ctx, r, d, digest, cfg, reduce, false)
}

// These private origins distinguish freshly verified authority, ancestry of a
// verified recovery checkpoint, and replay from already durable local anchors.
// Only verification callers construct provenance; no peer trust flag is used.
type automationApplicationKind uint8

const (
	automationFreshAnchor automationApplicationKind = iota + 1
	automationStagedAnchor
	automationAnchoredReplay
)

type automationApplicationProvenance struct {
	kind        automationApplicationKind
	sequence    uint64
	generation  int64
	membersHash string
	certificate string
}

func (c *Client) automationApply(ctx context.Context, r AutomationRecord, d contract.Decision, digest string, cfg *VoterConfig, reduce AutomationReducer, replay bool) (out contract.Receipt, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		source := automationApplicationProvenance{kind: automationAnchoredReplay}
		if !replay {
			current, err := automationAuthorityTx(ctx, tx, c.hostName, cfg.Generation)
			if err != nil {
				return err
			}
			if MembersHash(current.Members) != MembersHash(cfg.Members) {
				return fmt.Errorf("automation membership changed")
			}
			source = automationApplicationProvenance{kind: automationFreshAnchor, sequence: d.Sequence, generation: cfg.Generation, membersHash: MembersHash(cfg.Members)}
		}
		var err error
		out, err = automationApplyTx(ctx, tx, r, d, digest, reduce, source, nil)
		return err
	})
	if e != nil {
		out = contract.Receipt{}
	}
	return
}

// automationApplyTx is the sole reducer/application persistence path. History,
// anchors, permanent receipts, typed projections and prefix share this FULL tx.
func automationApplyTx(ctx context.Context, tx *LocalTx, r AutomationRecord, d contract.Decision, digest string, reduce AutomationReducer, source automationApplicationProvenance, prepared *contract.KeyTransitionProjection) (out contract.Receipt, e error) {
	defer func() {
		if e != nil {
			out = contract.Receipt{}
		}
	}()
	if err := requireAutomationFull(ctx, tx); err != nil {
		return out, err
	}
	switch source.kind {
	case automationFreshAnchor:
		if source.sequence != d.Sequence {
			return out, fmt.Errorf("invalid fresh automation provenance")
		}
	case automationStagedAnchor:
		if source.sequence < d.Sequence || source.certificate == "" {
			return out, fmt.Errorf("invalid staged automation provenance")
		}
	case automationAnchoredReplay:
	default:
		return out, fmt.Errorf("missing verified automation provenance")
	}
	if source.kind != automationAnchoredReplay && (source.generation <= 0 || source.membersHash == "") {
		return out, fmt.Errorf("invalid automation anchor provenance")
	}
	head, err := automationHeadTx(ctx, tx)
	if err != nil {
		return out, err
	}
	trusted := head
	if source.kind == automationAnchoredReplay {
		head, err = automationSemanticHeadTx(ctx, tx, "")
		if err != nil {
			return out, err
		}
		if head.Sequence > trusted.Sequence {
			return out, fmt.Errorf("replay cursor exceeds retained certified prefix")
		}
	}
	if d.Sequence <= head.Sequence {
		rows, err := tx.Query(ctx, `SELECT digest,receipt_json FROM local_automation_history WHERE sequence=? LIMIT 1`, d.Sequence)
		if err != nil {
			return out, err
		}
		if len(rows) != 1 || rows[0].String("digest") != digest {
			return out, fmt.Errorf("automation history diverged")
		}
		err = json.Unmarshal([]byte(rows[0].String("receipt_json")), &out)
		return out, err
	}
	if err := validateAutomationPredecessor(head, d); err != nil {
		return out, err
	}
	if head.Sequence == 0 && source.kind == automationAnchoredReplay {
		if err := automationResetSemanticProjectionTx(ctx, tx, ""); err != nil {
			return out, err
		}
	}
	projection, err := automationProjectionTx(ctx, tx, head, d, prepared)
	if err != nil {
		return out, err
	}
	// The compatibility callback may refuse, but only the concrete evaluator
	// supplies the reduction used for persistence.
	if reduce == nil {
		return out, fmt.Errorf("automation reducer unavailable")
	}
	callbackProjection := cloneAutomationProjection(projection)
	callback, err := reduce(callbackProjection, d)
	if err != nil {
		return out, err
	}
	var expected *contract.Receipt
	if source.kind == automationAnchoredReplay {
		rows, err := tx.Query(ctx, `SELECT receipt_json FROM local_automation_history WHERE sequence=? AND digest=? LIMIT 1`, d.Sequence, digest)
		if err != nil {
			return out, err
		}
		if len(rows) != 1 {
			return out, fmt.Errorf("automation replay result missing")
		}
		expected = new(contract.Receipt)
		if err = json.Unmarshal([]byte(rows[0].String("receipt_json")), expected); err != nil {
			return out, err
		}
	}
	result, next, err := evaluateAutomationHistory(automationHistoryInput{Projection: projection, Value: r.Value, Digest: digest, Expected: expected})
	if err != nil {
		return out, err
	}
	if err = validateAutomationCallback(result, callback); err != nil {
		return out, err
	}
	out = result.Receipt
	receipt, err := json.Marshal(out)
	if err != nil {
		return out, err
	}
	value, err := json.Marshal(r.Value)
	if err != nil || len(value) > MaxAutomationClaimBytes {
		return out, fmt.Errorf("automation value too large")
	}
	cert, err := r.Certificate.Encode()
	if err != nil {
		return out, err
	}
	if source.kind != automationAnchoredReplay {
		if source.kind == automationFreshAnchor {
			_, err = tx.Exec(ctx, `INSERT INTO local_automation_anchors (sequence,digest,generation,members_hash,certificate) VALUES (?,?,?,?,?) ON CONFLICT(sequence) DO UPDATE SET certificate=excluded.certificate WHERE digest=excluded.digest`, d.Sequence, digest, source.generation, source.membersHash, cert)
		} else {
			_, err = tx.Exec(ctx, `INSERT INTO local_automation_anchors (sequence,digest,generation,members_hash,certificate) VALUES (?,?,?,?,?)`, d.Sequence, digest, source.generation, source.membersHash, source.certificate)
		}
		if err != nil {
			return out, err
		}
		if _, err = tx.Exec(ctx, `INSERT INTO local_automation_history (sequence,digest,value_json,certificate,receipt_json,anchor_sequence) VALUES (?,?,?,?,?,?)`, d.Sequence, digest, string(value), cert, string(receipt), source.sequence); err != nil {
			return out, err
		}

	}

	if err := automationApplySemanticEffectsTx(ctx, tx, "", head, next, result); err != nil {
		return out, err
	}
	if result.SaveRequest {
		if _, err = tx.Exec(ctx, `INSERT INTO local_automation_requests (scope,request_id,identity,receipt_json,operation_id) VALUES (?,?,?,?,?)`, result.Scope, d.Command.RequestID, result.Identity, string(receipt), out.OperationID); err != nil {
			return out, err
		}
	}
	if source.kind == automationAnchoredReplay && next.Sequence <= trusted.Sequence {
		return out, nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_prefix (id,cluster_uid,sequence,digest) VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET cluster_uid=excluded.cluster_uid,sequence=excluded.sequence,digest=excluded.digest`, next.ClusterUID, next.Sequence, next.Digest)
	return out, err
}

// AutomationReplay rebuilds projections only from locally durable authenticated
// anchors. Each query and transaction holds one bounded record, never history.
func (c *Client) AutomationReplay(ctx context.Context, reduce AutomationReducer, budget int) error {
	if budget <= 0 {
		return fmt.Errorf("automation replay budget exhausted")
	}
	// Keep the certified frontier while rebuilding derived state. A partial
	// semantic cursor is never a new genesis or a fresh admission frontier.
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		semantic, err := automationSemanticHeadTx(ctx, tx, "")
		if err != nil {
			return err
		}
		retained, err := automationRetainedHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		for _, marker := range []AutomationPrefix{head, semantic} {
			if marker.Sequence == 0 {
				continue
			}
			digest, found, err := automationTrustedDigestTx(ctx, tx, marker.Sequence)
			if err != nil {
				return err
			}
			if !found || digest != marker.Digest || marker.ClusterUID != retained.ClusterUID {
				return fmt.Errorf("unanchored semantic reconstruction boundary")
			}
		}
		if head.Sequence > retained.Sequence || semantic.Sequence > retained.Sequence {
			return fmt.Errorf("reconstruction beyond retained history")
		}
		if head != retained {
			if _, err := tx.Exec(ctx, `INSERT INTO local_automation_prefix(id,cluster_uid,sequence,digest) VALUES(1,?,?,?) ON CONFLICT(id) DO UPDATE SET cluster_uid=excluded.cluster_uid,sequence=excluded.sequence,digest=excluded.digest`, retained.ClusterUID, retained.Sequence, retained.Digest); err != nil {
				return err
			}
		}
		if (semantic.Sequence == 0 || head != retained) && retained.Sequence > 0 {
			return automationResetSemanticProjectionTx(ctx, tx, "")
		}
		return nil
	}); err != nil {
		return err
	}

	for range budget {
		complete := false
		e := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			head, e := automationSemanticHeadTx(ctx, tx, "")
			if e != nil {
				return e
			}
			rows, e := tx.Query(ctx, `SELECT h.digest,a.digest AS anchor_digest FROM local_automation_history h JOIN local_automation_anchors a ON a.sequence=h.sequence WHERE h.sequence=? LIMIT 1`, head.Sequence+1)
			if e != nil {
				return e
			}
			if len(rows) == 0 {
				complete = true
				return automationProjectionAuthorityTx(ctx, tx)
			}
			if rows[0].String("digest") != rows[0].String("anchor_digest") {
				return fmt.Errorf("automation anchor mismatch")
			}
			_, e = automationApplyStoredTx(ctx, tx, head.Sequence+1, rows[0].String("digest"), reduce, automationApplicationProvenance{kind: automationAnchoredReplay}, false)
			return e
		})
		if e != nil {
			return e
		}
		if complete {
			return nil
		}
	}

	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationProjectionAuthorityTx(ctx, tx) }); err == nil {
		return nil
	}
	return fmt.Errorf("automation replay budget exhausted")
}

// Projection authority is independent of custody/class permits: a voter with
// valid generic authority still cannot admit against incomplete derived state.
func automationProjectionAuthorityTx(ctx context.Context, tx *LocalTx) error {
	head, err := automationHeadTx(ctx, tx)
	if err != nil {
		return err
	}
	semantic, err := automationSemanticHeadTx(ctx, tx, "")
	if err != nil {
		return err
	}
	if head != semantic {
		return errAutomationAuthority
	}
	rows, err := tx.Query(ctx, `SELECT sequence FROM local_automation_history ORDER BY sequence DESC LIMIT 1`)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if head.Sequence != 0 {
			return errAutomationAuthority
		}
		return nil
	}
	if rows[0].Int64("sequence") <= 0 || uint64(rows[0].Int64("sequence")) != head.Sequence {
		return errAutomationAuthority
	}
	digest, found, err := automationTrustedDigestTx(ctx, tx, head.Sequence)
	if err != nil {
		return err
	}
	if !found || digest != head.Digest {
		return errAutomationAuthority
	}
	return nil
}
func automationRetainedHeadTx(ctx context.Context, tx *LocalTx) (AutomationPrefix, error) {
	rows, err := tx.Query(ctx, `SELECT sequence FROM local_automation_history ORDER BY sequence DESC LIMIT 1`)
	if err != nil || len(rows) == 0 {
		return AutomationPrefix{}, err
	}
	sequence := rows[0].Int64("sequence")
	if sequence <= 0 {
		return AutomationPrefix{}, fmt.Errorf("invalid retained automation sequence")
	}
	if sequence > 1 {
		head, found, err := automationTrustedSummaryTx(ctx, tx, uint64(sequence))
		if err != nil {
			return AutomationPrefix{}, err
		}
		if !found {
			return AutomationPrefix{}, fmt.Errorf("retained automation anchor missing")
		}
		return head, nil
	}
	digest, found, err := automationTrustedDigestTx(ctx, tx, uint64(sequence))
	if err != nil {
		return AutomationPrefix{}, err
	}
	if !found {
		return AutomationPrefix{}, fmt.Errorf("retained automation anchor missing")
	}
	rows, err = tx.Query(ctx, `SELECT value_json FROM local_automation_history WHERE sequence=? AND length(CAST(value_json AS BLOB))<=? LIMIT 1`, sequence, MaxAutomationClaimBytes)
	if err != nil {
		return AutomationPrefix{}, err
	}
	if len(rows) != 1 {
		return AutomationPrefix{}, fmt.Errorf("retained automation value missing or oversized")
	}
	key, _ := AutomationClaimKey(uint64(sequence))
	var value ClaimValue
	if err := decodeClaimValue(key, rows[0].String("value_json"), &value); err != nil {
		return AutomationPrefix{}, err
	}
	decision, err := automationDecision(value)
	if err != nil {
		return AutomationPrefix{}, err
	}
	cluster := decision.Command.ClusterUID
	if sequence == 1 {
		assigned, err := contract.DecodeAssignment(decision)
		if err != nil {
			return AutomationPrefix{}, err
		}
		cluster = assigned.ClusterUID
	}
	return AutomationPrefix{ClusterUID: cluster, Sequence: uint64(sequence), Digest: digest}, nil
}
func automationOperationTx(ctx context.Context, tx *LocalTx, id string) (*contract.Receipt, error) {
	if id == "" {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `SELECT receipt_json FROM local_automation_requests WHERE operation_id=? AND operation_id<>'' LIMIT 1`, id)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	var out contract.Receipt
	err = json.Unmarshal([]byte(rows[0].String("receipt_json")), &out)
	return &out, err
}
func automationProjectionTx(ctx context.Context, tx *LocalTx, head AutomationPrefix, d contract.Decision, prepared *contract.KeyTransitionProjection) (AutomationProjection, error) {
	existing, err := automationRequestTx(ctx, tx, AutomationScope(d), d.Command.RequestID)
	if err != nil {
		return AutomationProjection{}, err
	}
	assigned, err := contract.DecodeAssignment(d)
	if err != nil {
		return AutomationProjection{}, err
	}
	op, err := automationOperationTx(ctx, tx, assigned.OperationID)
	if err != nil {
		return AutomationProjection{}, err
	}
	p := AutomationProjection{Head: head, Existing: existing, Operation: op, ReplayOriginal: existing != nil && existing.Receipt.Sequence == d.Sequence, KeyTransition: prepared}
	if err := automationSemanticProjectionTx(ctx, tx, "", &p, d); err != nil {
		return AutomationProjection{}, err
	}
	return p, nil
}
func (c *Client) AutomationOperation(ctx context.Context, id string) (out contract.Receipt, found bool, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		r, err := automationOperationTx(ctx, tx, id)
		if r != nil {
			out = *r
			found = true
		}
		return err
	})
	return
}

// automationTrustedSummaryTx owns one original body for the duration of this
// call. Only copied scalar identity escapes; no envelope, row or decoded body
// survives into a subsequent original read. It does not confer fresh authority.
func automationTrustedSummaryTx(ctx context.Context, tx *LocalTx, sequence uint64) (AutomationPrefix, bool, error) {
	rows, err := tx.Query(ctx, `SELECT h.digest,h.value_json,a.digest AS anchor_digest FROM local_automation_history h JOIN local_automation_anchors a ON a.sequence=h.sequence WHERE h.sequence=? AND typeof(h.value_json)='text' AND typeof(h.digest)='text' AND typeof(a.digest)='text' AND length(CAST(h.value_json AS BLOB))<=? AND length(CAST(h.digest AS BLOB))=64 AND length(CAST(a.digest AS BLOB))=64 LIMIT 1`, sequence, MaxAutomationClaimBytes)
	if err != nil || len(rows) == 0 {
		return AutomationPrefix{}, false, err
	}
	row := rows[0]
	digest := row.String("digest")
	var value ClaimValue
	key, _ := AutomationClaimKey(sequence)
	if err := decodeClaimValue(key, row.String("value_json"), &value); err != nil {
		return AutomationPrefix{}, false, &automationProofCorruptionError{cause: err}
	}
	if sequence <= 1 {
		// Digest-only genesis callers historically validate the envelope, not
		// its typed assignment. Retained-head genesis still does both above.
		if err := validateAutomationTrustedValue(sequence, value, digest, row.String("anchor_digest")); err != nil {
			return AutomationPrefix{}, false, &automationProofCorruptionError{cause: err}
		}
		return AutomationPrefix{Sequence: sequence, Digest: digest}, true, nil
	}
	if digest != row.String("anchor_digest") {
		return AutomationPrefix{}, false, &automationProofCorruptionError{cause: fmt.Errorf("automation parent anchor mismatch")}
	}
	if _, err := AutomationClaimKey(sequence); err != nil {
		return AutomationPrefix{}, false, &automationProofCorruptionError{cause: err}
	}
	if value.Automation == nil || value.Proof != nil || value.Config != nil || value.LUN != nil || value.LeaseTerm != nil || value.SourceHost != "" {
		return AutomationPrefix{}, false, &automationProofCorruptionError{cause: fmt.Errorf("invalid automation alternative")}
	}
	// decodeClaimValue already checked the exact canonical outer bytes and
	// storage bound. Validate the inner codec once, then hash those exact bytes.
	decision, err := contract.DecodeDecision(value.Automation.Envelope)
	if err != nil {
		return AutomationPrefix{}, false, &automationProofCorruptionError{cause: fmt.Errorf("invalid automation envelope")}
	}
	if decision.Sequence != sequence {
		return AutomationPrefix{}, false, &automationProofCorruptionError{cause: fmt.Errorf("automation value does not match key")}
	}
	h := sha256.New()
	claimField(h, "litevirt-automation-decision-v1")
	claimField(h, string(value.Automation.Envelope))
	if hex.EncodeToString(h.Sum(nil)) != digest {
		return AutomationPrefix{}, false, &automationProofCorruptionError{cause: fmt.Errorf("automation parent digest mismatch")}
	}
	return AutomationPrefix{Sequence: sequence, ClusterUID: decision.Command.ClusterUID, Digest: digest}, true, nil
}

func automationTrustedDigestTx(ctx context.Context, tx *LocalTx, sequence uint64) (string, bool, error) {
	summary, found, err := automationTrustedSummaryTx(ctx, tx, sequence)
	return summary.Digest, found, err
}

func validateAutomationRecordSize(r AutomationRecord) error {
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxAutomationRecordBytes {
		return fmt.Errorf("automation record exceeds transport bound")
	}
	return nil
}

func cloneAutomationProjection(projection AutomationProjection) AutomationProjection {
	callbackProjection := projection
	if projection.Execution != nil {
		// All nested requirements, dispositions, snapshots and exclusion
		// predecessor requirements belong exclusively to the callback copy.
		raw, _ := json.Marshal(projection.Execution)
		callbackProjection.Execution = new(contract.ExecutionProjection)
		_ = json.Unmarshal(raw, callbackProjection.Execution)
	}
	if projection.Target != nil {
		raw, _ := json.Marshal(projection.Target)
		callbackProjection.Target = new(contract.TargetProjection)
		_ = json.Unmarshal(raw, callbackProjection.Target)
	}
	if projection.KeyTransition != nil {
		raw, _ := json.Marshal(projection.KeyTransition)
		callbackProjection.KeyTransition = new(contract.KeyTransitionProjection)
		_ = json.Unmarshal(raw, callbackProjection.KeyTransition)
	}
	if projection.Existing != nil {
		existing := *projection.Existing
		existing.Identity = append([]byte(nil), existing.Identity...)
		callbackProjection.Existing = &existing
	}
	if projection.Operation != nil {
		operation := *projection.Operation
		callbackProjection.Operation = &operation
	}
	if projection.Identity != nil {
		facts := *projection.Identity
		if facts.Project != nil {
			v := *facts.Project
			facts.Project = &v
		}
		if facts.Alias != nil {
			v := *facts.Alias
			facts.Alias = &v
		}
		if facts.Assigned != nil {
			v := *facts.Assigned
			facts.Assigned = &v
		}
		if facts.Resource != nil {
			v := *facts.Resource
			facts.Resource = &v
		}
		if facts.AssignedResource != nil {
			v := *facts.AssignedResource
			facts.AssignedResource = &v
		}
		if facts.Name != nil {
			v := *facts.Name
			facts.Name = &v
		}
		callbackProjection.Identity = &facts
	}
	if projection.Ownership != nil {
		facts := *projection.Ownership
		if facts.Project != nil {
			v := *facts.Project
			facts.Project = &v
		}
		if facts.Principal != nil {
			v := *facts.Principal
			facts.Principal = &v
		}
		if facts.NextPrincipal != nil {
			v := *facts.NextPrincipal
			facts.NextPrincipal = &v
		}
		if facts.Owner != nil {
			v := *facts.Owner
			facts.Owner = &v
		}
		if facts.AssignedSession != nil {
			v := *facts.AssignedSession
			facts.AssignedSession = &v
		}
		callbackProjection.Ownership = &facts
	}
	if projection.Binding != nil {
		facts := *projection.Binding
		for _, field := range []**contract.IdentityRecord{&facts.Project, &facts.Principal, &facts.AssignedIdentity, &facts.NameIdentity} {
			if *field != nil {
				v := **field
				*field = &v
			}
		}
		if facts.Owner != nil {
			v := *facts.Owner
			facts.Owner = &v
		}
		if facts.Last != nil {
			v := *facts.Last
			facts.Last = &v
		}
		if facts.Name != nil {
			v := *facts.Name
			facts.Name = &v
		}
		if facts.Resource != nil {
			v := *facts.Resource
			facts.Resource = &v
		}
		if facts.AssignedResource != nil {
			v := *facts.AssignedResource
			facts.AssignedResource = &v
		}
		if facts.Dependencies != nil {
			facts.Dependencies = make([]*contract.IdentityRecord, len(projection.Binding.Dependencies))
			for i, record := range projection.Binding.Dependencies {
				if record != nil {
					v := *record
					facts.Dependencies[i] = &v
				}
			}
		}
		if facts.TargetOwner != nil {
			v := *facts.TargetOwner
			facts.TargetOwner = &v
		}
		if facts.TargetPrincipal != nil {
			v := *facts.TargetPrincipal
			facts.TargetPrincipal = &v
		}
		if facts.TargetLast != nil {
			v := *facts.TargetLast
			facts.TargetLast = &v
		}
		if facts.OriginalTarget != nil {
			v := *facts.OriginalTarget
			v.Body = append([]byte(nil), v.Body...)
			v.Assignment = append([]byte(nil), v.Assignment...)
			facts.OriginalTarget = &v
		}
		if facts.OriginalAdmission != nil {
			// Admission/VMIntent contains no unsupported or recursive JSON types.
			encoded, _ := json.Marshal(facts.OriginalAdmission)
			facts.OriginalAdmission = new(contract.AdmissionRecord)
			_ = json.Unmarshal(encoded, facts.OriginalAdmission)
		}
		callbackProjection.Binding = &facts
	}
	return callbackProjection
}

func (c *Client) automationMatchingRecovery(ctx context.Context, sequence uint64, digest string, generation int64, members string) error {
	return c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		rows, e := tx.Query(ctx, `SELECT r.sequence,r.digest,r.generation,r.members_hash,s.digest AS staged_digest FROM local_automation_recovery r JOIN local_automation_staging s ON s.sequence=r.sequence WHERE r.id=1 LIMIT 1`)
		if e != nil {
			return e
		}
		if len(rows) != 1 || rows[0].Int64("sequence") != int64(sequence) || rows[0].String("digest") != digest || rows[0].String("staged_digest") != digest || rows[0].Int64("generation") != generation || rows[0].String("members_hash") != members {
			return fmt.Errorf("automation recovery belongs to a different certified record")
		}
		return nil
	})
}
