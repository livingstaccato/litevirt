package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// MaxAutomationRecordBytes includes the complete value AND quorum certificate.
// Readiness must bound electorate/certificate capacity before admission.
const MaxAutomationRecordBytes = 3 << 20

var errAutomationAuthority = errors.New("automation authority unavailable")

// AutomationPrefix is certified AND transactionally applied progress.
type AutomationPrefix struct {
	ClusterUID string
	Sequence   uint64
	Digest     string
}

// AutomationRecord transports one bounded complete decision and its certificate.
// Membership and trust roots are always selected locally, never by this record.
type AutomationRecord struct {
	Value       ClaimValue
	Certificate ClaimCertificate
}
type AutomationRequest struct {
	Identity []byte
	Receipt  contract.Receipt
}
type AutomationProjection struct {
	Head      AutomationPrefix
	Existing  *AutomationRequest
	Operation *contract.Receipt
	// ReplayOriginal distinguishes rebuilding the original admission from a
	// later duplicate. Semantic owners must reset/stage their derived tables
	// from certified history before replay, never read retained future state.
	ReplayOriginal bool
}
type AutomationReduction struct {
	ClusterUID  string
	Scope       string
	Identity    []byte
	Receipt     contract.Receipt
	SaveRequest bool
}
type AutomationReducer func(AutomationProjection, contract.Decision) (AutomationReduction, error)

const automationHeadSQL = `SELECT cluster_uid, sequence, digest FROM local_automation_prefix WHERE id=1`

func automationHeadTx(ctx context.Context, tx *LocalTx) (AutomationPrefix, error) {
	rows, e := tx.Query(ctx, automationHeadSQL)
	if e != nil || len(rows) == 0 {
		return AutomationPrefix{}, e
	}
	r := rows[0]
	return AutomationPrefix{r.String("cluster_uid"), uint64(r.Int64("sequence")), r.String("digest")}, nil
}
func (c *Client) AutomationHead(ctx context.Context) (h AutomationPrefix, e error) {
	e = c.ExecuteLocal(ctx, func(tx *LocalTx) error { var err error; h, err = automationHeadTx(ctx, tx); return err })
	return
}

func automationAuthorityTx(ctx context.Context, tx *LocalTx, self string, gen int64) (*VoterConfig, error) {
	st, e := readStandingTx(ctx, tx, self)
	if e != nil {
		return nil, e
	}
	if st.adopted != gen || st.cfg == nil || !st.cfg.Explicit() || len(st.cfg.Members) < 3 {
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
func AutomationScope(d contract.Decision) string {
	if d.Command.Kind == "initialize_cluster" {
		return "internal:bootstrap"
	}
	if d.Command.Kind == "read_barrier" {
		return "internal:barrier"
	}
	b, _ := json.Marshal([]string{d.Command.ClusterUID, d.Command.ProjectUID, d.Command.OwnerID})
	return string(b)
}
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
		out, err = automationApplyTx(ctx, tx, r, d, digest, reduce, source)
		return err
	})
	return
}

// automationApplyTx is the sole reducer/application persistence path. History,
// anchors, permanent receipts, typed projections and prefix share this FULL tx.
func automationApplyTx(ctx context.Context, tx *LocalTx, r AutomationRecord, d contract.Decision, digest string, reduce AutomationReducer, source automationApplicationProvenance) (out contract.Receipt, e error) {
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
	if d.Sequence != head.Sequence+1 || d.ParentDigest != head.Digest {
		return out, fmt.Errorf("automation predecessor unavailable")
	}
	projection, err := automationProjectionTx(ctx, tx, head, d)
	if err != nil {
		return out, err
	}
	result, err := reduce(projection, d)
	if err != nil {
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

	} else {
		rows, err := tx.Query(ctx, `SELECT receipt_json FROM local_automation_history WHERE sequence=? AND digest=? LIMIT 1`, d.Sequence, digest)
		if err != nil {
			return out, err
		}
		if len(rows) != 1 {
			return out, fmt.Errorf("automation replay result missing")
		}
		var expected contract.Receipt
		if err = json.Unmarshal([]byte(rows[0].String("receipt_json")), &expected); err != nil {
			return out, err
		}
		if expected != out {
			return out, fmt.Errorf("automation replay receipt drift")
		}
	}

	if result.SaveRequest {
		if _, err = tx.Exec(ctx, `INSERT INTO local_automation_requests (scope,request_id,identity,receipt_json,operation_id) VALUES (?,?,?,?,?)`, result.Scope, d.Command.RequestID, result.Identity, string(receipt), out.OperationID); err != nil {
			return out, err
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_prefix (id,cluster_uid,sequence,digest) VALUES (1,?,?,?) ON CONFLICT(id) DO UPDATE SET cluster_uid=excluded.cluster_uid,sequence=excluded.sequence,digest=excluded.digest`, result.ClusterUID, d.Sequence, digest)
	return out, err
}

// AutomationReplay rebuilds projections only from locally durable authenticated
// anchors. Each query and transaction holds one bounded record, never history.
func (c *Client) AutomationReplay(ctx context.Context, reduce AutomationReducer, budget int) error {
	for range budget {
		h, e := c.AutomationHead(ctx)
		if e != nil {
			return e
		}
		var r AutomationRecord
		var digest string
		found := false
		e = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
			rs, err := tx.Query(ctx, `SELECT h.digest,h.value_json,h.certificate,a.digest AS anchor_digest FROM local_automation_history h JOIN local_automation_anchors a ON a.sequence=h.sequence WHERE h.sequence=? LIMIT 1`, h.Sequence+1)
			if err != nil || len(rs) == 0 {
				return err
			}
			row := rs[0]
			digest = row.String("digest")
			if digest != row.String("anchor_digest") {
				return fmt.Errorf("automation anchor mismatch")
			}
			if err = json.Unmarshal([]byte(row.String("value_json")), &r.Value); err != nil {
				return err
			}
			r.Certificate, err = DecodeClaimCertificate(row.String("certificate"))
			found = err == nil
			return err
		})
		if e != nil {
			return e
		}
		if !found {
			return nil
		}
		d, e := automationDecision(r.Value)
		if e != nil {
			return e
		}
		actual, e := r.Value.Digest()
		if e != nil || actual != digest {
			return fmt.Errorf("automation history digest mismatch")
		}
		if _, e = c.automationApply(ctx, r, d, digest, nil, reduce, true); e != nil {
			return e
		}
	}
	return fmt.Errorf("automation replay budget exhausted")
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
func automationProjectionTx(ctx context.Context, tx *LocalTx, head AutomationPrefix, d contract.Decision) (AutomationProjection, error) {
	existing, err := automationRequestTx(ctx, tx, AutomationScope(d), d.Command.RequestID)
	if err != nil {
		return AutomationProjection{}, err
	}
	assigned, err := contract.DecodeAssignment(d)
	if err != nil {
		return AutomationProjection{}, err
	}
	op, err := automationOperationTx(ctx, tx, assigned.OperationID)
	return AutomationProjection{Head: head, Existing: existing, Operation: op, ReplayOriginal: existing != nil && existing.Receipt.Sequence == d.Sequence}, err
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

func automationTrustedDigestTx(ctx context.Context, tx *LocalTx, sequence uint64) (string, bool, error) {
	rows, err := tx.Query(ctx, `SELECT h.digest,h.value_json,a.digest AS anchor_digest FROM local_automation_history h JOIN local_automation_anchors a ON a.sequence=h.sequence WHERE h.sequence=? LIMIT 1`, sequence)
	if err != nil || len(rows) == 0 {
		return "", false, err
	}
	row := rows[0]
	digest := row.String("digest")
	if digest != row.String("anchor_digest") {
		return "", false, fmt.Errorf("automation parent anchor mismatch")
	}
	var value ClaimValue
	key, _ := AutomationClaimKey(sequence)
	if err := decodeClaimValue(key, row.String("value_json"), &value); err != nil {
		return "", false, err
	}
	if err := validateAutomationValue(key, value); err != nil {
		return "", false, err
	}
	actual, err := value.Digest()
	if err != nil || actual != digest {
		return "", false, fmt.Errorf("automation parent digest mismatch")
	}
	return digest, true, nil
}

func validateAutomationRecordSize(r AutomationRecord) error {
	b, err := json.Marshal(r)
	if err != nil || len(b) > MaxAutomationRecordBytes {
		return fmt.Errorf("automation record exceeds transport bound")
	}
	return nil
}
