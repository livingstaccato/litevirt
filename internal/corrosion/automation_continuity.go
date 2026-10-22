package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// AutomationIdentityContinuity retains exact intent and genuine local session
// provenance. It carries neither a release grant nor a reusable permission bit.
type AutomationIdentityContinuity struct {
	kind, uid string
	session   *AutomationOwnerSession
	command   contract.Command
	identity  []byte
	facts     contract.IdentityContinuity
	origin    AutomationLifetimeEvidence
}

func PrepareAutomationIdentityContinuity(ctx context.Context, c *Client, session *AutomationOwnerSession, kind, uid, requestID string) (*AutomationIdentityContinuity, error) {
	if c == nil || session == nil || session.db != c || (kind != "principal" && kind != "project") || (kind == "principal" && session.principal != uid) || uid == "" || requestID == "" {
		return nil, ErrAutomationLifecycleUnavailable
	}
	r := &AutomationIdentityContinuity{session: session, kind: kind, uid: uid}
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		identity, origin, parent, err := r.currentTx(ctx, tx)
		if err != nil {
			return err
		}
		r.origin = origin
		r.facts = contract.IdentityContinuity{ClusterUID: identity.ClusterUID, UID: identity.UID, OriginalWitness: identity.Witness, Generation: identity.Generation, Parent: parent}
		body, err := json.Marshal(contract.IdentityContinuityBody{Version: 1, IdentityContinuity: r.facts})
		if err != nil {
			return err
		}
		r.command = contract.Command{Kind: contract.IdentityContinuityCommand, ClusterUID: identity.ClusterUID, PrincipalID: session.principal, ResourceUID: identity.UID, Generation: identity.Generation, RequestID: requestID, Body: body}
		if kind == "project" {
			r.command.ProjectUID = identity.UID
		}
		if err = contract.ValidateSupportedCommand(r.command); err != nil {
			return err
		}
		r.identity, err = contract.CanonicalCommand(r.command)
		return err
	})
	if err != nil {
		return nil, automationCredentialFailure(err, AutomationCredentialProofInvalid)
	}
	return r, nil
}

func (r *AutomationIdentityContinuity) currentTx(ctx context.Context, tx *LocalTx) (*contract.IdentityRecord, AutomationLifetimeEvidence, contract.ParentLifetime, error) {
	var origin AutomationLifetimeEvidence
	var parent contract.ParentLifetime
	a := r.session
	if a == nil || a.db == nil || a.db.CredentialsUnhydrated() || a.idle <= 0 {
		return nil, origin, parent, ErrAutomationLifecycleUnavailable
	}
	i, err := automationCredentialPrincipalTx(ctx, a.db, tx.tx, "session", a.id)
	if err != nil {
		return nil, origin, parent, err
	}
	if i == nil || i.UID != a.principal || i.ClusterUID != a.cluster || i.Kind != "principal" || i.ProjectUID != "" || i.Retired {
		return nil, origin, parent, ErrAutomationLifecycleUnavailable
	}
	var realm, username, last string
	err = tx.tx.QueryRowContext(ctx, `SELECT realm,username,last_used_at FROM sessions WHERE id=? AND revoked_at IS NULL`, a.id).Scan(&realm, &username, &last)
	if err != nil {
		return nil, origin, parent, err
	}
	used, err := time.Parse(time.RFC3339, last)
	if err != nil || realm != "local" || username != i.Alias || time.Since(used) > a.idle {
		return nil, origin, parent, ErrAutomationLifecycleUnavailable
	}
	// A project attachment still authenticates a current principal. Its public
	// parent refusal (including an actual held newer incarnation) is independent
	// of the target project's lifetime stored in the attachment.
	principalParent, err := readAutomationParentLifetimeTx(ctx, a.db, tx.tx, "principal", i.Alias)
	if err != nil {
		return nil, origin, parent, err
	}
	if r.kind == "project" {
		owner := &AutomationOwnerSubmission{session: a, command: contract.Command{ClusterUID: a.cluster, PrincipalID: a.principal, ProjectUID: r.uid}}
		if err := owner.authorizeTx(ctx, tx); err != nil {
			return nil, origin, parent, err
		}
		i, err = automationIdentityRecordTx(ctx, tx, "", r.uid)
		if err != nil {
			return nil, origin, parent, err
		}
		if i == nil || i.Kind != "project" || i.Retired || i.ClusterUID != a.cluster || i.ProjectUID != "" || i.UID != r.uid || i.Alias == "" {
			return nil, origin, parent, ErrAutomationLifecycleUnavailable
		}
	} else if r.kind != "principal" || i.UID != r.uid {
		return nil, origin, parent, ErrAutomationLifecycleUnavailable
	}
	origin, err = automationLifetimeTx(ctx, tx.tx, r.kind, i.Alias)
	if err != nil {
		return nil, origin, parent, err
	}
	if origin.Witness != i.Witness || origin.Origin == "" {
		return nil, origin, parent, ErrAutomationLifecycleUnavailable
	}
	parent = principalParent
	if r.kind == "project" {
		parent, err = readAutomationParentLifetimeTx(ctx, a.db, tx.tx, r.kind, i.Alias)
		if err != nil {
			return nil, origin, parent, err
		}
	}
	return i, origin, parent, nil
}

func (r *AutomationIdentityContinuity) authorizeTx(ctx context.Context, tx *LocalTx) error {
	i, origin, parent, err := r.currentTx(ctx, tx)
	if err != nil {
		return automationCredentialFailure(err, AutomationCredentialProofInvalid)
	}
	if origin != r.origin || parent != r.facts.Parent || i.UID != r.facts.UID || i.ClusterUID != r.facts.ClusterUID || i.Generation != r.facts.Generation || i.Witness != r.facts.OriginalWitness {
		return &AutomationCredentialError{Kind: AutomationCredentialProofInvalid}
	}
	return nil
}

func (r *AutomationIdentityContinuity) UsesClient(c *Client) bool {
	return r != nil && r.session != nil && r.session.db == c
}
func (r *AutomationIdentityContinuity) Command() contract.Command {
	c := r.command
	c.Body = append([]byte(nil), c.Body...)
	return c
}
func (r *AutomationIdentityContinuity) Facts() contract.IdentityContinuity { return r.facts }
func (r *AutomationIdentityContinuity) Authorize(ctx context.Context) error {
	if r == nil || r.session == nil || r.session.db == nil {
		return ErrAutomationLifecycleUnavailable
	}
	return r.session.db.ExecuteLocal(ctx, func(tx *LocalTx) error { return r.authorizeTx(ctx, tx) })
}

// Original performs final current authorization and exact request/fact lookup
// together. The caller must complete its current decision quorum first.
func (r *AutomationIdentityContinuity) Original(ctx context.Context, receipt contract.Receipt, current AutomationRecord) (out contract.Decision, err error) {
	if r == nil || r.session == nil || r.session.db == nil {
		return out, ErrAutomationLifecycleUnavailable
	}
	key, e := AutomationClaimKey(receipt.Sequence)
	if e != nil {
		return out, e
	}
	p, release, e := r.session.db.prepareContinuityProof(ctx, continuityCertificate, key, current.Value, current.Certificate.ConfigGeneration, current.Certificate, nil)
	if e != nil {
		return out, e
	}
	defer release()
	err = r.session.db.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := r.session.db.validateContinuityProofTx(ctx, tx, p); err != nil {
			return err
		}
		if err := r.authorizeTx(ctx, tx); err != nil {
			return err
		}
		var err error
		out, err = automationOwnerOriginalTx(ctx, tx, receipt)
		if err != nil {
			return err
		}
		encoded, err := contract.EncodeDecision(out)
		if err != nil {
			return err
		}
		if !bytes.Equal(encoded, p.value.Automation.Envelope) {
			return ownerRequestError(contract.CodeIdempotencyConflict)
		}
		identity, err := contract.CanonicalCommand(out.Command)
		if err != nil {
			return err
		}
		a, err := contract.DecodeAssignment(out)
		if err != nil {
			return err
		}
		if out.Command.RequestID != r.command.RequestID || contract.Scope(out) != contract.Scope(contract.Decision{Command: r.command}) || !bytes.Equal(identity, r.identity) || a.Continuity == nil || *a.Continuity != r.facts {
			return ownerRequestError(contract.CodeIdempotencyConflict)
		}
		return nil
	})
	return
}

// This is an inert, history-derived projection. It supplies neither a parent
// observation nor a native acceptance permit. Callers own this FULL transaction.
func automationContinuityRecordTx(ctx context.Context, tx *LocalTx, stage, cluster, uid string, generation uint64) (*contract.IdentityContinuity, error) {
	if len(stage) > contract.MaxStringBytes || !utf8.ValidString(stage) || cluster == "" || uid == "" || len(cluster) > contract.MaxStringBytes || len(uid) > contract.MaxStringBytes || !utf8.ValidString(cluster) || !utf8.ValidString(uid) || generation == 0 || generation > math.MaxInt64 {
		return nil, &automationProofCorruptionError{cause: fmt.Errorf("invalid continuity projection key")}
	}
	// Do not filter cluster: a row at the exact PK under the wrong cluster is
	// corruption, not absence. Probe types and individual byte bounds first.
	const where = ` FROM local_automation_identity_continuity WHERE stage=? AND uid=? AND generation=? LIMIT 1`
	text := []string{"stage", "cluster_uid", "uid", "original_witness", "parent_kind", "parent_alias", "parent_realm", "parent_birth"}
	var bad []string
	for _, column := range text {
		bad = append(bad, fmt.Sprintf("typeof(%s)<>'text' OR length(CAST(%s AS BLOB))>%d", column, column, contract.MaxStringBytes))
	}
	bad = append(bad, "typeof(generation)<>'integer' OR generation<=0")
	probe, err := tx.Query(ctx, "SELECT CASE WHEN "+strings.Join(bad, " OR ")+" THEN 1 ELSE 0 END AS bad"+where, stage, uid, generation)
	if err != nil {
		return nil, err
	}
	if len(probe) == 0 {
		return nil, nil
	}
	if len(probe) != 1 || probe[0].Int64("bad") != 0 {
		return nil, &automationProofCorruptionError{cause: fmt.Errorf("malformed continuity projection")}
	}
	rows, err := tx.Query(ctx, `SELECT stage,cluster_uid,uid,generation,original_witness,parent_kind,parent_alias,parent_realm,parent_birth`+where, stage, uid, generation)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, &automationProofCorruptionError{cause: fmt.Errorf("continuity projection disappeared")}
	}
	row := rows[0]
	f := contract.IdentityContinuity{ClusterUID: row.String("cluster_uid"), UID: row.String("uid"), Generation: uint64(row.Int64("generation")), OriginalWitness: row.String("original_witness"), Parent: contract.ParentLifetime{Kind: row.String("parent_kind"), Alias: row.String("parent_alias"), Realm: row.String("parent_realm"), Birth: row.String("parent_birth")}}
	if row.String("stage") != stage || f.ClusterUID != cluster || f.UID != uid || f.Generation != generation || contract.ValidateIdentityContinuity(f) != nil {
		return nil, &automationProofCorruptionError{cause: fmt.Errorf("invalid continuity projection facts")}
	}
	return &f, nil
}

func automationApplyContinuityEffectTx(ctx context.Context, tx *LocalTx, stage, cluster string, r contract.Reduction) error {
	if r.ContinuityEffect == nil {
		return nil
	}
	if err := requireAutomationFull(ctx, tx); err != nil {
		return err
	}
	f := *r.ContinuityEffect
	if r.Receipt.Code != "" || len(stage) > contract.MaxStringBytes || !utf8.ValidString(stage) || f.ClusterUID != cluster || contract.ValidateIdentityContinuity(f) != nil {
		return fmt.Errorf("invalid continuity effect")
	}
	// First attachment only. Identical decisions have no effect; no upsert can
	// replace an established parent, original witness, or identity generation.
	_, err := tx.Exec(ctx, `INSERT INTO local_automation_identity_continuity(stage,cluster_uid,uid,generation,original_witness,parent_kind,parent_alias,parent_realm,parent_birth) VALUES(?,?,?,?,?,?,?,?,?)`, stage, f.ClusterUID, f.UID, f.Generation, f.OriginalWitness, f.Parent.Kind, f.Parent.Alias, f.Parent.Realm, f.Parent.Birth)
	return err
}

func automationVerifyContinuityIndexesTx(ctx context.Context, tx *LocalTx) error {
	const table = "local_automation_identity_continuity"
	rows, err := tx.Query(ctx, `SELECT count(*) AS n FROM pragma_index_list(?)`, table)
	if err != nil {
		return err
	}
	if len(rows) != 1 || rows[0].Int64("n") != 2 {
		return fmt.Errorf("continuity index inventory differs")
	}
	for _, index := range []struct {
		name, columns, origin string
		unique                int64
	}{
		{"sqlite_autoindex_" + table + "_1", "stage,uid,generation", "pk", 1},
		{"local_automation_identity_continuity_parent", "stage,cluster_uid,parent_kind,parent_alias,parent_realm,parent_birth,uid,generation", "c", 0},
	} {
		rows, err = tx.Query(ctx, `SELECT "unique" AS uq,partial,origin FROM pragma_index_list(?) WHERE name=? LIMIT 1`, table, index.name)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Int64("uq") != index.unique || rows[0].Int64("partial") != 0 || rows[0].String("origin") != index.origin {
			return fmt.Errorf("continuity index shape differs")
		}
		columns := strings.Split(index.columns, ",")
		rows, err = tx.Query(ctx, `SELECT count(*) AS n FROM pragma_index_xinfo(?) WHERE "key"=1`, index.name)
		if err != nil {
			return err
		}
		if len(rows) != 1 || rows[0].Int64("n") != int64(len(columns)) {
			return fmt.Errorf("continuity index key count differs")
		}
		for pos, column := range columns {
			rows, err = tx.Query(ctx, `SELECT 1 AS valid FROM pragma_index_xinfo(?) WHERE seqno=? AND name=? AND coll='BINARY' AND "desc"=0 AND "key"=1 LIMIT 1`, index.name, pos, column)
			if err != nil {
				return err
			}
			if len(rows) != 1 {
				return fmt.Errorf("continuity index order differs")
			}
		}
	}
	return nil
}
