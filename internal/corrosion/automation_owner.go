package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"time"
	"unicode/utf8"

	"github.com/litevirt/litevirt/internal/auth/policy"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/safename"
)

var ErrAutomationOwnerPermission = errors.New("automation owner permission denied")

type ownerRequestError string

func (e ownerRequestError) Error() string { return "automation owner: " + string(e) }
func (e ownerRequestError) Code() string  { return string(e) }

// AutomationOwnerSession is a process-local reference to genuine Login
// provenance. Its fields cannot be supplied by a public command or a peer.
// It is not authorization: every new native Accept rechecks it in FULL.
type AutomationOwnerSession struct {
	db                     *Client
	id, principal, cluster string
	idle                   time.Duration
}

func AuthenticateAutomationOwnerSession(ctx context.Context, c *Client, id string, idle time.Duration) (*contract.IdentityRecord, *AutomationOwnerSession, error) {
	identity, err := AutomationSessionPrincipal(ctx, c, id)
	if err != nil {
		return nil, nil, err
	}
	if identity == nil || idle <= 0 {
		return nil, nil, ErrAutomationLifecycleUnavailable
	}
	a := &AutomationOwnerSession{db: c, id: id, principal: identity.UID, cluster: identity.ClusterUID, idle: idle}
	return identity, a, nil
}

// AutomationOwnerSubmission retains immutable intent, not a permission bit.
// Credential IDs never leave this process or enter an envelope/audit record.
type AutomationOwnerSubmission struct {
	session  *AutomationOwnerSession
	command  contract.Command
	identity []byte
	target   string
}

func IsAutomationOwnerKind(kind string) bool {
	return kind == "ensure_owner" || kind == "acquire_session" || kind == "handoff_session"
}

func NewAutomationOwnerSubmission(ctx context.Context, session *AutomationOwnerSession, command contract.Command, target string) (*AutomationOwnerSubmission, error) {
	if session == nil || session.db == nil {
		return nil, ErrAutomationLifecycleUnavailable
	}
	if !IsAutomationOwnerKind(command.Kind) || command.ClusterUID != session.cluster || command.PrincipalID != session.principal || !utf8.ValidString(target) || len(target) > contract.MaxStringBytes || (command.Kind == "ensure_owner") != (target == "") {
		return nil, ownerRequestError(contract.CodeValidation)
	}
	if err := contract.ValidateSupportedCommand(command); err != nil {
		return nil, err
	}
	identity, err := contract.CanonicalCommand(command)
	if err != nil {
		return nil, err
	}
	command.Body = append([]byte(nil), command.Body...)
	r := &AutomationOwnerSubmission{session: session, command: command, identity: identity, target: target}
	if err := r.Authorize(ctx); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *AutomationOwnerSubmission) Command() contract.Command {
	c := r.command
	c.Body = append([]byte(nil), c.Body...)
	return c
}
func (r *AutomationOwnerSubmission) TargetSessionID() string { return r.target }
func (r *AutomationOwnerSubmission) UsesClient(c *Client) bool {
	return r != nil && r.session != nil && r.session.db == c
}

// Authorize precedes receipt/history disclosure. Native issuance later repeats
// this read under the actual Accept transaction, after highest-value selection.
func (r *AutomationOwnerSubmission) Authorize(ctx context.Context) error {
	if r == nil || r.session == nil || r.session.db == nil {
		return ErrAutomationLifecycleUnavailable
	}
	return r.session.db.ExecuteLocal(ctx, func(tx *LocalTx) error { return r.authorizeTx(ctx, tx) })
}

func (r *AutomationOwnerSubmission) authorizeTx(ctx context.Context, tx *LocalTx) (resultErr error) {
	defer func() { resultErr = automationCredentialFailure(resultErr, AutomationCredentialProofInvalid) }()
	a := r.session
	if a == nil || a.db == nil || a.db.CredentialsUnhydrated() {
		return ErrAutomationLifecycleUnavailable
	}
	identity, err := automationCredentialPrincipalTx(ctx, a.db, tx.tx, "session", a.id)
	if err != nil {
		return err
	}
	if identity == nil || identity.UID != a.principal || identity.ClusterUID != a.cluster || r.command.PrincipalID != identity.UID || r.command.ClusterUID != identity.ClusterUID {
		return ErrAutomationLifecycleUnavailable
	}
	var realm, last, expires, username, role string
	err = tx.tx.QueryRowContext(ctx, `SELECT s.realm,s.last_used_at,s.expires_at,s.username,u.role FROM sessions s JOIN users u ON u.username=s.username WHERE s.id=? AND s.revoked_at IS NULL AND u.deleted_at IS NULL`, a.id).Scan(&realm, &last, &expires, &username, &role)
	if err != nil {
		return err
	}
	now := time.Now()
	used, e1 := time.Parse(time.RFC3339, last)
	until, e2 := time.Parse(time.RFC3339, expires)
	if realm != "local" || username != identity.Alias || e1 != nil || e2 != nil || !now.Before(until) || now.Sub(used) > a.idle {
		return ErrAutomationLifecycleUnavailable
	}
	project, err := automationIdentityRecordTx(ctx, tx, "", r.command.ProjectUID)
	if err != nil {
		return err
	}
	if project == nil || project.Retired || project.Kind != "project" || project.ClusterUID != a.cluster || project.ProjectUID != "" || project.Alias == "" {
		return ErrAutomationLifecycleUnavailable
	}
	aliases, err := tx.Query(ctx, `SELECT uid FROM local_automation_aliases WHERE stage='' AND cluster_uid=? AND project_scope='' AND kind='project' AND alias=? AND generation=? AND uid=?`, project.ClusterUID, project.Alias, project.Generation, project.UID)
	if err != nil {
		return err
	}
	if len(aliases) != 1 {
		return ErrAutomationLifecycleUnavailable
	}
	certified, err := automationCertifiedIdentityForAliasTx(ctx, tx.tx, "project", project.Alias)
	if err != nil {
		return err
	}
	if certified == nil || *certified != *project {
		return ErrAutomationLifecycleUnavailable
	}
	continuity, err := automationIdentityContinuityProofTx(ctx, a.db, tx.tx, project)
	if err != nil {
		return err
	}
	if continuity == nil {
		lifetime, err := automationLifetimeTx(ctx, tx.tx, "project", project.Alias)
		if err != nil {
			return err
		}
		if lifetime.Witness != project.Witness || lifetime.Origin == "" {
			return ErrAutomationLifecycleUnavailable
		}
	}
	name, err := safename.CanonicalProjectName(project.Alias)
	if err != nil || name == "" {
		return ErrAutomationLifecycleUnavailable
	}
	path := safename.ProjectRBACPath(name)
	// One SQL snapshot supplies both the presence and grants of bindings. A
	// binding anywhere suppresses fallback, including a missing/NoAccess role.
	rows, err := tx.Query(ctx, `SELECT b.id,b.path,b.propagate,b.updated_at,r.verbs FROM role_bindings b LEFT JOIN roles r ON r.name=b.role AND r.deleted_at IS NULL WHERE b.deleted_at IS NULL AND (b.principal=? OR b.principal=?)`, "user:"+username+"@local", "group:"+role+"@local")
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if role == "operator" || role == "admin" {
			return nil
		}
		return ErrAutomationOwnerPermission
	}
	// Use the existing project-incarnation owner in this same authorization
	// transaction. Held bindings remain present above, suppressing fallback,
	// but cannot grant access to a project incarnation they never held.
	states, err := loadProjectStatesTx(ctx, tx.tx)
	if err != nil {
		return err
	}
	for _, row := range rows {
		binding := RoleBindingRecord{ID: row.String("id"), Path: row.String("path"), Propagate: row.Int64("propagate") != 0, UpdatedAt: row.String("updated_at")}
		if projectBindingHeld(binding, states) {
			continue
		}
		if !policy.BindingApplies(row.String("path"), path, row.Int64("propagate") != 0) {
			continue
		}
		var verbs []string
		if json.Unmarshal([]byte(row.String("verbs")), &verbs) != nil {
			continue
		}
		if policy.VerbMatches(verbs, policy.OwnerManage) {
			return nil
		}
	}
	return ErrAutomationOwnerPermission
}

// SameOwnerTarget compares the original certified assignment, separately from
// the established canonical identity that intentionally excludes authority.
func SameOwnerTarget(d contract.Decision, target string) bool {
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return false
	}
	if d.Command.Kind == "ensure_owner" {
		return target == "" && a.Owner == nil
	}
	return IsAutomationOwnerKind(d.Command.Kind) && a.Owner != nil && a.Owner.SessionID == target
}

func automationOwnerOriginalTx(ctx context.Context, tx *LocalTx, receipt contract.Receipt) (contract.Decision, error) {
	rows, err := tx.Query(ctx, `SELECT value_json FROM local_automation_history WHERE sequence=?`, receipt.Sequence)
	if err != nil {
		return contract.Decision{}, err
	}
	if len(rows) != 1 {
		return contract.Decision{}, errAutomationAuthority
	}
	key, err := AutomationClaimKey(receipt.Sequence)
	if err != nil {
		return contract.Decision{}, err
	}
	var value ClaimValue
	if err := decodeClaimValue(key, rows[0].String("value_json"), &value); err != nil {
		return contract.Decision{}, err
	}
	digest, found, err := automationTrustedDigestTx(ctx, tx, receipt.Sequence)
	if err != nil {
		return contract.Decision{}, err
	}
	if !found || digest != value.MustDigest() {
		return contract.Decision{}, errAutomationAuthority
	}
	d, err := automationDecision(value)
	if err != nil {
		return d, err
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return d, err
	}
	if d.Sequence != receipt.Sequence || d.Command.RequestID != receipt.RequestID || a.OperationID != receipt.OperationID {
		return d, errAutomationAuthority
	}
	return d, nil
}

func (r *AutomationOwnerSubmission) Original(ctx context.Context, receipt contract.Receipt) (out contract.Decision, err error) {
	if r == nil || r.session == nil {
		return out, ErrAutomationLifecycleUnavailable
	}
	err = r.session.db.ExecuteLocal(ctx, func(tx *LocalTx) error {
		var e error
		out, e = automationOwnerOriginalTx(ctx, tx, receipt)
		if e != nil {
			return e
		}
		identity, e := contract.CanonicalCommand(out.Command)
		if e != nil {
			return e
		}
		if out.Command.RequestID != r.command.RequestID || !bytes.Equal(identity, r.identity) || !SameOwnerTarget(out, r.target) {
			return ownerRequestError(contract.CodeIdempotencyConflict)
		}
		return nil
	})
	return
}

// The FULL duplicate boundary closes races between independently issued
// proposals. Retained historical replay remains byte-for-byte unchanged.
func automationOwnerDuplicateTx(ctx context.Context, tx *LocalTx, d contract.Decision) error {
	old, err := automationRequestTx(ctx, tx, contract.Scope(d), d.Command.RequestID)
	if err != nil || old == nil {
		return err
	}
	identity, err := contract.CanonicalCommand(d.Command)
	if err != nil {
		return err
	}
	if !bytes.Equal(identity, old.Identity) {
		return ownerRequestError(contract.CodeIdempotencyConflict)
	}
	original, err := automationOwnerOriginalTx(ctx, tx, old.Receipt)
	if err != nil {
		return err
	}
	a, err := contract.DecodeAssignment(d)
	if err != nil {
		return err
	}
	target := ""
	if a.Owner != nil {
		target = a.Owner.SessionID
	}
	if !SameOwnerTarget(original, target) {
		return ownerRequestError(contract.CodeIdempotencyConflict)
	}
	return nil
}
