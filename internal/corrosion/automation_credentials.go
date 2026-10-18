package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// InsertAutomationToken reuses the actual legacy issuer, with an additional
// atomic local provenance record. The opaque authentication must be current;
// no caller-supplied principal UID is accepted.
func InsertAutomationToken(ctx context.Context, c *Client, a *AutomationAccountAuthentication, t TokenRecord) error {
	if a == nil {
		return ErrAutomationLifecycleUnavailable
	}
	t.automationAuthentication = a
	return InsertToken(ctx, c, t)
}

func InsertAutomationSession(ctx context.Context, c *Client, a *AutomationAccountAuthentication, s SessionRecord) error {
	if a == nil || s.Realm != "local" {
		return ErrAutomationLifecycleUnavailable
	}
	s.automationAuthentication = a
	return InsertSession(ctx, c, s)
}

type automationIssuance struct {
	kind, id      string
	authenticated *AutomationAccountAuthentication
	identity      *contract.IdentityRecord
}

func (c *Client) executeCredentialBatch(ctx context.Context, a *AutomationAccountAuthentication, kind, id, username string, stmts []Statement) error {
	if a == nil {
		return c.ExecuteBatch(ctx, stmts)
	}
	if username != a.username || id == "" {
		return ErrAutomationLifecycleUnavailable
	}
	mutation := &lifecycleMutation{kind: "principal", name: username, event: "issue", expected: a.parent, issuance: &automationIssuance{kind: kind, id: id, authenticated: a}}
	_, err := c.executeBatchWithLifecycle(ctx, stmts, true, false, mutation)
	return err
}
func (i *automationIssuance) check(ctx context.Context, tx *sql.Tx, m *lifecycleMutation) error {
	current, err := automationLifetimeTx(ctx, tx, "principal", m.name)
	if err != nil {
		return err
	}
	if current != m.previous {
		return ErrAutomationLifecycleUnavailable
	}

	if m.previous.Witness == "" || m.previous.Witness != i.authenticated.witness {
		return ErrAutomationLifecycleUnavailable
	}
	if err := automationPasswordAccountAllowedTx(ctx, tx, m.name); err != nil {
		return err
	}
	identity, err := automationPrincipalForLifetimeTx(ctx, tx, m.previous)
	if err != nil {
		return err
	}
	i.identity = identity
	return nil
}
func (i *automationIssuance) persist(ctx context.Context, tx *sql.Tx, m *lifecycleMutation) error {
	if i.identity == nil {
		return ErrAutomationLifecycleUnavailable
	}
	// This recheck also rejects a credential insertion whose trigger or another
	// batch statement altered the account or certified projection.
	if err := i.check(ctx, tx, m); err != nil {
		return err
	}
	snapshot, err := automationCredentialSnapshotTx(ctx, tx, i.kind, i.id)
	if err != nil {
		return err
	}
	if snapshot.Username != m.name {
		return ErrAutomationLifecycleUnavailable
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO local_automation_credential_issuance(kind,credential_id,username,witness,principal_uid,cluster_uid,credential_digest,valid) VALUES(?,?,?,?,?,?,?,1)`, i.kind, i.id, m.name, m.previous.Witness, i.identity.UID, i.identity.ClusterUID, snapshot.digest())
	return err
}

func automationPrincipalForLifetimeTx(ctx context.Context, tx *sql.Tx, e AutomationLifetimeEvidence) (*contract.IdentityRecord, error) {
	local := &LocalTx{tx: tx}
	if err := automationProjectionAuthorityTx(ctx, local); err != nil {
		return nil, ErrAutomationLifecycleUnavailable
	}
	var uid string
	err := tx.QueryRowContext(ctx, `SELECT i.uid FROM local_automation_identities i JOIN local_automation_aliases a ON a.stage=i.stage AND a.uid=i.uid AND a.cluster_uid=i.cluster_uid AND a.project_scope=i.project_uid AND a.kind=i.kind AND a.alias=i.alias AND a.generation=i.generation
 WHERE i.stage='' AND i.kind='principal' AND i.project_uid='' AND i.alias=? AND i.witness=? AND i.retired=0`, e.Name, e.Witness).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAutomationLifecycleUnavailable
	}
	if err != nil {
		return nil, err
	}
	identity, err := automationIdentityRecordTx(ctx, local, "", uid)
	if err != nil {
		return nil, err
	}
	head, err := automationHeadTx(ctx, local)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.ClusterUID != head.ClusterUID {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return identity, nil
}

type automationCredentialSnapshot struct{ ID, Username, Realm, Secret, Name, Scopes, Created, Expires, IP, Agent string }

func (s automationCredentialSnapshot) digest() string {
	encoded, _ := json.Marshal(s)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func automationCredentialSnapshotTx(ctx context.Context, tx *sql.Tx, kind, id string) (automationCredentialSnapshot, error) {
	s := automationCredentialSnapshot{ID: id}
	var revoked string
	var err error
	switch kind {
	case "token":
		err = tx.QueryRowContext(ctx, `SELECT t.username,CASE WHEN c.token_id IS NOT NULL THEN c.token_hash ELSE t.token_hash END,t.name,COALESCE(t.scope_paths,''),t.created_at,COALESCE(t.expires_at,''),COALESCE(t.deleted_at,'') FROM tokens t LEFT JOIN token_credentials c ON c.token_id=t.id AND c.deleted_at IS NULL WHERE t.id=?`, id).Scan(&s.Username, &s.Secret, &s.Name, &s.Scopes, &s.Created, &s.Expires, &revoked)
	case "session":
		err = tx.QueryRowContext(ctx, `SELECT username,realm,ip,user_agent,created_at,expires_at,COALESCE(revoked_at,'') FROM sessions WHERE id=?`, id).Scan(&s.Username, &s.Realm, &s.IP, &s.Agent, &s.Created, &s.Expires, &revoked)
	default:
		return s, ErrAutomationLifecycleUnavailable
	}
	if errors.Is(err, sql.ErrNoRows) {
		return s, ErrAutomationLifecycleUnavailable
	}
	if err != nil {
		return s, err
	}
	if revoked != "" {
		return s, ErrAutomationLifecycleUnavailable
	}
	if s.Expires != "" {
		expires, err := time.Parse(time.RFC3339, s.Expires)
		if err != nil || !time.Now().Before(expires) {
			return s, ErrAutomationLifecycleUnavailable
		}
	}
	return s, nil
}

// AutomationTokenPrincipal first performs actual bearer authentication. IDs,
// display names, roles and timestamps alone cannot supply this bridge.
func AutomationTokenPrincipal(ctx context.Context, c *Client, raw string) (*contract.IdentityRecord, error) {
	if c.CredentialsUnhydrated() {
		return nil, ErrAutomationLifecycleUnavailable
	}
	user, err := ValidateToken(ctx, c, raw)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return automationCredentialPrincipal(ctx, c, "token", user.TokenID)
}

// AutomationSessionPrincipal adds provenance to an already authenticated
// session. The normal interceptor still owns idle timeout, scope and permission
// checks; this bridge cannot replace them or authorize an operation.
func AutomationSessionPrincipal(ctx context.Context, c *Client, id string) (*contract.IdentityRecord, error) {
	if c.CredentialsUnhydrated() {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return automationCredentialPrincipal(ctx, c, "session", id)
}
func automationCredentialPrincipal(ctx context.Context, c *Client, kind, id string) (*contract.IdentityRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var username, witness, principal, cluster, digest string
	err = tx.QueryRowContext(ctx, `SELECT username,witness,principal_uid,cluster_uid,credential_digest FROM local_automation_credential_issuance WHERE kind=? AND credential_id=? AND valid=1`, kind, id).Scan(&username, &witness, &principal, &cluster, &digest)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAutomationLifecycleUnavailable
	}
	if err != nil {
		return nil, err
	}
	evidence, err := automationLifetimeTx(ctx, tx, "principal", username)
	if err != nil {
		return nil, err
	}
	if evidence.Witness != witness {
		return nil, ErrAutomationLifecycleUnavailable
	}
	if err := automationPasswordAccountAllowedTx(ctx, tx, username); err != nil {
		return nil, err
	}
	snapshot, err := automationCredentialSnapshotTx(ctx, tx, kind, id)
	if err != nil {
		return nil, err
	}
	if snapshot.Username != username || snapshot.digest() != digest {
		return nil, ErrAutomationLifecycleUnavailable
	}
	life, err := automationUserLifecycleTx(ctx, tx, username)
	if err != nil {
		return nil, err
	}
	if (kind == "token" && life.TokenPredates(snapshot.Created)) || (kind == "session" && life.SessionPredates(snapshot.Created)) {
		return nil, ErrAutomationLifecycleUnavailable
	}
	identity, err := automationPrincipalForLifetimeTx(ctx, tx, evidence)
	if err != nil {
		return nil, err
	}
	if identity.UID != principal || identity.ClusterUID != cluster {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return identity, nil
}
func automationUserLifecycleTx(ctx context.Context, tx *sql.Tx, name string) (UserLifecycle, error) {
	var life UserLifecycle
	rows, err := tx.QueryContext(ctx, `SELECT attribute,value FROM user_lifecycle WHERE username=? AND deleted_at IS NULL`, name)
	if err != nil {
		return life, err
	}
	defer rows.Close()
	for rows.Next() {
		var attr, value string
		if err := rows.Scan(&attr, &value); err != nil {
			return life, err
		}
		life.applyAttribute(attr, value)
	}
	return life, rows.Err()
}
