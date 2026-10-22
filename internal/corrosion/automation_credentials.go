package corrosion

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/capabilities"
)

type AutomationCredentialDisposition uint8

const (
	AutomationCredentialUnknown AutomationCredentialDisposition = iota
	AutomationCredentialNoLocalProof
	AutomationCredentialUnsupportedFlow
	AutomationCredentialEligible
)

type AutomationCredentialFailure uint8

const (
	AutomationCredentialProofInvalid AutomationCredentialFailure = iota + 1
	AutomationCredentialAuthenticationChanged
)

// AutomationCredentialError exposes a safe classification without account or
// credential material. Its cause remains available for storage diagnostics.
type AutomationCredentialError struct {
	Kind AutomationCredentialFailure
	Err  error
}

func (e *AutomationCredentialError) Error() string { return "automation credential proof unavailable" }
func (e *AutomationCredentialError) Unwrap() error { return e.Err }
func (e *AutomationCredentialError) Is(target error) bool {
	return target == ErrAutomationLifecycleUnavailable
}

var ErrAutomationCredentialUnstamped = fmt.Errorf("automation session has no local issuance: %w", ErrAutomationLifecycleUnavailable)

func automationCredentialFailure(err error, kind AutomationCredentialFailure) error {
	if err == nil {
		return nil
	}
	var typed *AutomationCredentialError
	if errors.As(err, &typed) {
		return err
	}
	var corrupt *automationProofCorruptionError
	if errors.Is(err, ErrAutomationLifecycleUnavailable) || errors.Is(err, errAutomationAuthority) || errors.As(err, &corrupt) {
		return &AutomationCredentialError{Kind: kind, Err: err}
	}
	if kind == AutomationCredentialAuthenticationChanged && errors.Is(err, ErrAmbiguousUsername) {
		return &AutomationCredentialError{Kind: kind, Err: err}
	}
	return err
}

// PrepareAutomationLocalSession discovers only existing certified local proof.
// A missing local observation never asserts authoritative identity absence.
func PrepareAutomationLocalSession(ctx context.Context, c *Client, username, password string) (*AutomationAccountAuthentication, AutomationCredentialDisposition, error) {
	m, err := authenticateAutomationLocal(ctx, c, username, password)
	if err != nil {
		return nil, AutomationCredentialUnknown, automationCredentialFailure(err, AutomationCredentialAuthenticationChanged)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, AutomationCredentialUnknown, err
	}
	defer tx.Rollback()
	current, err := lifecycleParentTx(ctx, tx, "principal", m.name)
	if err != nil {
		return nil, AutomationCredentialUnknown, err
	}
	if current != m.expected || c.CredentialsUnhydrated() {
		return nil, AutomationCredentialUnknown, &AutomationCredentialError{Kind: AutomationCredentialAuthenticationChanged}
	}
	if err := automationPasswordAccountCurrentTx(ctx, tx, m.name); err != nil {
		return nil, AutomationCredentialUnknown, automationCredentialFailure(err, AutomationCredentialAuthenticationChanged)
	}
	unsupported, err := automationPasswordFactorRequiredTx(ctx, tx, m.name)
	if err != nil {
		return nil, AutomationCredentialUnknown, err
	}
	if unsupported {
		return nil, AutomationCredentialUnsupportedFlow, nil
	}
	var witness, origin string
	var valid, retired int
	err = tx.QueryRowContext(ctx, `SELECT witness,origin,valid,retired FROM local_automation_lifetimes WHERE kind='principal' AND name=? ORDER BY retired LIMIT 1`, m.name).Scan(&witness, &origin, &valid, &retired)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, AutomationCredentialNoLocalProof, nil
	}
	if err != nil {
		return nil, AutomationCredentialUnknown, err
	}
	if witness == "" || origin == "" || valid != 1 || retired != 0 {
		return nil, AutomationCredentialUnknown, &AutomationCredentialError{Kind: AutomationCredentialProofInvalid}
	}
	local := &LocalTx{tx: tx}
	if err := automationProjectionAuthorityTx(ctx, local); err != nil {
		return nil, AutomationCredentialUnknown, automationCredentialFailure(err, AutomationCredentialProofInvalid)
	}
	var candidates int
	err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM local_automation_identities WHERE stage='' AND kind='principal' AND alias=?) + (SELECT count(*) FROM local_automation_aliases WHERE stage='' AND kind='principal' AND alias=?)`, m.name, m.name).Scan(&candidates)
	if err != nil {
		return nil, AutomationCredentialUnknown, err
	}
	if candidates == 0 {
		return nil, AutomationCredentialNoLocalProof, nil
	}
	identity, err := automationPrincipalForLifetimeTx(ctx, tx, AutomationLifetimeEvidence{Kind: "principal", Name: m.name, Witness: witness, Origin: origin})
	if err != nil {
		return nil, AutomationCredentialUnknown, automationCredentialFailure(err, AutomationCredentialProofInvalid)
	}
	return &AutomationAccountAuthentication{username: m.name, witness: witness, parent: current, principalUID: identity.UID, clusterUID: identity.ClusterUID}, AutomationCredentialEligible, nil
}

// InsertAutomationSessionWithLoginData preserves the composite issuer's grant
// dispatch. Public completed-factor/external automation flows remain unsupported.
func InsertAutomationSessionWithLoginData(ctx context.Context, c *Client, g capabilities.FeatureGrant, a *AutomationAccountAuthentication, s SessionRecord, factor string, groups []string) error {
	if a == nil || a.principalUID == "" || a.clusterUID == "" || s.Realm != "local" || factor != "" || len(groups) != 0 {
		return &AutomationCredentialError{Kind: AutomationCredentialProofInvalid}
	}
	s.automationAuthentication = a
	return InsertSessionWithLoginData(ctx, c, g, s, factor, groups)
}

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

// accountCheck, when given (at most one, after stmts so the statement
// checkers keep their argument position), is checked inside the same
// transaction before anything is written: false fails the write with
// ErrUserAccountChanged (the token's account was re-created since its
// incarnation was read; token_incarnation.go).
func (c *Client) executeCredentialBatch(ctx context.Context, a *AutomationAccountAuthentication, kind, id, username string, stmts []Statement, accountCheck ...func(tx *sql.Tx) (bool, error)) (err error) {
	var account func(tx *sql.Tx) (bool, error)
	if len(accountCheck) > 0 {
		account = accountCheck[0]
	}
	if a == nil {
		if account == nil {
			return c.ExecuteBatch(ctx, stmts)
		}
		applied, err := c.ExecuteBatchGuarded(ctx, account, stmts)
		if err == nil && !applied {
			err = ErrUserAccountChanged
		}
		return err
	}
	defer func() { err = automationCredentialFailure(err, AutomationCredentialProofInvalid) }()
	if c.CredentialsUnhydrated() {
		return ErrAutomationLifecycleUnavailable
	}
	if username != a.username || id == "" {
		return ErrAutomationLifecycleUnavailable
	}
	mutation := &lifecycleMutation{kind: "principal", name: username, event: "issue", expected: a.parent, account: account, issuance: &automationIssuance{kind: kind, id: id, authenticated: a}}
	_, err = c.executeBatchWithLifecycle(ctx, stmts, true, false, mutation)
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
	if (i.authenticated.principalUID != "" && i.authenticated.principalUID != identity.UID) || (i.authenticated.clusterUID != "" && i.authenticated.clusterUID != identity.ClusterUID) {
		return ErrAutomationLifecycleUnavailable
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
	if i.kind == "session" {
		life, err := automationUserLifecycleTx(ctx, tx, m.name)
		if err != nil {
			return err
		}
		if life.SessionPredates(snapshot.Created) {
			return ErrAutomationLifecycleUnavailable
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO local_automation_credential_issuance(kind,credential_id,username,witness,principal_uid,cluster_uid,credential_digest,valid) VALUES(?,?,?,?,?,?,?,1)`, i.kind, i.id, m.name, m.previous.Witness, i.identity.UID, i.identity.ClusterUID, snapshot.digest())
	return err
}

func automationPrincipalForLifetimeTx(ctx context.Context, tx *sql.Tx, e AutomationLifetimeEvidence) (*contract.IdentityRecord, error) {
	local := &LocalTx{tx: tx}
	if err := automationProjectionAuthorityTx(ctx, local); err != nil {
		return nil, automationCredentialFailure(err, AutomationCredentialProofInvalid)
	}
	var uid string
	var count, wellFormed int
	// Validate the bounded row shape before the shared decoder. SQL/read errors
	// keep their causes; malformed present projection is a typed proof failure.
	err := tx.QueryRowContext(ctx, `SELECT count(*),COALESCE(min(i.uid),''),COALESCE(min(typeof(i.generation)='integer' AND i.generation>0 AND i.cluster_uid<>'' AND i.witness<>'' AND
 length(CAST(i.uid AS BLOB))+length(CAST(i.cluster_uid AS BLOB))+length(CAST(i.project_uid AS BLOB))+length(CAST(i.kind AS BLOB))+length(CAST(i.alias AS BLOB))+length(CAST(i.witness AS BLOB))<=?),0)
 FROM local_automation_identities i JOIN local_automation_aliases a ON a.stage=i.stage AND a.uid=i.uid AND a.cluster_uid=i.cluster_uid AND a.project_scope=i.project_uid AND a.kind=i.kind AND a.alias=i.alias AND a.generation=i.generation
 WHERE i.stage='' AND i.kind='principal' AND i.project_uid='' AND i.alias=? AND i.witness=? AND i.retired=0`, 6*contract.MaxStringBytes, e.Name, e.Witness).Scan(&count, &uid, &wellFormed)
	if err != nil {
		return nil, err
	}
	if count != 1 || wellFormed != 1 || uid == "" {
		return nil, ErrAutomationLifecycleUnavailable
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
		// The token's account incarnation is read beside it, outside the
		// snapshot (and its digest): a token opens only the incarnation it
		// was issued to (token_incarnation.go).
		var stamp, current string
		err = tx.QueryRowContext(ctx, `SELECT t.username,CASE WHEN c.token_id IS NOT NULL THEN c.token_hash ELSE t.token_hash END,t.name,COALESCE(t.scope_paths,''),t.created_at,COALESCE(t.expires_at,''),COALESCE(t.deleted_at,''),t.user_created_at,COALESCE(u.created_at,'') FROM tokens t LEFT JOIN token_credentials c ON c.token_id=t.id AND c.deleted_at IS NULL LEFT JOIN users u ON u.username=t.username WHERE t.id=?`, id).Scan(&s.Username, &s.Secret, &s.Name, &s.Scopes, &s.Created, &s.Expires, &revoked, &stamp, &current)
		if err == nil && !tokenIncarnationHolds(stamp, current) {
			return s, ErrAutomationLifecycleUnavailable
		}
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
func automationCredentialPrincipal(ctx context.Context, c *Client, kind, id string) (identityResult *contract.IdentityRecord, resultErr error) {
	defer func() {
		if !errors.Is(resultErr, ErrAutomationCredentialUnstamped) {
			resultErr = automationCredentialFailure(resultErr, AutomationCredentialProofInvalid)
		}
	}()
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	return automationCredentialPrincipalTx(ctx, tx, kind, id)
}

// The caller owns Client.mu and this transaction. Never call the public,
// self-locking credential reader from a local admission transaction.
func automationCredentialPrincipalTx(ctx context.Context, tx *sql.Tx, kind, id string) (*contract.IdentityRecord, error) {
	var username, witness, principal, cluster, digest string
	var valid int
	err := tx.QueryRowContext(ctx, `SELECT username,witness,principal_uid,cluster_uid,credential_digest,valid FROM local_automation_credential_issuance WHERE kind=? AND credential_id=?`, kind, id).Scan(&username, &witness, &principal, &cluster, &digest, &valid)
	if errors.Is(err, sql.ErrNoRows) {
		if kind == "session" {
			return nil, ErrAutomationCredentialUnstamped
		}
		return nil, ErrAutomationLifecycleUnavailable
	}
	if err != nil {
		return nil, err
	}
	if valid != 1 {
		return nil, ErrAutomationLifecycleUnavailable
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
