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
	identity, err := automationCertifiedIdentityForAliasTx(ctx, tx, "principal", m.name)
	if err != nil {
		return nil, AutomationCredentialUnknown, automationCredentialFailure(err, AutomationCredentialProofInvalid)
	}
	if identity != nil {
		proof, err := automationIdentityContinuityProofTx(ctx, c, tx, identity)
		if err != nil {
			return nil, AutomationCredentialUnknown, automationCredentialFailure(err, AutomationCredentialProofInvalid)
		}
		if proof != nil {
			return &AutomationAccountAuthentication{db: c, identity: *identity, proof: *proof, username: m.name, parent: current, principalUID: identity.UID, clusterUID: identity.ClusterUID}, AutomationCredentialEligible, nil
		}
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
	identity, err = automationPrincipalForLifetimeTx(ctx, tx, AutomationLifetimeEvidence{Kind: "principal", Name: m.name, Witness: witness, Origin: origin})
	if err != nil {
		return nil, AutomationCredentialUnknown, automationCredentialFailure(err, AutomationCredentialProofInvalid)
	}
	return &AutomationAccountAuthentication{db: c, identity: *identity, proof: automationCredentialProof{mode: automationProofOrigin, witness: witness}, username: m.name, witness: witness, origin: origin, parent: current, principalUID: identity.UID, clusterUID: identity.ClusterUID}, AutomationCredentialEligible, nil
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
	if a.db != c || !a.proof.valid(kind) || username != a.username || id == "" {
		return ErrAutomationLifecycleUnavailable
	}
	mutation := &lifecycleMutation{kind: "principal", name: username, event: "issue", expected: a.parent, account: account, issuance: &automationIssuance{kind: kind, id: id, authenticated: a}}
	_, err = c.executeBatchWithLifecycle(ctx, stmts, true, false, mutation)
	return err
}
func (i *automationIssuance) check(ctx context.Context, tx *sql.Tx, m *lifecycleMutation) error {
	a := i.authenticated
	if a == nil || a.db == nil || !a.proof.valid(i.kind) {
		return ErrAutomationLifecycleUnavailable
	}
	current, err := lifecycleParentTx(ctx, tx, "principal", m.name)
	if err != nil {
		return err
	}
	if current != a.parent {
		return ErrAutomationLifecycleUnavailable
	}
	if err := automationPasswordAccountAllowedTx(ctx, tx, m.name); err != nil {
		return err
	}
	var identity *contract.IdentityRecord
	switch a.proof.mode {
	case automationProofOrigin:
		evidence, err := automationLifetimeTx(ctx, tx, "principal", m.name)
		if err != nil {
			return err
		}
		if evidence.Witness != a.proof.witness || evidence.Origin != a.origin || a.witness != a.proof.witness {
			return ErrAutomationLifecycleUnavailable
		}
		m.previous = evidence
		identity, err = automationPrincipalForLifetimeTx(ctx, tx, evidence)
		if err != nil {
			return err
		}
	case automationProofContinuity:
		identity, err = automationCertifiedIdentityForAliasTx(ctx, tx, "principal", m.name)
		if err != nil {
			return err
		}
		if identity == nil {
			return ErrAutomationLifecycleUnavailable
		}
		proof, err := automationIdentityContinuityProofTx(ctx, a.db, tx, identity)
		if err != nil {
			return err
		}
		if proof == nil || *proof != a.proof {
			return ErrAutomationLifecycleUnavailable
		}
	default:
		return ErrAutomationLifecycleUnavailable
	}
	if (a.principalUID != "" && a.principalUID != identity.UID) || (a.clusterUID != "" && a.clusterUID != identity.ClusterUID) {
		return ErrAutomationLifecycleUnavailable
	}
	// Prepared handles pin the complete certified identity observed at login.
	// Legacy origin handles select it in this transaction; every later check
	// must preserve that first selection across the actual credential INSERT.
	if (a.identity.UID != "" && a.identity != *identity) || (i.identity != nil && *i.identity != *identity) {
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
	_, err = tx.ExecContext(ctx, `INSERT INTO local_automation_credential_issuance(kind,credential_id,username,witness,principal_uid,cluster_uid,credential_digest,valid,proof_mode,identity_generation,original_witness,parent_kind,parent_alias,parent_realm,parent_birth) VALUES(?,?,?,?,?,?,?,1,?,?,?,?,?,?,?)`, i.kind, i.id, m.name, i.authenticated.proof.witness, i.identity.UID, i.identity.ClusterUID, snapshot.digest(), i.authenticated.proof.mode, i.authenticated.proof.generation, i.authenticated.proof.originalWitness, i.authenticated.proof.parent.Kind, i.authenticated.proof.parent.Alias, i.authenticated.proof.parent.Realm, i.authenticated.proof.parent.Birth)
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
	return automationCredentialPrincipalTx(ctx, c, tx, kind, id)
}

// The caller owns Client.mu and this transaction. Never call the public,
// self-locking credential reader from a local admission transaction.
func automationCredentialPrincipalTx(ctx context.Context, c *Client, tx *sql.Tx, kind, id string) (*contract.IdentityRecord, error) {
	var username, principal, cluster, digest string
	var proof automationCredentialProof
	var generation int64
	var valid, wellFormed int
	const columns = `username,witness,principal_uid,cluster_uid,credential_digest,valid,proof_mode,identity_generation,original_witness,parent_kind,parent_alias,parent_realm,parent_birth`
	// Probe SQL types before scanning: conversion of a malformed present value
	// is proof corruption, while an actual query failure preserves its cause.
	err := tx.QueryRowContext(ctx, `SELECT typeof(username)='text' AND length(CAST(username AS BLOB))<=? AND typeof(witness)='text' AND length(CAST(witness AS BLOB))<=? AND typeof(principal_uid)='text' AND length(CAST(principal_uid AS BLOB))<=? AND typeof(cluster_uid)='text' AND length(CAST(cluster_uid AS BLOB))<=? AND typeof(credential_digest)='text' AND length(CAST(credential_digest AS BLOB))=64 AND typeof(valid)='integer' AND valid IN(0,1) AND typeof(proof_mode)='text' AND proof_mode IN('origin','continuity') AND typeof(identity_generation)='integer' AND identity_generation>=0 AND typeof(original_witness)='text' AND length(CAST(original_witness AS BLOB))<=? AND typeof(parent_kind)='text' AND length(CAST(parent_kind AS BLOB))<=? AND typeof(parent_alias)='text' AND length(CAST(parent_alias AS BLOB))<=? AND typeof(parent_realm)='text' AND length(CAST(parent_realm AS BLOB))<=? AND typeof(parent_birth)='text' AND length(CAST(parent_birth AS BLOB))<=? FROM local_automation_credential_issuance WHERE kind=? AND credential_id=?`, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, contract.MaxStringBytes, kind, id).Scan(&wellFormed)
	if errors.Is(err, sql.ErrNoRows) {
		if kind == "session" {
			return nil, ErrAutomationCredentialUnstamped
		}
		return nil, ErrAutomationLifecycleUnavailable
	}
	if err != nil {
		return nil, err
	}
	if wellFormed != 1 {
		return nil, ErrAutomationLifecycleUnavailable
	}
	err = tx.QueryRowContext(ctx, `SELECT `+columns+` FROM local_automation_credential_issuance WHERE kind=? AND credential_id=?`, kind, id).Scan(&username, &proof.witness, &principal, &cluster, &digest, &valid, &proof.mode, &generation, &proof.originalWitness, &proof.parent.Kind, &proof.parent.Alias, &proof.parent.Realm, &proof.parent.Birth)
	if err != nil {
		return nil, err
	}
	proof.generation = uint64(generation)
	if valid != 1 || !proof.valid(kind) || principal == "" || cluster == "" {
		return nil, ErrAutomationLifecycleUnavailable
	}
	var evidence AutomationLifetimeEvidence
	if proof.mode == automationProofOrigin {
		evidence, err = automationLifetimeTx(ctx, tx, "principal", username)
		if err != nil {
			return nil, err
		}
		if evidence.Witness != proof.witness {
			return nil, ErrAutomationLifecycleUnavailable
		}
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
	var identity *contract.IdentityRecord
	if proof.mode == automationProofOrigin {
		identity, err = automationPrincipalForLifetimeTx(ctx, tx, evidence)
	} else {
		identity, err = automationCertifiedIdentityForAliasTx(ctx, tx, "principal", username)
		if err == nil && identity != nil {
			var current *automationCredentialProof
			current, err = automationIdentityContinuityProofTx(ctx, c, tx, identity)
			if err == nil && (current == nil || *current != proof) {
				err = ErrAutomationLifecycleUnavailable
			}
		} else if err == nil {
			err = ErrAutomationLifecycleUnavailable
		}
	}
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
