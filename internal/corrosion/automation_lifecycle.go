package corrosion

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"golang.org/x/crypto/bcrypt"
	"time"
)

// ErrAutomationLifecycleUnavailable means no current positive source proof
// exists. It never permits inferring an absent or new account lifetime.
var ErrAutomationLifecycleUnavailable = errors.New("automation lifecycle provenance unavailable")

// AutomationLifetimeEvidence describes an originating lifecycle observation.
// It is not a certified identity, class permit, or a historical birth claim.
type AutomationLifetimeEvidence struct {
	Kind, Name, Witness, Origin string
}

func AutomationLifetime(ctx context.Context, c *Client, kind, name string) (AutomationLifetimeEvidence, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return AutomationLifetimeEvidence{}, err
	}
	defer tx.Rollback()
	return automationLifetimeTx(ctx, tx, kind, name)
}

func automationLifetimeTx(ctx context.Context, tx *sql.Tx, kind, name string) (AutomationLifetimeEvidence, error) {
	row, err := lifecycleParentTx(ctx, tx, kind, name)
	if err != nil {
		return AutomationLifetimeEvidence{}, err
	}
	if !row.exists || row.deleted != "" {
		return AutomationLifetimeEvidence{}, ErrAutomationLifecycleUnavailable
	}
	e := AutomationLifetimeEvidence{Kind: kind, Name: name}
	err = tx.QueryRowContext(ctx, `SELECT witness,origin FROM local_automation_lifetimes WHERE kind=? AND name=? AND retired=0 AND valid=1`, kind, name).Scan(&e.Witness, &e.Origin)
	if errors.Is(err, sql.ErrNoRows) {
		err = ErrAutomationLifecycleUnavailable
	}
	return e, err
}

// Every field is compared again inside the existing parent write transaction.
// These values never escape into a public identity or error.
type lifecycleParent struct {
	exists                                   bool
	deleted, created, updated, secret, realm string
}

func lifecycleParentTx(ctx context.Context, tx *sql.Tx, kind, name string) (lifecycleParent, error) {
	var p lifecycleParent
	var err error
	switch kind {
	case "principal":
		err = tx.QueryRowContext(ctx, `SELECT COALESCE(u.deleted_at,''),u.created_at,u.updated_at,
   CASE WHEN c.username IS NOT NULL THEN c.password_hash ELSE u.password_hash END,COALESCE(u.realm,'local')
   FROM users u LEFT JOIN user_credentials c ON c.username=u.username AND c.deleted_at IS NULL WHERE u.username=?`, name).Scan(&p.deleted, &p.created, &p.updated, &p.secret, &p.realm)
	case "project":
		err = tx.QueryRowContext(ctx, `SELECT COALESCE(deleted_at,''),created_at,updated_at FROM projects WHERE name=?`, name).Scan(&p.deleted, &p.created, &p.updated)
	default:
		return p, ErrAutomationLifecycleUnavailable
	}
	if errors.Is(err, sql.ErrNoRows) {
		return p, nil
	}
	p.exists = err == nil
	return p, err
}

type lifecycleMutation struct {
	issuance *automationIssuance
	// account, when set, is a credential's account check, run first in the
	// transaction (executeCredentialBatch).
	account           func(tx *sql.Tx) (bool, error)
	kind, name, event string
	expected          lifecycleParent
	previous          AutomationLifetimeEvidence
}

func (c *Client) executeLifecycleBatch(ctx context.Context, stmts []Statement, kind, name, event string) error {
	// Capture before taking the write lock; before() makes this a strict CAS.
	c.mu.Lock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		c.mu.Unlock()
		return err
	}
	expected, err := lifecycleParentTx(ctx, tx, kind, name)
	tx.Rollback()
	c.mu.Unlock()
	if err != nil {
		return err
	}
	_, err = c.executeBatchWithLifecycle(ctx, stmts, true, false, &lifecycleMutation{kind: kind, name: name, event: event, expected: expected})
	return err
}

// executeGuardedLifecycleBatch observes only a successful originating lifecycle
// decision. The executor captures its parent after the guard passes, and rolls
// back both the parent and this evidence if either lifecycle callback fails.
func (c *Client) executeGuardedLifecycleBatch(ctx context.Context, guard func(tx *sql.Tx) (bool, error), stmts []Statement, kind, name, event string) (bool, error) {
	return c.executeEntriesGuardedWithLifecycle(ctx, guard, [][]Statement{stmts}, &lifecycleMutation{kind: kind, name: name, event: event})
}

func (m *lifecycleMutation) before(ctx context.Context, tx *sql.Tx) error {
	if m.account != nil {
		if ok, err := m.account(tx); err != nil {
			return err
		} else if !ok {
			return ErrUserAccountChanged
		}
	}
	current, err := lifecycleParentTx(ctx, tx, m.kind, m.name)
	if err != nil {
		return err
	}
	if current != m.expected {
		return ErrAutomationLifecycleUnavailable
	}
	if m.issuance != nil {
		return m.issuance.check(ctx, tx, m)
	}
	m.previous, err = automationLifetimeTx(ctx, tx, m.kind, m.name)
	if errors.Is(err, ErrAutomationLifecycleUnavailable) {
		return nil
	}
	return err
}
func (m *lifecycleMutation) after(ctx context.Context, tx *sql.Tx) error {
	current, err := lifecycleParentTx(ctx, tx, m.kind, m.name)
	if err != nil {
		return err
	}
	switch m.event {
	case "issue":
		if m.issuance == nil || current != m.expected {
			return ErrAutomationLifecycleUnavailable
		}
		return m.issuance.persist(ctx, tx, m)
	case "enroll":
		if !current.exists || current.deleted != "" || current != m.expected {
			return ErrAutomationLifecycleUnavailable
		}
		if err = automationPasswordAccountAllowedTx(ctx, tx, m.name); err != nil {
			return err
		}
		if m.previous.Witness != "" {
			return nil
		}
		var witness [32]byte
		if _, err = rand.Read(witness[:]); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO local_automation_lifetimes(kind,name,witness,origin,retired,valid) VALUES(?,?,?,'enrollment',0,1)`, m.kind, m.name, hex.EncodeToString(witness[:]))

	case "birth":
		if m.expected.exists && m.expected.deleted == "" {
			return ErrAutomationLifecycleUnavailable
		}
		if !current.exists || current.deleted != "" {
			return ErrAutomationLifecycleUnavailable
		}
		// A new witness is minted only after the real birth SQL succeeded inside
		// this same transaction. It has no certified-UID meaning.
		if _, err = tx.ExecContext(ctx, `UPDATE local_automation_lifetimes SET retired=1,valid=0 WHERE kind=? AND name=?`, m.kind, m.name); err != nil {
			return err
		}
		var witness [32]byte
		if _, err = rand.Read(witness[:]); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO local_automation_lifetimes(kind,name,witness,origin,retired,valid) VALUES(?,?,?,'birth',0,1)`, m.kind, m.name, hex.EncodeToString(witness[:]))
	case "retire":
		if current.exists && current.deleted == "" {
			return ErrAutomationLifecycleUnavailable
		}
		_, err = tx.ExecContext(ctx, `UPDATE local_automation_lifetimes SET retired=1,valid=0 WHERE kind=? AND name=?`, m.kind, m.name)
	case "rotate":
		if m.previous.Witness == "" {
			return nil
		} // missing proof never self-heals
		if !current.exists || current.deleted != "" || current.created != m.expected.created || current.realm != m.expected.realm {
			return ErrAutomationLifecycleUnavailable
		}
		_, err = tx.ExecContext(ctx, `UPDATE local_automation_lifetimes SET valid=1 WHERE kind=? AND name=? AND witness=? AND retired=0`, m.kind, m.name, m.previous.Witness)
	default:
		return ErrAutomationLifecycleUnavailable
	}
	return err
}

// AutomationAccountAuthentication is an opaque, locally authenticated account
// observation. Prepared session handles also pin an existing certified identity;
// neither form carries permissions or business admission authority.
func (*AutomationAccountAuthentication) String() string { return "automation-account-authentication" }

type AutomationAccountAuthentication struct {
	identity                 contract.IdentityRecord
	db                       *Client
	proof                    automationCredentialProof
	username, witness        string
	origin                   string
	principalUID, clusterUID string
	parent                   lifecycleParent
}

// EnrollAutomationLocalAccount establishes source evidence from this verified
// password authentication onward. It never asserts a historical birth or
// assigns a principal UID. Accounts requiring a second factor must use a future
// completed-login adapter; a password alone cannot enroll them here.
func EnrollAutomationLocalAccount(ctx context.Context, c *Client, username, password string) (AutomationLifetimeEvidence, error) {
	m, err := authenticateAutomationLocal(ctx, c, username, password)
	if err != nil {
		return AutomationLifetimeEvidence{}, err
	}
	m.event = "enroll"
	if _, err = c.executeBatchWithLifecycle(ctx, []Statement{}, false, false, m); err != nil {
		return AutomationLifetimeEvidence{}, err
	}
	return AutomationLifetime(ctx, c, "principal", m.name)
}

func AuthenticateAutomationLocalAccount(ctx context.Context, c *Client, username, password string) (*AutomationAccountAuthentication, error) {
	m, err := authenticateAutomationLocal(ctx, c, username, password)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if err = m.before(ctx, tx); err != nil {
		return nil, err
	}
	if err = automationPasswordAccountAllowedTx(ctx, tx, m.name); err != nil {
		return nil, err
	}
	if m.previous.Witness == "" {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return &AutomationAccountAuthentication{db: c, proof: automationCredentialProof{mode: automationProofOrigin, witness: m.previous.Witness}, username: m.name, witness: m.previous.Witness, origin: m.previous.Origin, parent: m.expected}, nil
}

func authenticateAutomationLocal(ctx context.Context, c *Client, username, password string) (*lifecycleMutation, error) {
	if password == "" || c.CredentialsUnhydrated() {
		return nil, ErrAutomationLifecycleUnavailable
	}
	user, err := GetUser(ctx, c, username)
	if err != nil {
		return nil, err
	}
	if user == nil || user.Realm != "local" {
		return nil, ErrAutomationLifecycleUnavailable
	}
	c.mu.Lock()
	tx, err := c.db.BeginTx(ctx, nil)
	if err != nil {
		c.mu.Unlock()
		return nil, err
	}
	parent, err := lifecycleParentTx(ctx, tx, "principal", user.Username)
	tx.Rollback()
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !parent.exists || parent.deleted != "" || parent.realm != "local" || bcrypt.CompareHashAndPassword([]byte(parent.secret), []byte(password)) != nil {
		return nil, ErrAutomationLifecycleUnavailable
	}
	return &lifecycleMutation{kind: "principal", name: user.Username, expected: parent}, nil
}

func automationPasswordAccountAllowedTx(ctx context.Context, tx *sql.Tx, name string) error {
	if err := automationPasswordAccountCurrentTx(ctx, tx, name); err != nil {
		return err
	}
	required, err := automationPasswordFactorRequiredTx(ctx, tx, name)
	if err != nil {
		return err
	}
	if required {
		return ErrAutomationLifecycleUnavailable
	}
	return nil
}

func automationPasswordFactorRequiredTx(ctx context.Context, tx *sql.Tx, name string) (bool, error) {
	var policy string
	err := tx.QueryRowContext(ctx, `SELECT value FROM cluster_policies WHERE key=? AND deleted_at IS NULL`, LoginTwoFactorPolicyKey).Scan(&policy)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	p, parseErr := ParseTwoFactorPolicy(policy)
	// Unknown stored values have the same fail-closed All semantics as Login.
	required := parseErr != nil || p.Requires("local")
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM user_2fa WHERE username=? AND deleted_at IS NULL AND epoch=(SELECT active_epoch FROM user_2fa_sets WHERE username=? AND deleted_at IS NULL)`, name, name).Scan(&count); err != nil {
		return false, err
	}
	if required || count != 0 {
		return true, nil
	}
	// Held factors are never accepted, but their account cannot fall back to
	// password-only automation authentication. Match ListHeldUser2FA inside
	// this same authorization transaction rather than taking a second read.
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM user_2fa WHERE username=? AND deleted_at IS NULL AND epoch || ?=(SELECT active_epoch FROM user_2fa_sets WHERE username=? AND deleted_at IS NULL)`, name, userEpochHeldSuffix, name).Scan(&count); err != nil {
		return false, err
	}
	return count != 0, nil
}

func automationPasswordAccountCurrentTx(ctx context.Context, tx *sql.Tx, name string) error {
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM users u WHERE `+usernameNormSQL+`=? AND u.deleted_at IS NULL`, NormalizeUsername(name)).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return ErrAutomationLifecycleUnavailable
	}
	rows, err := tx.QueryContext(ctx, `SELECT attribute,value FROM user_lifecycle WHERE username=? AND deleted_at IS NULL`, name)
	if err != nil {
		return err
	}
	defer rows.Close()
	var life UserLifecycle
	for rows.Next() {
		var attr, value string
		if err := rows.Scan(&attr, &value); err != nil {
			return err
		}
		switch attr {
		case UserAttrDisabled:
			life.Disabled = value != "false"
		case UserAttrExpiresAt:
			life.ExpiresAt = value
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if life.InactiveReason(time.Now()) != "" {
		return ErrAutomationLifecycleUnavailable
	}
	return nil
}
