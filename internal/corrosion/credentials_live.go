package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// "Credentials live": this node has completed a SplitCredentials pass with the
// credentials_split_v1 gate open, so every secret it held in an old column has
// a credential row. A pass that left a host password uncopied until the
// sensitive lane merged (CredentialSplitReport.Deferred) does not count.
//
// Two things hang on it.
//
// READINESS. credentials_clear_v1 is advertised only by a live node
// (grpcapi's advertisement filter). So the clear cannot latch anywhere until
// every replication recipient has completed its first pass, and at the moment
// a node completes that pass no old column has been cleared anywhere in the
// cluster.
//
// EXTERNAL USERS. An external-realm user (OIDC/LDAP) is a users row with an
// empty password_hash. Once the clear exists, an empty old column with no
// credential row can also be a LOCAL account whose credential row has not
// arrived yet (anti-entropy merges users and user_credentials separately), and
// auth.EnsureUserShadow must never adopt that one. So a users row is judged
// external only on POSITIVE evidence, never on an absence:
//
//   - a live credential row that holds '' — written by a shadow created after
//     the split, by a node's first live pass (below), or by an administrator's
//     `lv user mark-external` (MarkUserExternal) — and that is not older than
//     the users row's own updated_at (emptyCredentialHolds);
//   - or, on this node and only until it is live, PER-USER evidence bound to
//     the users row as it stood (username, created_at and the row's own
//     updated_at), so a local account cleared later never matches it, and
//     neither does a name deleted and created again — which REACTIVATES the
//     row and keeps its created_at (users rows are never hard-deleted), but
//     always moves its updated_at:
//     the CREDENTIALS BASELINE, the users that had an empty old column and no
//     credential row in this node's own database when this build first started
//     on it (recorded before replication can bring anything, fsynced, and
//     bound to the state.db's incarnation), when nothing in that database
//     showed a clear; and the EXTERNAL-SEEN set, shadows this node created
//     itself while it could not write a credential row.
//
// A node's first live pass gives each user with such evidence an empty
// credential row stamped evidenceStamp(the users row's updated_at), so any real
// credential write beats it; the row replicates the evidence to every peer.
//
// Every piece of evidence describes the users row AS IT STOOD. The row's own
// updated_at moves only when the account itself is written — created,
// reactivated, deleted, its password set, its old column cleared — never for
// anything unrelated (no other writer touches users). Evidence about an
// earlier version is therefore dropped, and the account is judged afresh: at
// worst a transient fail-closed refusal (Unavailable, or FailedPrecondition
// naming `lv user mark-external`), never an external principal adopting a
// local account whose credential is still in flight. This compares a row with
// its own earlier stamp, or reads an empty credential row FAIL-CLOSED against
// it; it never picks a winner between a copy and its parent by updated_at
// (CLAUDE.md), so nothing stale is ever brought back by it.

// credentialsLiveFile is the durable half of credentialsLive. NODE-LOCAL.
const credentialsLiveFile = "credentials_split_live"

// credentialsBaselineFile holds the credentials baseline. NODE-LOCAL.
const credentialsBaselineFile = "credentials_baseline"

// externalSeenFile holds the external-seen set. NODE-LOCAL.
const externalSeenFile = "credentials_external_seen"

// credentialEvidenceShift moves the stamp of an evidence row (a materialised
// shadow credential or an administrator's mark) decades back: older than any
// real credential write, so it never replaces a credential and only fills an
// absence. The shift is a fixed duration, so it is exactly undone on read
// (evidenceMadeAt): the row still says when it was made.
const credentialEvidenceShift = 40 * 365 * 24 * time.Hour

// credentialEvidenceCeiling: every evidence row is stamped before it, every
// real credential write after it.
var credentialEvidenceCeiling = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// evidenceStamp is the updated_at of an evidence row made at instant at.
func evidenceStamp(at time.Time) string {
	return at.Add(-credentialEvidenceShift).UTC().Format(nowTSLayout)
}

// evidenceMadeAt is the instant an empty credential row stands for: the
// decoded instant of an evidence row, the row's own instant otherwise.
func evidenceMadeAt(credTS string) (time.Time, bool) {
	at, ok := tsInstant(credTS)
	if !ok {
		return time.Time{}, false
	}
	if at.Before(credentialEvidenceCeiling) {
		return at.Add(credentialEvidenceShift), true
	}
	return at, true
}

// emptyCredentialHolds reports whether an empty credential row stamped credTS
// is evidence that the users row stamped usersTS is an external user. It holds
// only when it was made no earlier than that version of the users row: a
// shadow writes both in one batch at one timestamp, a first pass stamps the
// users row's own, and a mark is made after it. A users row written since —
// above all a name deleted and created again as a local account, whose
// credential row has not arrived — is not what the row was written for
// (re-review 3, R1 and R2). Unreadable stamps hold nothing.
func emptyCredentialHolds(credTS, usersTS string) bool {
	made, ok := evidenceMadeAt(credTS)
	if !ok {
		return false
	}
	u, ok := tsInstant(usersTS)
	if !ok {
		return false
	}
	return !made.Before(u)
}

// userIdentity is one version of a users row: its name, its incarnation and
// the row's own updated_at.
type userIdentity struct {
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// credentialsBaseline is the persisted baseline, bound to the state.db
// incarnation that recorded it.
type credentialsBaseline struct {
	Incarnation string         `json:"incarnation"`
	Shadows     []userIdentity `json:"shadows"`
}

// NoteCredentialsBaseline records the credentials baseline for this state.db
// if it has not been recorded yet. The daemon calls it right after InitSchema,
// before replication or anti-entropy can bring any row
// (TestRunNotesTheCredentialsBaselineBeforeReplication pins that). Idempotent
// per incarnation: the first answer stands, and a lost or replaced state.db
// (a new incarnation) is recorded afresh from what it holds then — usually
// nothing.
func (c *Client) NoteCredentialsBaseline(ctx context.Context) error {
	c.externalSeenMu.Lock()
	defer c.externalSeenMu.Unlock()
	if c.baselineLoaded {
		return nil
	}
	inc, err := c.VoterIncarnation(ctx)
	if err != nil {
		return err
	}
	if c.dataDir != "" {
		b, err := os.ReadFile(filepath.Join(c.dataDir, credentialsBaselineFile))
		if err == nil {
			var bl credentialsBaseline
			if json.Unmarshal(b, &bl) == nil && bl.Incarnation == inc && inc != "" {
				c.setBaselineLocked(bl.Shadows)
				return nil
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	shadows, err := baselineShadows(ctx, c)
	if err != nil {
		return err
	}
	if c.dataDir != "" {
		b, err := json.Marshal(credentialsBaseline{Incarnation: inc, Shadows: shadows})
		if err != nil {
			return err
		}
		// Fsynced and renamed into place: a baseline lost to a power cut
		// would be recorded again after anti-entropy had brought rows in.
		if err := secretfile.Write(filepath.Join(c.dataDir, credentialsBaselineFile), b, 0o600); err != nil {
			return err
		}
	}
	c.setBaselineLocked(shadows)
	return nil
}

// baselineShadows is what the baseline records: every live users row with an
// empty old column and no credential row — unless anything in this database
// already shows a clear, in which case nothing (an empty old column may then
// be a cleared local account).
func baselineShadows(ctx context.Context, c *Client) ([]userIdentity, error) {
	evidence, err := clearEvidence(ctx, c)
	if err != nil || evidence {
		return nil, err
	}
	rows, err := c.Query(ctx, `SELECT u.username, u.created_at, u.updated_at FROM users u
		 WHERE u.deleted_at IS NULL AND u.password_hash = ''
		   AND NOT EXISTS (SELECT 1 FROM user_credentials k WHERE k.username = u.username)`)
	if err != nil {
		return nil, err
	}
	out := make([]userIdentity, 0, len(rows))
	for _, r := range rows {
		out = append(out, rowIdentity(r))
	}
	return out, nil
}

func rowIdentity(r Row) userIdentity {
	return userIdentity{Username: r.String("username"), CreatedAt: r.String("created_at"), UpdatedAt: r.String("updated_at")}
}

func (c *Client) setBaselineLocked(shadows []userIdentity) {
	c.baselineSet = map[userIdentity]bool{}
	for _, s := range shadows {
		c.baselineSet[s] = true
	}
	c.baselineLoaded = true
}

// CredentialsLive reports whether this node has completed a credentials split
// pass with the gate open.
func (c *Client) CredentialsLive() bool {
	if c.credentialsLive.Load() {
		return true
	}
	if c.dataDir == "" || c.credentialsLiveChecked.Swap(true) {
		return false
	}
	if _, err := os.Stat(filepath.Join(c.dataDir, credentialsLiveFile)); err != nil {
		return false
	}
	c.credentialsLive.Store(true)
	return true
}

// afterCredentialPass marks this node live after its first complete pass,
// materialising the external users it holds positive evidence for first.
func (c *Client) afterCredentialPass(ctx context.Context, passErr error) {
	if passErr != nil || c.CredentialsLive() {
		return
	}
	if err := c.materialiseEvidencedShadows(ctx); err != nil {
		slog.Warn("credentials split: shadow credentials incomplete; not live yet", "error", err)
		return
	}
	c.credentialsLive.Store(true)
	if c.dataDir == "" {
		return
	}
	if err := secretfile.Write(filepath.Join(c.dataDir, credentialsLiveFile), []byte("1\n"), 0o600); err != nil {
		c.credentialsLive.Store(false)
		slog.Warn("credentials split: could not persist the live marker; retrying next pass", "error", err)
	}
}

// clearEvidence reports whether this node holds a row that only a clear
// produces: an empty old column beside a live, non-empty credential row.
func clearEvidence(ctx context.Context, c *Client) (bool, error) {
	rows, err := c.Query(ctx, `SELECT 1 AS x WHERE
		EXISTS (SELECT 1 FROM users u JOIN user_credentials k ON k.username = u.username
		         WHERE u.password_hash = '' AND k.deleted_at IS NULL AND k.password_hash != '')
		OR EXISTS (SELECT 1 FROM tokens t JOIN token_credentials k ON k.token_id = t.id
		         WHERE t.token_hash = '' AND k.deleted_at IS NULL AND k.token_hash != '')
		OR EXISTS (SELECT 1 FROM hosts h JOIN host_fence_credentials k ON k.host_name = h.name
		         WHERE COALESCE(h.ipmi_pass, '') = '' AND k.deleted_at IS NULL AND k.ipmi_pass != '')`)
	if err != nil {
		return false, err
	}
	return len(rows) > 0, nil
}

// materialiseEvidencedShadows gives every user this node holds per-user
// evidence for — whose CURRENT row still matches that evidence, has an empty
// old column and no credential row — an empty credential row stamped with
// evidenceStamp of the users row's own updated_at, so it holds for that
// version of the row only.
func (c *Client) materialiseEvidencedShadows(ctx context.Context) error {
	rows, err := c.Query(ctx, `SELECT u.username, u.created_at, u.updated_at FROM users u
		 WHERE u.deleted_at IS NULL AND u.password_hash = ''
		   AND NOT EXISTS (SELECT 1 FROM user_credentials k WHERE k.username = u.username)`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		id := rowIdentity(r)
		if !c.externalEvidence(id) {
			continue
		}
		at, ok := tsInstant(id.UpdatedAt)
		if !ok {
			slog.Warn("credentials split: an external user's row has no readable timestamp; "+
				"not materialised", "user", id.Username)
			continue
		}
		if err := c.copyUserCredential(ctx, id.Username, "", evidenceStamp(at)); err != nil {
			return err
		}
	}
	return nil
}

// externalEvidence reports whether this node holds per-user evidence that the
// users row incarnation id is an external user: the baseline or the
// external-seen set. Both are node-local and consulted only by this node's own
// first pass and while it is not live.
func (c *Client) externalEvidence(id userIdentity) bool {
	c.externalSeenMu.Lock()
	defer c.externalSeenMu.Unlock()
	if c.baselineSet[id] {
		return true
	}
	return c.loadExternalSeenLocked()[id]
}

// UserLocalCredential reports whether username is a LOCAL account — one with
// a password — and whether this node can tell. known is false for a live users
// row with an empty old column, no credential row and no positive evidence on
// this node: that is either an external user whose evidence has not reached
// this node or a local account whose credential row has not, and the caller
// must not guess. known is false too when there is no live row under exactly
// username (credentials-clear M1): its caller holds a live row, so "none"
// means the name was spelled differently, which says nothing about the
// account.
func UserLocalCredential(ctx context.Context, c *Client, username string) (local, known bool, err error) {
	rows, err := c.Query(ctx, userLocalCredentialSQL, username)
	if err != nil {
		return false, false, err
	}
	if len(rows) == 0 {
		return false, false, nil
	}
	r := rows[0]
	local, known = c.judgeUserRow(rowIdentity(r), r.String("password_hash"),
		r.String("cred_key") != "", r.String("cred_val"), r.String("cred_ts"))
	return local, known, nil
}

const userLocalCredentialSQL = `SELECT u.username, u.password_hash, u.created_at, u.updated_at,
	        k.username AS cred_key, k.password_hash AS cred_val, k.updated_at AS cred_ts
	   FROM users u LEFT JOIN user_credentials k ON k.username = u.username AND k.deleted_at IS NULL
	  WHERE u.username = ? AND u.deleted_at IS NULL`

// judgeUserRow is UserLocalCredential's decision for one live users row: its
// version id, its old column and its live credential row (credKey false when
// there is none).
func (c *Client) judgeUserRow(id userIdentity, oldVal string, credKey bool, credVal, credTS string) (local, known bool) {
	if credKey {
		if credVal != "" {
			return true, true
		}
		if emptyCredentialHolds(credTS, id.UpdatedAt) {
			return false, true
		}
		// An empty credential row older than the users row: evidence about
		// an earlier version, judged as if there were none.
	}
	if oldVal != "" {
		return true, true
	}
	if !c.CredentialsLive() && c.externalEvidence(id) {
		return false, true
	}
	return false, false
}

// noteExternalShadow records the users row incarnation id as a shadow this
// node created while it could not write a credential row. Called only after
// the insert succeeded.
func (c *Client) noteExternalShadow(id userIdentity) {
	c.externalSeenMu.Lock()
	defer c.externalSeenMu.Unlock()
	seen := c.loadExternalSeenLocked()
	if seen[id] {
		return
	}
	seen[id] = true
	c.saveExternalSeenLocked()
}

// forgetExternalShadow drops every recorded version of username: it was
// deleted, reactivated, or written again as a local account.
func (c *Client) forgetExternalShadow(username string) {
	c.externalSeenMu.Lock()
	defer c.externalSeenMu.Unlock()
	seen := c.loadExternalSeenLocked()
	changed := false
	for id := range seen {
		if id.Username == username {
			delete(seen, id)
			changed = true
		}
	}
	if changed {
		c.saveExternalSeenLocked()
	}
}

func (c *Client) saveExternalSeenLocked() {
	if c.dataDir == "" {
		return
	}
	ids := make([]userIdentity, 0, len(c.externalSeenSet))
	for id := range c.externalSeenSet {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if ids[i].Username != ids[j].Username {
			return ids[i].Username < ids[j].Username
		}
		if ids[i].CreatedAt != ids[j].CreatedAt {
			return ids[i].CreatedAt < ids[j].CreatedAt
		}
		return ids[i].UpdatedAt < ids[j].UpdatedAt
	})
	b, _ := json.Marshal(ids)
	if err := secretfile.Write(filepath.Join(c.dataDir, externalSeenFile), b, 0o600); err != nil {
		slog.Warn("credentials: could not record an external shadow; it is judged by the credential row instead",
			"error", err)
	}
}

func (c *Client) loadExternalSeenLocked() map[userIdentity]bool {
	if c.externalSeenSet != nil {
		return c.externalSeenSet
	}
	c.externalSeenSet = map[userIdentity]bool{}
	if c.dataDir == "" {
		return c.externalSeenSet
	}
	b, err := os.ReadFile(filepath.Join(c.dataDir, externalSeenFile))
	if err != nil {
		return c.externalSeenSet
	}
	var ids []userIdentity
	if json.Unmarshal(b, &ids) == nil {
		for _, id := range ids {
			if id.Username != "" && id.CreatedAt != "" && id.UpdatedAt != "" {
				c.externalSeenSet[id] = true
			}
		}
	}
	return c.externalSeenSet
}

// ErrUserNotExternalCandidate: MarkUserExternal was asked to mark an account
// that holds a password, or does not exist.
var ErrUserNotExternalCandidate = errors.New("not an account without a local password")

// MarkUserExternal records, as an administrator's affirmative and audited
// decision, that username is an external-realm user: an empty credential row
// stamped evidenceStamp(now), which replicates as positive evidence to every
// node. It holds only for the users row as it stands now (emptyCredentialHolds):
// a name deleted and created again since needs a new decision.
//
// It refuses an account with any local-credential evidence in view: a
// password in its old column, or a credential row with a password — live or
// tombstoned. Stamped decades back, it never replaces a credential row: where
// a real one exists it wins, so a mistaken mark cannot take a password away.
func MarkUserExternal(ctx context.Context, c *Client, username string) error {
	if !c.MayWriteCredentialTables() {
		return ErrCredentialTablesNotLatched
	}
	// The name is resolved as every account lookup resolves it, normalized
	// (credentials-clear M4): an operator types it as a refusal printed it or
	// in another case. Two accounts that normalize alike are refused
	// (ErrAmbiguousUsername); the one found is marked under its stored name.
	u, err := GetUser(ctx, c, username)
	if err != nil {
		return err
	}
	if u == nil {
		return ErrUserNotExternalCandidate
	}
	username = u.Username
	rows, err := c.Query(ctx,
		`SELECT u.password_hash, u.updated_at,
		        k.username AS cred_key, k.password_hash AS cred_val, k.updated_at AS cred_ts,
		        COALESCE(k.deleted_at, '') AS cred_deleted
		   FROM users u LEFT JOIN user_credentials k ON k.username = u.username
		  WHERE u.username = ? AND u.deleted_at IS NULL`, username)
	if err != nil {
		return err
	}
	if len(rows) == 0 || rows[0].String("password_hash") != "" || rows[0].String("cred_val") != "" {
		return ErrUserNotExternalCandidate
	}
	r := rows[0]
	if r.String("cred_key") != "" && r.String("cred_deleted") == "" &&
		emptyCredentialHolds(r.String("cred_ts"), r.String("updated_at")) {
		return nil // already carries an empty credential row that holds
	}
	at, ok := tsInstant(c.NowTS())
	if !ok {
		return errors.New("this node's clock produced an unreadable timestamp")
	}
	return c.copyUserCredential(ctx, username, "", evidenceStamp(at))
}

// ErrCredentialTablesNotLatched: credentials_split_v1 has not latched here.
var ErrCredentialTablesNotLatched = errors.New("credentials_split_v1 has not latched on this node")

// UsersSynced reports whether this node's users table can be trusted to show
// every account the cluster holds, so that "no row under this name" means
// none exists: its replica has caught up with a peer since this process
// started, or it has no peer to catch up with at all (a node alone, such as a
// single-node founder). A node that has not synced must not create an
// external shadow under a name it cannot see: the new row would replace the
// cluster's local account of that name everywhere (auth.EnsureUserShadow).
func (c *Client) UsersSynced() bool {
	if ok, _ := c.ReplicaCaughtUp(); ok {
		return true
	}
	for _, p := range c.Members() {
		if p.Name != "" && p.Name != c.hostName {
			return false
		}
	}
	return true
}
