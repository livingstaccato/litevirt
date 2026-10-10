package corrosion

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// "Credentials live": this node has completed a SplitCredentials pass with the
// credentials_split_v1 gate open, so every secret it held in an old column has
// a credential row.
//
// Two things hang on it.
//
// READINESS. credentials_clear_v1 is advertised only by a live node
// (grpcapi's advertisement filter). So the clear cannot latch anywhere until
// every replication recipient has completed its first pass, and at the moment
// a node completes that pass no old column has been cleared anywhere in the
// cluster.
//
// LEGACY SHADOWS. An external-realm user (OIDC/LDAP) is a users row with an
// empty password_hash. One created before credentials_split_v1 latched on its
// node has no credential row, and once the clear exists an empty old column
// with no credential row can ALSO be a local account whose credential row has
// not arrived yet (anti-entropy merges users and user_credentials separately).
// auth.EnsureUserShadow must never adopt that one. So the pass that makes a
// node live gives each legacy shadow an empty credential row — stamped with
// credentialFloorTS, so any real credential write beats it — and from then on
// a missing credential row means "not here yet", never "external".
// (UserLocalCredential.)
//
// The materialisation is safe on that pass because of READINESS: no clear can
// exist yet — but only on a node that was part of the cluster BEFORE the clear
// latched. A node that joins afterwards reaches its first pass after the clear,
// and an empty old column there may be a cleared local account whose
// credential row has not arrived. Absence of a cleared row in view is no proof
// of anything (its sensitive lane may simply not have merged yet), so the
// decision rests on POSITIVE evidence recorded at the node's first start on
// this build (the credentials baseline): a node that started with users rows
// already in its database held them before it could see a clear, and its first
// pass may treat an empty old column with no credential row as a pre-split
// external user. A node that started EMPTY — every joiner — never materialises
// and never treats an absence as external; it receives the shadows' rows from
// the peers that did. clearEvidence remains as a second guard.

// credentialsLiveFile is the durable half of credentialsLive. NODE-LOCAL.
const credentialsLiveFile = "credentials_split_live"

// credentialsBaselineFile records, once, what this node's database held when
// it first started on a build that knows the credentials baseline: "held" when
// it already had users rows, "empty" otherwise. NODE-LOCAL.
const credentialsBaselineFile = "credentials_baseline"

// NoteCredentialsBaseline records the credentials baseline if it has not been
// recorded yet. The daemon calls it right after InitSchema, before replication
// or anti-entropy can bring any row. Idempotent: the first answer stands.
func (c *Client) NoteCredentialsBaseline(ctx context.Context) error {
	if c.credentialsBaselineHeld.Load() || c.credentialsBaselineNoted.Load() {
		return nil
	}
	if c.dataDir != "" {
		b, err := os.ReadFile(filepath.Join(c.dataDir, credentialsBaselineFile))
		if err == nil {
			c.credentialsBaselineNoted.Store(true)
			c.credentialsBaselineHeld.Store(strings.TrimSpace(string(b)) == "held")
			return nil
		}
		if !os.IsNotExist(err) {
			return err
		}
	}
	held, err := UsersEverExisted(ctx, c)
	if err != nil {
		return err
	}
	if c.dataDir != "" {
		v := "empty\n"
		if held {
			v = "held\n"
		}
		if err := os.WriteFile(filepath.Join(c.dataDir, credentialsBaselineFile), []byte(v), 0o600); err != nil {
			return err
		}
	}
	c.credentialsBaselineHeld.Store(held)
	c.credentialsBaselineNoted.Store(true)
	return nil
}

// credentialsBaselineHeldNow reports the recorded baseline: true only for a
// node that started with users rows in its database. Unrecorded reads false:
// fail closed, as for a joiner.
func (c *Client) credentialsBaselineHeldNow() bool {
	if !c.credentialsBaselineNoted.Load() && c.dataDir != "" {
		if b, err := os.ReadFile(filepath.Join(c.dataDir, credentialsBaselineFile)); err == nil {
			c.credentialsBaselineHeld.Store(strings.TrimSpace(string(b)) == "held")
			c.credentialsBaselineNoted.Store(true)
		}
	}
	return c.credentialsBaselineHeld.Load()
}

// credentialFloorTS stamps a materialised shadow credential: older than any
// real write, so it never replaces a credential and only fills an absence.
const credentialFloorTS = "1970-01-01T00:00:00.000000000Z"

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
// materialising legacy shadow credentials first.
func (c *Client) afterCredentialPass(ctx context.Context, passErr error) {
	if passErr != nil || c.CredentialsLive() {
		return
	}
	evidence, err := clearEvidence(ctx, c)
	if err != nil {
		slog.Warn("credentials split: could not check for cleared rows; not live yet", "error", err)
		return
	}
	if !evidence && c.credentialsBaselineHeldNow() {
		if err := c.materialiseShadowCredentials(ctx); err != nil {
			slog.Warn("credentials split: shadow credentials incomplete; not live yet", "error", err)
			return
		}
	}
	if err := c.materialiseSeenShadows(ctx); err != nil {
		slog.Warn("credentials split: shadow credentials incomplete; not live yet", "error", err)
		return
	}
	c.credentialsLive.Store(true)
	if c.dataDir == "" {
		return
	}
	if err := os.WriteFile(filepath.Join(c.dataDir, credentialsLiveFile), []byte("1\n"), 0o600); err != nil {
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

// materialiseShadowCredentials gives every users row with an empty old column
// and no credential row at all an empty credential row at credentialFloorTS.
func (c *Client) materialiseShadowCredentials(ctx context.Context) error {
	rows, err := c.Query(ctx, `SELECT u.username FROM users u
		 WHERE u.password_hash = ''
		   AND NOT EXISTS (SELECT 1 FROM user_credentials k WHERE k.username = u.username)`)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if err := c.copyUserCredential(ctx, r.String("username"), "", credentialFloorTS); err != nil {
			return err
		}
	}
	return nil
}

// materialiseSeenShadows gives every shadow this node itself created
// (externalSeen) an empty floor credential row, when it still has none. That is
// positive evidence whatever else is in view.
func (c *Client) materialiseSeenShadows(ctx context.Context) error {
	for _, name := range c.externalSeenNames() {
		rows, err := c.Query(ctx, `SELECT u.username FROM users u
			 WHERE u.username = ? AND u.password_hash = ''
			   AND NOT EXISTS (SELECT 1 FROM user_credentials k WHERE k.username = u.username)`, name)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			continue
		}
		if err := c.copyUserCredential(ctx, name, "", credentialFloorTS); err != nil {
			return err
		}
	}
	return nil
}

// UserLocalCredential reports whether username is a LOCAL account — one with
// a password — and whether this node can tell. known is false only for a live
// users row with an empty old column and no credential row on a node where a
// clear may exist: that is either an external shadow or a local account whose
// credential row has not arrived yet, and the caller must not guess.
func UserLocalCredential(ctx context.Context, c *Client, username string) (local, known bool, err error) {
	rows, err := c.Query(ctx,
		`SELECT u.password_hash, k.username AS cred_key, k.password_hash AS cred_val
		   FROM users u LEFT JOIN user_credentials k ON k.username = u.username AND k.deleted_at IS NULL
		  WHERE u.username = ? AND u.deleted_at IS NULL`, username)
	if err != nil {
		return false, false, err
	}
	if len(rows) == 0 {
		return false, true, nil
	}
	r := rows[0]
	if r.String("cred_key") != "" {
		return r.String("cred_val") != "", true, nil
	}
	if r.String("password_hash") != "" {
		return true, true, nil
	}
	if c.externalSeen(username) {
		return false, true, nil // this node created it as a shadow
	}
	if c.CredentialsLive() {
		return false, false, nil
	}
	// Not live yet: an empty old column with no credential row is an external
	// user only on positive evidence — a node that held its users rows before
	// it could see any clear — and never when a cleared row is in view.
	if !c.credentialsBaselineHeldNow() {
		return false, false, nil
	}
	evidence, err := clearEvidence(ctx, c)
	if err != nil {
		return false, false, err
	}
	return false, !evidence, nil
}

// externalSeenFile lists the usernames THIS node created as external-realm
// shadows while it could not write a credential row (credentials_split_v1 not
// latched here): positive, node-local evidence that their empty old column is
// empty by design. The node's first live pass gives each an empty credential
// row at the floor, which replicates that evidence. NODE-LOCAL.
const externalSeenFile = "credentials_external_seen"

// noteExternalShadow records username as a shadow this node created.
func (c *Client) noteExternalShadow(username string) {
	c.externalSeenMu.Lock()
	defer c.externalSeenMu.Unlock()
	seen := c.loadExternalSeenLocked()
	if seen[username] {
		return
	}
	seen[username] = true
	if c.dataDir == "" {
		return
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	sort.Strings(names)
	b, _ := json.Marshal(names)
	if err := os.WriteFile(filepath.Join(c.dataDir, externalSeenFile), b, 0o600); err != nil {
		slog.Warn("credentials: could not record an external shadow; it is judged by the credential row instead",
			"user", username, "error", err)
	}
}

// externalSeen reports whether this node created username as a shadow.
func (c *Client) externalSeen(username string) bool {
	c.externalSeenMu.Lock()
	defer c.externalSeenMu.Unlock()
	return c.loadExternalSeenLocked()[username]
}

func (c *Client) externalSeenNames() []string {
	c.externalSeenMu.Lock()
	defer c.externalSeenMu.Unlock()
	out := make([]string, 0)
	for n := range c.loadExternalSeenLocked() {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func (c *Client) loadExternalSeenLocked() map[string]bool {
	if c.externalSeenSet != nil {
		return c.externalSeenSet
	}
	c.externalSeenSet = map[string]bool{}
	if c.dataDir == "" {
		return c.externalSeenSet
	}
	b, err := os.ReadFile(filepath.Join(c.dataDir, externalSeenFile))
	if err != nil {
		return c.externalSeenSet
	}
	var names []string
	if json.Unmarshal(b, &names) == nil {
		for _, n := range names {
			c.externalSeenSet[n] = true
		}
	}
	return c.externalSeenSet
}
