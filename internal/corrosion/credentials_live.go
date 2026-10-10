package corrosion

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
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
// exist yet. A node that joins a cluster that has already cleared reaches its
// first pass after the clear; it skips the materialisation whenever it holds
// any row that shows a clear (clearEvidence), and receives the shadows' rows
// from its peers instead.

// credentialsLiveFile is the durable half of credentialsLive. NODE-LOCAL.
const credentialsLiveFile = "credentials_split_live"

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
	if !evidence {
		if err := c.materialiseShadowCredentials(ctx); err != nil {
			slog.Warn("credentials split: shadow credentials incomplete; not live yet", "error", err)
			return
		}
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
	if c.CredentialsLive() {
		return false, false, nil
	}
	evidence, err := clearEvidence(ctx, c)
	if err != nil {
		return false, false, err
	}
	return false, !evidence, nil
}
