package corrosion

import (
	"context"
	"fmt"
	"log/slog"
)

// Secret columns on the sensitive lane (colonelpanik/litevirt#268).
//
// hosts, users and tokens are public inventory: every node reads them, the
// operator-safe state dump carries them, and anti-entropy repairs them on the
// public lane. Each also had ONE secret column — hosts.ipmi_pass,
// users.password_hash, tokens.token_hash — so classifying replication by table
// put three secrets in the public dump. Their values now live in three tables
// that only the peer-only sensitive lane carries:
//
//	hosts.ipmi_pass       -> host_fence_credentials(host_name, ipmi_pass)
//	users.password_hash   -> user_credentials(username, password_hash)
//	tokens.token_hash     -> token_credentials(token_id, token_hash)
//
// THE ROLLING-UPGRADE CONTRACT. Two facts about a previous-release node decide
// the ordering, and both are facts about its binary:
//
//   - it has no ledger entry for any statement on the credential tables, so a
//     write to one back-pressures its whole replication stream;
//   - it reads the secret from the OLD column and nowhere else.
//
// So nothing writes to a credential table until credentials_split_v1 has
// DURABLY latched on this node — a mandatory, ReplicationGated token, so the
// latch cannot form while any host this node replicates to is on the previous
// build. Until then every writer writes the old column exactly as the previous
// release did and every reader falls back to it: the credential tables are
// empty, so a new-build node reads what an old-build node reads.
//
// Once latched, every writer writes the credential table in the SAME batch as
// the parent row, and SplitCredentials copies any old-column value the
// credential table does not yet hold.
//
// READ RULE. The credential row wins, except when the old column holds a
// DIFFERENT value on a parent row whose updated_at is newer than the
// credential row's. That exception is not a corner case: per-node markers mean
// the latch forms per node, so between one node latching and the next, the
// unlatched node's writers still write the old column only, and a reader that
// trusted the credential row unconditionally would serve the value from before
// that write.

// SetCredentialsSplitGate injects the predicate that permits WRITING the
// credential tables. Wired at daemon start to
// `checker.DurablyLatched(CredentialsSplitV1)`.
//
// Nil-safe and FAIL CLOSED: an unset gate writes the old columns only, which is
// exactly the previous release's behaviour. A wiring omission therefore costs
// the split — the secrets stay in the public dump — and never a peer's
// replication stream. Unlike SetLeaseTermLedgerGate the test constructors
// leave it CLOSED: most tests assert on the pre-latch columns, and a test that
// wants the split opens it itself.
func (c *Client) SetCredentialsSplitGate(fn func() bool) { c.credentialsSplit = fn }

// MayWriteCredentialTables reports whether this node may write the credential
// tables (nil-safe, fail closed).
func (c *Client) MayWriteCredentialTables() bool {
	return c.credentialsSplit != nil && c.credentialsSplit()
}

// credentialFallback reports whether a reader may still take a secret from
// the old column when the credential row is absent or older.
func (c *Client) credentialFallback() bool {
	return true
}

// resolveCredential picks the secret a reader returns. present/credVal/credTS
// describe the live credential row; oldVal/oldTS the parent's old column and
// the parent's updated_at. See READ RULE above.
func resolveCredential(present bool, credVal, credTS, oldVal, oldTS string, fallback bool) string {
	if !fallback {
		if present {
			return credVal
		}
		return ""
	}
	if !present {
		return oldVal
	}
	if oldVal != "" && oldVal != credVal && oldTS != "" && lwwOrder(credTS, oldTS) < 0 {
		return oldVal
	}
	return credVal
}

// The credential writers. Each is an explicit upsert on the table's primary
// key, so the originating node applies it whether or not it already holds the
// row, and a receiver LWW-gates it on updated_at (DispExplicitUpsert). A write
// revives a tombstone: every writer here is setting a live secret.
const (
	HostFenceCredentialUpsertSQL = `INSERT INTO host_fence_credentials (host_name, ipmi_pass, updated_at, deleted_at)
		 VALUES (?, ?, ?, NULL)
		 ON CONFLICT(host_name) DO UPDATE SET ipmi_pass = excluded.ipmi_pass,
		   updated_at = excluded.updated_at, deleted_at = NULL`
	userCredentialUpsertSQL = `INSERT INTO user_credentials (username, password_hash, updated_at, deleted_at)
		 VALUES (?, ?, ?, NULL)
		 ON CONFLICT(username) DO UPDATE SET password_hash = excluded.password_hash,
		   updated_at = excluded.updated_at, deleted_at = NULL`
	tokenCredentialUpsertSQL = `INSERT INTO token_credentials (token_id, token_hash, updated_at, deleted_at)
		 VALUES (?, ?, ?, NULL)
		 ON CONFLICT(token_id) DO UPDATE SET token_hash = excluded.token_hash,
		   updated_at = excluded.updated_at, deleted_at = NULL`
)

// CredentialSplitReport is what one SplitCredentials pass did.
type CredentialSplitReport struct {
	// Copied counts old-column values written into a credential table.
	Copied int
}

// The pass reads each parent together with its credential row, including
// tombstoned parents: a deleted user's hash and a revoked token's hash are
// still secrets, and a deleted admin can be reinstated with its hash.
const (
	hostCredentialSplitScanSQL = `SELECT h.name AS pk, h.ipmi_pass AS old_val, h.updated_at AS src_ts,
		       c.host_name AS cred_key, c.ipmi_pass AS cred_val, c.updated_at AS cred_ts,
		       c.deleted_at AS cred_deleted
		  FROM hosts h LEFT JOIN host_fence_credentials c ON c.host_name = h.name
		 WHERE h.ipmi_pass IS NOT NULL AND h.ipmi_pass != ''`
	userCredentialSplitScanSQL = `SELECT u.username AS pk, u.password_hash AS old_val, u.updated_at AS src_ts,
		       c.username AS cred_key, c.password_hash AS cred_val, c.updated_at AS cred_ts,
		       c.deleted_at AS cred_deleted
		  FROM users u LEFT JOIN user_credentials c ON c.username = u.username
		 WHERE u.password_hash IS NOT NULL AND u.password_hash != ''`
	// tokens.updated_at arrived in v29 and is NULL on older rows; created_at
	// is then the best record of when the hash was written.
	tokenCredentialSplitScanSQL = `SELECT t.id AS pk, t.token_hash AS old_val,
		       COALESCE(NULLIF(t.updated_at, ''), t.created_at) AS src_ts,
		       c.token_id AS cred_key, c.token_hash AS cred_val, c.updated_at AS cred_ts,
		       c.deleted_at AS cred_deleted
		  FROM tokens t LEFT JOIN token_credentials c ON c.token_id = t.id
		 WHERE t.token_hash IS NOT NULL AND t.token_hash != ''`
)

// credentialSplitRow is one parent row the pass looked at.
type credentialSplitRow struct {
	pk, oldVal, srcTS string
	present           bool
	credVal, credTS   string
}

func scanCredentialSplitRows(ctx context.Context, c *Client, query string) ([]credentialSplitRow, error) {
	rows, err := c.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	out := make([]credentialSplitRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, credentialSplitRow{
			pk:      r.String("pk"),
			oldVal:  r.String("old_val"),
			srcTS:   r.String("src_ts"),
			present: r.String("cred_key") != "" && r.String("cred_deleted") == "",
			credVal: r.String("cred_val"),
			credTS:  r.String("cred_ts"),
		})
	}
	return out, nil
}

// needsCopy reports whether the old column holds a value the credential table
// must take: there is no live credential row, or it holds a different value
// that is older than the parent row.
func (r credentialSplitRow) needsCopy() bool {
	if !r.present {
		return true
	}
	return r.credVal != r.oldVal && lwwOrder(r.credTS, r.srcTS) < 0
}

// copyTS is the updated_at a copied credential row carries: the PARENT row's.
//
// Not NowTS, deliberately. Every node runs this pass over the same replicated
// parent rows, so every node that copies one writes the same (value,
// updated_at) — the copies converge instead of racing. And a node whose
// parent row is behind the cluster copies an OLDER timestamp, so its stale
// value loses LWW to a fresher node's copy rather than beating it with a newer
// clock.
func (c *Client) copyTS(r credentialSplitRow) string {
	if _, ok := tsInstant(r.srcTS); ok {
		return r.srcTS
	}
	return c.NowTS()
}

// SplitCredentials copies secrets from the old columns into the credential
// tables. It does nothing unless the credentials_split_v1 gate is open, and it
// is idempotent: a parent whose credential row already holds its value is
// skipped. The daemon runs it at start and periodically; its writes replicate
// on the WAL lane and are repaired by the sensitive anti-entropy lane.
func (c *Client) SplitCredentials(ctx context.Context) (CredentialSplitReport, error) {
	var rep CredentialSplitReport
	if !c.MayWriteCredentialTables() {
		return rep, nil
	}
	var firstErr error
	note := func(what string, err error) {
		if err == nil {
			return
		}
		slog.Warn("credentials split: pass incomplete; retrying next cycle", "table", what, "error", err)
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", what, err)
		}
	}

	hosts, err := scanCredentialSplitRows(ctx, c, hostCredentialSplitScanSQL)
	note("host_fence_credentials", err)
	for _, r := range hosts {
		if !r.needsCopy() {
			continue
		}
		if err := c.copyHostCredential(ctx, r.pk, r.oldVal, c.copyTS(r)); err != nil {
			note("host_fence_credentials", err)
			continue
		}
		rep.Copied++
	}

	users, err := scanCredentialSplitRows(ctx, c, userCredentialSplitScanSQL)
	note("user_credentials", err)
	for _, r := range users {
		if !r.needsCopy() {
			continue
		}
		if err := c.copyUserCredential(ctx, r.pk, r.oldVal, c.copyTS(r)); err != nil {
			note("user_credentials", err)
			continue
		}
		rep.Copied++
	}

	tokens, err := scanCredentialSplitRows(ctx, c, tokenCredentialSplitScanSQL)
	note("token_credentials", err)
	for _, r := range tokens {
		if !r.needsCopy() {
			continue
		}
		if err := c.copyTokenCredential(ctx, r.pk, r.oldVal, c.copyTS(r)); err != nil {
			note("token_credentials", err)
			continue
		}
		rep.Copied++
	}
	return rep, firstErr
}

// The per-table writers take the timestamp as updatedAt: the copy stamps the
// PARENT's updated_at (see copyTS), never a fresh clock.

func (c *Client) copyHostCredential(ctx context.Context, host, pass, updatedAt string) error {
	return c.Execute(ctx, HostFenceCredentialUpsertSQL, host, pass, updatedAt)
}

func (c *Client) copyUserCredential(ctx context.Context, username, hash, updatedAt string) error {
	return c.Execute(ctx, userCredentialUpsertSQL, username, hash, updatedAt)
}

func (c *Client) copyTokenCredential(ctx context.Context, tokenID, hash, updatedAt string) error {
	return c.Execute(ctx, tokenCredentialUpsertSQL, tokenID, hash, updatedAt)
}
