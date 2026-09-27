package corrosion

import (
	"context"
	"fmt"
	"log/slog"
	"time"
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
// the parent row and writes '' to the old column, and SplitCredentials copies
// any old-column value the credential table does not yet hold and then CLEARS
// the column. The latch is what proves no replication recipient still reads
// the column, which is the only thing that makes clearing it safe. After this
// node's first complete pass, readers stop consulting the old column at all.
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
//
// It may until this node has latched AND finished one complete split pass.
// From then on every old column this node holds has been copied and cleared,
// so a value that turns up there later is one a node wrote before ITS latch
// formed, and the next pass here moves it across; the reader does not act on
// it in the meantime.
func (c *Client) credentialFallback() bool {
	return !(c.MayWriteCredentialTables() && c.credentialsCleared.Load())
}

// oldColumnValue is what a writer puts in the old secret column: the secret
// itself before the latch, where a previous-release node reads it, and ”
// after, where nothing does.
func (c *Client) oldColumnValue(secret string) string {
	if c.MayWriteCredentialTables() {
		return ""
	}
	return secret
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

// The old-column clears. Each is a full-primary-key UPDATE that binds
// updated_at, so a receiver LWW-gates it (DispFullPKUpdate). It deliberately
// has no deleted_at guard: a tombstoned user's hash and a revoked token's hash
// are secrets too.
const (
	hostsClearIPMIPassSQL     = `UPDATE hosts SET ipmi_pass = ?, updated_at = ? WHERE name = ?`
	usersClearPasswordHashSQL = `UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?`
	tokensClearTokenHashSQL   = `UPDATE tokens SET token_hash = ?, updated_at = ? WHERE id = ?`
)

// CredentialSplitReport is what one SplitCredentials pass did.
type CredentialSplitReport struct {
	// Copied counts old-column values written into a credential table.
	Copied int
	// Cleared counts old columns set to ''.
	Cleared int
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

// clearTS is the updated_at an old-column clear carries: ONE MICROSECOND past
// the parent row's own updated_at, not NowTS.
//
// The clear has to beat the stale copy of the row it replaces, or anti-entropy
// would carry the secret back from a lagging peer. It must NOT beat any real
// write the row has had since. Every node clears every row at about the same
// moment the latch forms. With a fresh clock, a revoke or delete a peer issued
// a moment earlier, still in flight, would arrive older than the clear and be
// LWW-skipped, and anti-entropy would then spread the un-revoked row. The
// successor of the row's own timestamp is newer than exactly the row it read.
// A node whose row is behind the cluster produces a clear that loses to the
// fresher row, and that fresher row is cleared by its own node's pass.
func (c *Client) clearTS(r credentialSplitRow) string {
	if t, ok := tsInstant(r.srcTS); ok {
		return t.Add(time.Microsecond).UTC().Format(nowTSLayout)
	}
	return c.NowTS()
}

// credentialFor is the row a clear is paired with: the old column when it must
// be copied, otherwise the credential row as it stands, re-emitted so this
// node's stream carries it AHEAD of the clear. A receiver then never applies a
// clear from this node before it holds the value the clear hands over to.
func (c *Client) credentialFor(r credentialSplitRow) (val, ts string, copied bool) {
	if r.needsCopy() {
		return r.oldVal, c.copyTS(r), true
	}
	return r.credVal, r.credTS, false
}

// SplitCredentials copies secrets from the old columns into the credential
// tables and clears the old columns. It does nothing unless the
// credentials_split_v1 gate is open, and it is idempotent: it acts only on an
// old column that still holds a value. Each copy and its clear go in ONE batch.
// The daemon runs it at start and periodically. Its writes replicate on the WAL
// lane and are repaired by anti-entropy: the credential rows on the sensitive
// lane, the cleared parent rows on the public one.
//
// A complete pass (no error) with the gate open stops this node's readers from
// falling back to the old column (credentialFallback).
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
		val, ts, copied := c.credentialFor(r)
		if err := c.splitHostCredential(ctx, r.pk, val, ts, c.clearTS(r)); err != nil {
			note("host_fence_credentials", err)
			continue
		}
		rep.count(copied)
	}

	users, err := scanCredentialSplitRows(ctx, c, userCredentialSplitScanSQL)
	note("user_credentials", err)
	for _, r := range users {
		val, ts, copied := c.credentialFor(r)
		if err := c.splitUserCredential(ctx, r.pk, val, ts, c.clearTS(r)); err != nil {
			note("user_credentials", err)
			continue
		}
		rep.count(copied)
	}

	tokens, err := scanCredentialSplitRows(ctx, c, tokenCredentialSplitScanSQL)
	note("token_credentials", err)
	for _, r := range tokens {
		val, ts, copied := c.credentialFor(r)
		if err := c.splitTokenCredential(ctx, r.pk, val, ts, c.clearTS(r)); err != nil {
			note("token_credentials", err)
			continue
		}
		rep.count(copied)
	}
	if firstErr == nil {
		c.credentialsCleared.Store(true)
	}
	return rep, firstErr
}

func (r *CredentialSplitReport) count(copied bool) {
	if copied {
		r.Copied++
	}
	r.Cleared++
}

// The per-table batches: the credential row, then the clear, in one
// transaction. Both timestamps are supplied by the caller — the credential
// row's (copyTS, or the row's own when re-emitted) and the clear's (clearTS) —
// and neither is a fresh clock, by design; see those two functions.

func (c *Client) splitHostCredential(ctx context.Context, host, pass, credTS, updatedAt string) error {
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{host, pass, credTS}},
		{SQL: hostsClearIPMIPassSQL, Params: []interface{}{"", updatedAt, host}},
	})
}

func (c *Client) splitUserCredential(ctx context.Context, username, hash, credTS, updatedAt string) error {
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: userCredentialUpsertSQL, Params: []interface{}{username, hash, credTS}},
		{SQL: usersClearPasswordHashSQL, Params: []interface{}{"", updatedAt, username}},
	})
}

func (c *Client) splitTokenCredential(ctx context.Context, tokenID, hash, credTS, updatedAt string) error {
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: tokenCredentialUpsertSQL, Params: []interface{}{tokenID, hash, credTS}},
		{SQL: tokensClearTokenHashSQL, Params: []interface{}{"", updatedAt, tokenID}},
	})
}
