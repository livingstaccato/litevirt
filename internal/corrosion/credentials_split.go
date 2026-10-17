package corrosion

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/hlc"
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
// Once latched, every writer writes the secret to BOTH places in the SAME
// batch under the same updated_at: the credential table and the old column.
// SplitCredentials copies an old-column value only where the credential table
// has no row for it, and never touches the old column. So a host rolled
// back to the previous release — which reads only the old column — still finds
// every current secret there. That lasts until credentials_clear_v1 latches
// (CLEARING, below).
//
// CLEARING (credentials_clear_v1, docs/design/credentials-clear.md). Once a
// second mandatory, ReplicationGated token has durably latched as well, the old
// columns are emptied:
//
//   - every writer writes the credential row and '' in the old column, in the
//     same statement shapes as before (oldColumnValue);
//   - the split pass, for every parent row whose old column still holds a
//     value, re-emits the credential row (copying the old value only where no
//     live credential row exists) and clears the old column, in ONE batch, so
//     this node's stream always carries the value ahead of the clear;
//   - the clear is stamped just past the parent row's own updated_at, never
//     with a fresh clock (clearTS).
//
// Readers need no change: they take the credential row whenever one exists,
// and absorb never takes an empty value. A host rolled back one build lands on
// the dual-write build, which reads the credential rows the same way. The
// clear cannot latch while any replication recipient — a maintenance host
// included — runs a build that reads only the old columns.
//
// READ RULE. A reader takes the live credential row whenever one exists, and
// the old column only when no credential row exists at all. A RETIRED row (a
// tombstone, written only by retireFenceCredential on a host's removal or
// re-admission) reads as no secret, never as the old column: a node whose
// hosts row predates the re-admission still holds the old machine's password
// there. It never compares the credential row's
// updated_at with the PARENT row's: the parent's is bumped by every unrelated
// write to the row, and when one of those reaches a replica ahead of a latched
// rotation the LWW gate refuses the rotation's parent half there, leaving the
// OLD secret on a NEWER parent row (the colonelpanik/litevirt#267 race). A rule
// that preferred the newer parent would serve, and the split pass would copy,
// the rotated-out secret. The split pass likewise copies only where no
// credential row exists.
//
// That leaves the one legitimate old-column-only write: a new-build neighbour
// that has not latched yet. It is recognised structurally on the WAL apply path
// — its entry sets the secret with no credential-table statement, which a
// latched writer never emits — and absorbed into the credential row there,
// stamped with the entry's own updated_at (credentials_absorb.go). A latched
// reader therefore serves such a rotation as soon as it replicates.

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
func (c *Client) SetCredentialsSplitGate(fn func() bool) { c.credentialsSplit.Store(&fn) }

// MayWriteCredentialTables reports whether this node may write the credential
// tables (nil-safe, fail closed).
func (c *Client) MayWriteCredentialTables() bool {
	fn := c.credentialsSplit.Load()
	return fn != nil && *fn != nil && (*fn)()
}

// SetCredentialsClearGate injects the predicate that permits CLEARING the old
// secret columns. Wired at daemon start to
// `checker.DurablyLatched(CredentialsClearV1)`. Nil-safe and FAIL CLOSED, like
// the split gate: unwired, every old column keeps its secret, which is the
// dual-write build's behaviour.
func (c *Client) SetCredentialsClearGate(fn func() bool) { c.credentialsClear.Store(&fn) }

// MayClearCredentialColumns reports whether this node empties the old secret
// columns. It needs the split gate open too: a node never clears a column
// before it writes the credential table that replaces it.
func (c *Client) MayClearCredentialColumns() bool {
	if !c.MayWriteCredentialTables() {
		return false
	}
	fn := c.credentialsClear.Load()
	return fn != nil && *fn != nil && (*fn)()
}

// oldColumnValue is what a writer puts in an old secret column: the secret
// itself until credentials_clear_v1 has latched, where a host on the previous
// builds reads it, and an empty string after, where nothing does.
func (c *Client) oldColumnValue(secret string) string {
	if c.MayClearCredentialColumns() {
		return ""
	}
	return secret
}

// resolveCredential picks the secret a reader returns: the live credential
// row's value when there is one, the parent's old column otherwise. See READ
// RULE above.
func resolveCredential(present bool, credVal, oldVal string) string {
	if present {
		return credVal
	}
	return oldVal
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

// The old-column clears (credentials_clear_v1). Each is a full-primary-key
// UPDATE that binds updated_at, so a receiver LWW-gates it (DispFullPKUpdate).
// None has a deleted_at guard: a tombstoned user's hash, a revoked token's hash
// and a removed host's BMC password are secrets too. The previous build
// decodes all three: the users and tokens forms are its
// credentials_split_clear_v56 family, the hosts form is a configure_host_v130
// subset.
const (
	hostsClearIPMIPassSQL     = `UPDATE hosts SET ipmi_pass = ?, updated_at = ? WHERE name = ?`
	usersClearPasswordHashSQL = `UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?`
	tokensClearTokenHashSQL   = `UPDATE tokens SET token_hash = ?, updated_at = ? WHERE id = ?`
)

// CredentialSplitReport is what one SplitCredentials pass did.
type CredentialSplitReport struct {
	// Copied counts old-column values written into a credential table.
	Copied int
	// Cleared counts old columns emptied (credentials_clear_v1 only).
	Cleared int
}

// The pass reads each parent together with its credential row, including
// tombstoned users and tokens: a deleted user's hash and a revoked token's hash
// are still secrets, and a deleted admin can be reinstated with its hash.
//
// Removed HOSTS are the exception. `lv host rm` leaves hosts.ipmi_pass in place
// (the old column is what a previous-release node reads) and retires the
// credential row to a tombstone (retireFenceCredential). A tombstone is not a
// live row, so needsCopy() would copy the old column straight back with
// deleted_at = NULL, and the next pass would replicate the removed machine's BMC
// password cluster-wide. Nothing reinstates a removed host's password: a
// re-admission under the name resets ipmi_pass to NULL.
//
// A LIVE host can hold a retired credential row too: a host re-added while its
// disk survived boots on its old database, re-records its serial (a hosts row
// newer than the re-admission, which therefore does not reset it there), and
// keeps the old machine's ipmi_pass while the re-admission retires the
// credential row. So no pass ever copies over a tombstone, and the clear pass
// clears the old column beside one without re-emitting it. A live old column
// over a tombstone is never a legitimate secret: a latched writer pairs every
// password with the credential upsert, which revives the row, and an
// unlatched writer's password is absorbed from its entry, which revives it too
// (credentials_absorb.go).
const (
	hostCredentialSplitScanSQL = `SELECT h.name AS pk, h.ipmi_pass AS old_val, h.updated_at AS src_ts,
		       c.host_name AS cred_key, c.ipmi_pass AS cred_val, c.updated_at AS cred_ts,
		       c.deleted_at AS cred_deleted
		  FROM hosts h LEFT JOIN host_fence_credentials c ON c.host_name = h.name
		 WHERE h.deleted_at IS NULL AND h.ipmi_pass IS NOT NULL AND h.ipmi_pass != ''`
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
	// A REMOVED host's password is cleared and nothing else: its credential
	// row was retired with it and is never re-emitted (see above).
	removedHostClearScanSQL = `SELECT h.name AS pk, h.updated_at AS src_ts
		  FROM hosts h
		 WHERE h.deleted_at IS NOT NULL AND h.ipmi_pass IS NOT NULL AND h.ipmi_pass != ''`
)

// credentialSplitRow is one parent row the pass looked at.
type credentialSplitRow struct {
	pk, oldVal, srcTS string
	present           bool // a live credential row exists
	retired           bool // the credential row exists and is a tombstone
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
			retired: r.String("cred_key") != "" && r.String("cred_deleted") != "",
			credVal: r.String("cred_val"),
			credTS:  r.String("cred_ts"),
		})
	}
	return out, nil
}

// needsCopy reports whether the old column holds a value the credential table
// must take: only when there is no credential row at all. A credential row
// that exists, live or retired, is never overwritten from the old column — the parent's updated_at
// does not date the secret (READ RULE); an unlatched write that belongs in the
// row is absorbed at apply time instead (credentials_absorb.go).
func (r credentialSplitRow) needsCopy() bool {
	return !r.present && !r.retired
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

// clearTS is the updated_at an old-column clear carries: the immediate
// successor of the parent row's own updated_at — one microsecond past it, or,
// for an HLC key, the same physical and logical time with the node id
// extended — never NowTS.
//
// The clear has to beat the copy of the row it replaces, or anti-entropy would
// carry the secret back from a peer that has not cleared yet. It must NOT beat
// any real write the row has had since. Every node clears every row at about
// the moment the latch forms. With a fresh clock, a revoke or delete a peer
// issued a moment earlier, still in flight, would arrive older than the clear
// and be LWW-skipped, and anti-entropy would then spread the un-revoked row. A
// node whose row is behind the cluster produces a clear that loses to the
// fresher row, and that row is cleared by the next pass on the node that holds
// it.
//
// ok is false when the row's own timestamp cannot be read. There is then no
// successor to stamp, and a fresh clock is exactly the hazard above, so the
// caller leaves that row uncleared (and logs it) rather than guess.
func clearTS(r credentialSplitRow) (ts string, ok bool) {
	if hlc.IsHLC(r.srcTS) {
		if p, ok := hlc.Parse(r.srcTS); ok {
			p.NodeID += "+"
			return p.String(), true
		}
		return "", false
	}
	if t, err := time.Parse(time.RFC3339, r.srcTS); err == nil {
		return t.Add(time.Microsecond).UTC().Format(nowTSLayout), true
	}
	return "", false
}

// credentialFor is the credential row a clear is paired with: the old column
// when no live credential row exists, otherwise the credential row as it
// stands, re-emitted so this node's stream carries it AHEAD of the clear. A
// receiver then never applies a clear from this node before it holds the
// value the clear hands over to.
func (c *Client) credentialFor(r credentialSplitRow) (val, ts string, copied bool) {
	if r.needsCopy() {
		return r.oldVal, c.copyTS(r), true
	}
	return r.credVal, r.credTS, false
}

// SplitCredentials copies secrets from the old columns into the credential
// tables. It does nothing unless the credentials_split_v1 gate is open, and it
// is idempotent: it writes only where no live credential row exists. Until
// credentials_clear_v1 has latched it never writes the old column — that
// stays the copy a previous-release host reads. Once it has, every old column
// that still holds a value is cleared, in one batch with its credential row
// (see CLEARING above). The daemon runs it at start and periodically. Its
// writes replicate on the WAL lane and are repaired by anti-entropy: the
// credential rows on the sensitive lane, the cleared parent rows on the public
// one.
func (c *Client) SplitCredentials(ctx context.Context) (CredentialSplitReport, error) {
	var rep CredentialSplitReport
	if !c.MayWriteCredentialTables() {
		return rep, nil
	}
	if c.MayClearCredentialColumns() {
		// A node's FIRST pass decides which empty old columns are external
		// users (credentials_live.go), and its own clears must not be in view
		// when it does: copy and go live first, then clear. In production the
		// clear cannot latch before this node is live (the advertisement
		// gate), so this only orders a node whose gates opened together.
		if !c.CredentialsLive() {
			if _, err := c.copyCredentialColumns(ctx); err != nil {
				return rep, err
			}
		}
		rep, err := c.clearCredentialColumns(ctx)
		c.afterCredentialPass(ctx, err)
		return rep, err
	}
	return c.copyCredentialColumns(ctx)
}

// copyCredentialColumns is the dual-write pass: copy every old-column secret
// that has no credential row, touch no old column, then go live after a
// complete pass.
func (c *Client) copyCredentialColumns(ctx context.Context) (CredentialSplitReport, error) {
	var rep CredentialSplitReport
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
		if r.needsCopy() {
			rep.note(c.copyHostCredential(ctx, r.pk, r.oldVal, c.copyTS(r)), "host_fence_credentials", note)
		}
	}
	users, err := scanCredentialSplitRows(ctx, c, userCredentialSplitScanSQL)
	note("user_credentials", err)
	for _, r := range users {
		if r.needsCopy() {
			rep.note(c.copyUserCredential(ctx, r.pk, r.oldVal, c.copyTS(r)), "user_credentials", note)
		}
	}
	tokens, err := scanCredentialSplitRows(ctx, c, tokenCredentialSplitScanSQL)
	note("token_credentials", err)
	for _, r := range tokens {
		if r.needsCopy() {
			rep.note(c.copyTokenCredential(ctx, r.pk, r.oldVal, c.copyTS(r)), "token_credentials", note)
		}
	}
	c.afterCredentialPass(ctx, firstErr)
	return rep, firstErr
}

// note counts one copy, or hands its error to fail.
func (r *CredentialSplitReport) note(err error, table string, fail func(string, error)) {
	if err != nil {
		fail(table, err)
		return
	}
	r.Copied++
}

// The per-table copies: one credential upsert each, stamped with the
// updatedAt the caller supplies (copyTS, deliberately not a fresh clock).

func (c *Client) copyHostCredential(ctx context.Context, host, pass, updatedAt string) error {
	return c.Execute(ctx, HostFenceCredentialUpsertSQL, host, pass, updatedAt)
}

func (c *Client) copyUserCredential(ctx context.Context, username, hash, updatedAt string) error {
	return c.Execute(ctx, userCredentialUpsertSQL, username, hash, updatedAt)
}

func (c *Client) copyTokenCredential(ctx context.Context, tokenID, hash, updatedAt string) error {
	return c.Execute(ctx, tokenCredentialUpsertSQL, tokenID, hash, updatedAt)
}

// clearCredentialColumns is SplitCredentials once credentials_clear_v1 has
// latched: every old column that still holds a value is cleared, in one batch
// with its credential row.
func (c *Client) clearCredentialColumns(ctx context.Context) (CredentialSplitReport, error) {
	var rep CredentialSplitReport
	var firstErr error
	note := func(what string, err error) {
		if err == nil {
			return
		}
		slog.Warn("credentials clear: pass incomplete; retrying next cycle", "table", what, "error", err)
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", what, err)
		}
	}
	skipped := func(table string, r credentialSplitRow) bool {
		if _, ok := clearTS(r); ok {
			return false
		}
		slog.Warn("credentials clear: row has no readable updated_at to stamp its clear after; left uncleared",
			"table", table, "key", r.pk, "updated_at", r.srcTS)
		return true
	}
	stamp := func(r credentialSplitRow) string { ts, _ := clearTS(r); return ts }
	count := func(table string, copied bool, err error) {
		if err != nil {
			note(table, err)
			return
		}
		if copied {
			rep.Copied++
		}
		rep.Cleared++
	}

	hosts, err := scanCredentialSplitRows(ctx, c, hostCredentialSplitScanSQL)
	note("host_fence_credentials", err)
	for _, r := range hosts {
		if skipped("host_fence_credentials", r) {
			continue
		}
		if r.retired {
			count("host_fence_credentials", false, c.clearOldColumn(ctx, "host_fence_credentials", r.pk, stamp(r)))
			continue
		}
		val, ts, copied := c.credentialFor(r)
		count("host_fence_credentials", copied, c.clearHostCredential(ctx, r.pk, val, ts, stamp(r)))
	}
	users, err := scanCredentialSplitRows(ctx, c, userCredentialSplitScanSQL)
	note("user_credentials", err)
	for _, r := range users {
		if skipped("user_credentials", r) {
			continue
		}
		if r.retired {
			count("user_credentials", false, c.clearOldColumn(ctx, "user_credentials", r.pk, stamp(r)))
			continue
		}
		val, ts, copied := c.credentialFor(r)
		count("user_credentials", copied, c.clearUserCredential(ctx, r.pk, val, ts, stamp(r)))
	}
	tokens, err := scanCredentialSplitRows(ctx, c, tokenCredentialSplitScanSQL)
	note("token_credentials", err)
	for _, r := range tokens {
		if skipped("token_credentials", r) {
			continue
		}
		if r.retired {
			count("token_credentials", false, c.clearOldColumn(ctx, "token_credentials", r.pk, stamp(r)))
			continue
		}
		val, ts, copied := c.credentialFor(r)
		count("token_credentials", copied, c.clearTokenCredential(ctx, r.pk, val, ts, stamp(r)))
	}
	removed, err := c.Query(ctx, removedHostClearScanSQL)
	note("hosts", err)
	for _, row := range removed {
		r := credentialSplitRow{pk: row.String("pk"), srcTS: row.String("src_ts")}
		if skipped("hosts", r) {
			continue
		}
		count("hosts", false, c.clearOldColumn(ctx, "host_fence_credentials", r.pk, stamp(r)))
	}
	return rep, firstErr
}

// The per-table clears: the credential row, then the clear, in one
// transaction. Both timestamps come from the caller — the credential row's
// (copyTS, or the row's own when re-emitted) and the clear's updatedAt
// (clearTS) — and neither is a fresh clock, by design.

func (c *Client) clearHostCredential(ctx context.Context, host, pass, credTS, updatedAt string) error {
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: HostFenceCredentialUpsertSQL, Params: []interface{}{host, pass, credTS}},
		{SQL: hostsClearIPMIPassSQL, Params: []interface{}{"", updatedAt, host}},
	})
}

func (c *Client) clearUserCredential(ctx context.Context, username, hash, credTS, updatedAt string) error {
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: userCredentialUpsertSQL, Params: []interface{}{username, hash, credTS}},
		{SQL: usersClearPasswordHashSQL, Params: []interface{}{"", updatedAt, username}},
	})
}

func (c *Client) clearTokenCredential(ctx context.Context, tokenID, hash, credTS, updatedAt string) error {
	return c.ExecuteBatch(ctx, []Statement{
		{SQL: tokenCredentialUpsertSQL, Params: []interface{}{tokenID, hash, credTS}},
		{SQL: tokensClearTokenHashSQL, Params: []interface{}{"", updatedAt, tokenID}},
	})
}

// clearOldColumn clears the old secret column that credTable replaces, alone,
// with no credential row beside it: a removed host's, or one whose credential
// row is retired. updatedAt is the caller's clearTS.
func (c *Client) clearOldColumn(ctx context.Context, credTable, key, updatedAt string) error {
	switch credTable {
	case "host_fence_credentials":
		return c.Execute(ctx, hostsClearIPMIPassSQL, "", updatedAt, key)
	case "user_credentials":
		return c.Execute(ctx, usersClearPasswordHashSQL, "", updatedAt, key)
	case "token_credentials":
		return c.Execute(ctx, tokensClearTokenHashSQL, "", updatedAt, key)
	}
	return fmt.Errorf("no old secret column for %s", credTable)
}
