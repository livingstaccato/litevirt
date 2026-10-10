package corrosion

import (
	"context"
	"database/sql"
	"log/slog"
	"sync"
)

// The receiver-side half of the joining-node credential hazard (#186/#224).
//
// The sender-side guard — a node with join_peers configured declines to mint an
// admin credential — protects the cluster only for the code path and binary
// version it lives in. An operator whose workstation carries an older `lv`
// provisions a node whose daemon has no guard at all, and a node whose
// join_peers was reset (see `lv host init`) reaches the mint path with a current
// binary. Either way the minted row replicates, and the receiver had no opinion:
// applyLWWGated gates purely on updated_at, so a strictly-newer admin row was
// applied by BOTH lanes with no conflict raised, no unresolved marker and no
// metric. Nothing anywhere recorded that a cluster credential had been replaced.
//
// The invariant here is deliberately narrow, and it is keyed on created_at.
//
// users.created_at is written in exactly ONE place: the INSERT in InsertUser.
// No update path touches it — UpdateUserPassword sets password_hash/updated_at,
// InsertUser's reactivation branch sets role/password_hash/deleted_at/updated_at,
// and DeleteUser sets deleted_at/updated_at. So for a given username created_at
// is immutable in practice, and an incoming row that carries a DIFFERENT one is
// not a new password for the existing account — it is a different account minted
// somewhere else wearing that account's name. That is exactly the #186 event,
// and it is distinguishable from the legitimate operation (`lv user reset-admin`
// preserves created_at and keeps replicating normally).
//
// What this deliberately does NOT do:
//
//   - It does not refuse a second admin ACCOUNT. #224 proposed refusing any
//     incoming row that "creates an admin while a live admin exists", but that
//     would block `lv user create --role admin`, which is a legitimate operation
//     and is the remediation the last-admin delete guard tells operators to use.
//   - It does not refuse a promotion. Changing an existing account's role to
//     admin preserves created_at, so it is not a re-mint. (No `lv user`
//     subcommand does this today — `--role` only applies at create.)
//   - It does not use customMergeTables, which is what #224 proposed. That map
//     re-classifies every statement for its table to DispCustomMerge, and the
//     users shapes are recorded in the compatibility ledger as DispPlainInsert
//     and DispFullPKUpdate. Changing them is a wire-shape change for a
//     credential table — a mixed-version cluster would disagree about how to
//     apply users statements — so it needs a ReplicationGated capability token,
//     the way lease_term_ledger_v1 got one, rather than an edit to a map.
//     Refusing at the apply sites leaves every disposition untouched.
//   - It does not cover what the refused account does AFTERWARDS. Every other
//     auth table is keyed by username alone, so a factor enrolled, or a password
//     changed, on the node that kept its own admin replicates as the cluster
//     admin's. That is an accepted residual; binding those rows to the account
//     is written up in docs/design/auth-rows-account-identity.md.
//
// The refusal is asymmetric during a rolling upgrade: an old node still takes
// the row, a new node keeps its own. That is the point — #224 asks for a
// guarantee that does not depend on the sender's binary version — but it does
// mean the two nodes hold different hashes until an operator acts, so the
// refusal is counted and logged rather than being silent like the overwrite was.

const adminRemintAdvice = "A peer offered a DIFFERENT admin account under an existing admin's " +
	"name (its created_at does not match). Run `lv user ls` on both nodes; if the credential was " +
	"replaced, `lv user reset-admin` on the node you trust re-establishes one both will accept"

// adminRemintRefused is the whole decision, as a pure function of four strings,
// so the rule can be tested without a replication lane around it.
//
// It refuses only when the LOCAL row is a live admin and the incoming row claims
// a different created_at. An unknown created_at on either side is not evidence
// of anything and falls through to ordinary LWW — a dump from a peer that does
// not project the column must not be turned into a cluster-wide refusal.
func adminRemintRefused(localRole, localDeletedAt, localCreatedAt, incomingCreatedAt string) bool {
	if localRole != "admin" {
		return false
	}
	if localDeletedAt != "" {
		// A tombstoned admin cannot log in, so there is no live credential to
		// protect and nothing to refuse.
		return false
	}
	if localCreatedAt == "" || incomingCreatedAt == "" {
		return false
	}
	return incomingCreatedAt != localCreatedAt
}

// accountRemintRefused widens adminRemintRefused from admin accounts to every
// live LOCAL account — one that holds a password, in its old column or a live
// credential row. A different account under such a name (another created_at)
// is not that account's update, whoever minted it: a node whose users table
// had not caught up and created an external shadow under a name it could not
// see is the common way, and before this the newer shadow replaced the local
// account cluster-wide (pre-existing; found in the colonelpanik/litevirt#268
// review). An account without a password (an external shadow) is still
// replaced by LWW, as before.
func accountRemintRefused(localRole, localDeletedAt, localCreatedAt, incomingCreatedAt string, localHasPassword bool) bool {
	if adminRemintRefused(localRole, localDeletedAt, localCreatedAt, incomingCreatedAt) {
		return true
	}
	if !localHasPassword {
		return false
	}
	return adminRemintRefused("admin", localDeletedAt, localCreatedAt, incomingCreatedAt)
}

// localAccountHasPassword reports whether username's local account holds a
// password: its old column, or a live credential row.
func localAccountHasPassword(tx *sql.Tx, username string) (bool, error) {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM users u
		LEFT JOIN user_credentials k ON k.username = u.username AND k.deleted_at IS NULL
		WHERE u.username = ? AND (u.password_hash != '' OR COALESCE(k.password_hash, '') != '')`, username).Scan(&n)
	return n > 0, err
}

// usersAdminRemintIsRefused is the anti-entropy lane's adapter: it reads the
// local row for the incoming row's PK and applies adminRemintRefused. Its
// signature matches auditEvidenceGuard so it can only ever REFUSE.
func usersAdminRemintIsRefused(tx *sql.Tx, table syncTable, row []interface{}, pkCols []string, pkIdx []int) (bool, string, error) {
	idx := columnIndexMap(table.Columns)
	if _, ok := idx["created_at"]; !ok {
		// A dump that does not carry created_at cannot be judged.
		return false, "", nil
	}
	localRow, found, err := fetchLocalRowCells(tx, table.Name, table.Columns, pkCols, pkIdx, row)
	if err != nil || !found {
		return false, "", err
	}
	hasPassword, err := localAccountHasPassword(tx, cellStr(localRow, idx, "username"))
	if err != nil {
		return false, "", err
	}
	if accountRemintRefused(
		cellStr(localRow, idx, "role"),
		cellStr(localRow, idx, "deleted_at"),
		cellStr(localRow, idx, "created_at"),
		cellStr(row, idx, "created_at"),
		hasPassword,
	) {
		return true, "admin_remint", nil
	}
	return false, "", nil
}

// credentialMergeGuards is the users-table floor under anti-entropy. It is kept
// separate from auditEvidenceGuards because the two answer different questions —
// that one protects immutable signed assertions, this one protects a live
// credential — and collapsing them would make one comment have to explain both.
var credentialMergeGuards = map[string]mergeFloor{
	"users": {usersAdminRemintIsRefused, adminRemintAdvice},
}

// usersInsertRemintsALiveAdmin is the WAL lane's adapter.
//
// Only INSERTs are inspected, and that is sufficient rather than partial: no
// UPDATE path writes created_at at all, so an UPDATE cannot violate the
// invariant this guard enforces.
func (r *Replicator) usersInsertRemintsALiveAdmin(ctx context.Context, tx *sql.Tx, s Statement, sh StmtShape) (bool, error) {
	if sh.Kind != KindInsert {
		return false, nil
	}
	incomingCreatedAt, ok := insertParamString(s, sh, "created_at")
	if !ok {
		return false, nil
	}
	username, ok := insertParamString(s, sh, "username")
	if !ok {
		return false, nil
	}

	var role, createdAt string
	var deletedAt sql.NullString
	err := tx.QueryRowContext(ctx,
		`SELECT role, created_at, deleted_at FROM users WHERE username = ?`, username).
		Scan(&role, &createdAt, &deletedAt)
	if err == sql.ErrNoRows {
		return false, nil // first time we have seen this account
	}
	if err != nil {
		return false, err // unreadable is not "no live admin"
	}
	hasPassword, err := localAccountHasPassword(tx, username)
	if err != nil {
		return false, err
	}
	if !accountRemintRefused(role, deletedAt.String, createdAt, incomingCreatedAt, hasPassword) {
		return false, nil
	}
	if hash, ok := insertParamString(s, sh, "password_hash"); ok {
		r.client.remints.note(username, hash)
	}
	return true, nil
}

// The credential that comes with a refused re-mint (#224, after the
// credentials split).
//
// Refusing the users row protects nothing on its own. Readers take the
// user_credentials row whenever one exists (resolveCredential), so the
// re-minted account's credential replaces the cluster's admin password unless
// it is refused too. It reaches a receiver three ways, and each is closed where
// it arrives:
//
//   - A latched sender's InsertUser puts the users INSERT and the
//     user_credentials upsert in ONE entry. The WAL lane decides the entry's
//     users rows first (refusedRemintsInEntry) and skips a credential
//     statement for a refused username (remintCredentialStatement).
//   - An unlatched sender's InsertUser is the users INSERT alone, and
//     absorbUnlatchedSecretWrite would copy its hash into user_credentials. The
//     WAL lane hands the absorb the entry WITHOUT the refused statements
//     (withoutRefusedRemints). The origin test stays the entry's: a refused
//     row is simply not part of what the entry wrote here.
//   - Anti-entropy carries the users row on the public lane and its
//     credential on the sensitive lane, in separate pulls with nothing to pair
//     them by entry. Until credentials_clear_v1 latches every writer puts the
//     same hash in users.password_hash and user_credentials (dual-write), so a
//     refused users row names the credential that belongs to it by VALUE. The
//     refusal is remembered (refusedRemints) and the sensitive lane refuses a
//     user_credentials row carrying a remembered hash. A rotation of the SAME
//     account has the same created_at, is never refused, and keeps repairing.
//     Once the re-minting node has latched credentials_clear_v1 its users row
//     carries '' and names no credential. The refusal is then remembered for
//     the USERNAME, in the anti-entropy exchange with THAT peer only
//     (remintScope), and that exchange's sensitive pull refuses any
//     user_credentials row for the username whose hash differs from the one
//     this node holds for the account it kept. The peer that holds the re-mint
//     keeps offering it, so every exchange with it refuses again, including
//     the first after a restart. The cost is confined to that peer: a genuine
//     rotation of the account is still repaired from every other peer, and
//     the WAL lane delivers it as usual. The judgement ends with the exchange;
//     nothing is remembered across exchanges or peers.
//     The memory is per process: checkPeer pulls the public lane first, and
//     withholds user_credentials from the sensitive pull when the public pull
//     that should have judged the peer's users rows did not complete.
//
// Nothing here reads a parent row's updated_at.

// refusedRemints remembers, per username, the password hashes of re-minted
// admin rows this node refused. Bounded: a peer that keeps re-minting cannot
// grow it without limit, and the newest refusals are the ones still offered.
type refusedRemints struct {
	mu     sync.Mutex
	hashes map[string][]string
}

// remintScope is one anti-entropy exchange's memory of the re-minted accounts
// whose users row carried NO hash (credentials_clear_v1 had cleared it on the
// sender), so the credential cannot be recognised by value. checkPeer creates
// one per peer per cycle and hands it to both of that peer's pulls; nil means
// no exchange (a reseed, a test merge) and judges nothing.
type remintScope struct {
	mu      sync.Mutex
	unknown map[string]bool
}

func (s *remintScope) noteUnknown(username string) {
	if s == nil || username == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.unknown == nil {
		s.unknown = map[string]bool{}
	}
	s.unknown[username] = true
}

func (s *remintScope) hashUnknown(username string) bool {
	if s == nil || username == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unknown[username]
}

const refusedRemintsPerUser = 16

func (m *refusedRemints) note(username, hash string) {
	if username == "" || hash == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.hashes == nil {
		m.hashes = map[string][]string{}
	}
	for _, h := range m.hashes[username] {
		if h == hash {
			return
		}
	}
	l := append(m.hashes[username], hash)
	if len(l) > refusedRemintsPerUser {
		l = l[len(l)-refusedRemintsPerUser:]
	}
	m.hashes[username] = l
}

func (m *refusedRemints) refused(username, hash string) bool {
	if username == "" || hash == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, h := range m.hashes[username] {
		if h == hash {
			return true
		}
	}
	return false
}

// refusedRemintsInEntry returns the usernames whose users INSERT in this entry
// the floor refuses, judged against the local rows before the entry applies.
func (r *Replicator) refusedRemintsInEntry(ctx context.Context, tx *sql.Tx, stmts []Statement) (map[string]bool, error) {
	var out map[string]bool
	for _, s := range stmts {
		sh, ok := statementOnTable(s, "users")
		if !ok {
			continue
		}
		refused, err := r.usersInsertRemintsALiveAdmin(ctx, tx, s, sh)
		if err != nil {
			return nil, err
		}
		if !refused {
			continue
		}
		if username, ok := insertParamString(s, sh, "username"); ok {
			if out == nil {
				out = map[string]bool{}
			}
			out[username] = true
		}
	}
	return out, nil
}

// statementOnTable parses s structurally and reports its shape when it writes
// table. A statement that does not parse is not judged here: applyStatementLWW
// rejects it, and the entry with it.
func statementOnTable(s Statement, table string) (StmtShape, bool) {
	if !entryWritesTable([]Statement{s}, table) {
		return StmtShape{}, false
	}
	sh, _, err := parseResolved(s.SQL)
	return sh, err == nil
}

// remintCredentialStatement reports whether s writes the credential of a
// username whose users row this entry re-mints and the floor refused. A
// credential statement whose key cannot be read is treated as paired: it sits
// in an entry that re-mints an admin, and failing open there is the bypass.
func remintCredentialStatement(s Statement, refused map[string]bool) bool {
	if len(refused) == 0 {
		return false
	}
	sh, ok := statementOnTable(s, "user_credentials")
	if !ok {
		return false
	}
	username, ok := insertParamString(s, sh, "username")
	return !ok || refused[username]
}

// withoutRefusedRemints is the entry as it applied here: the refused users
// INSERTs and their paired credential statements removed.
func withoutRefusedRemints(stmts []Statement, refused map[string]bool) []Statement {
	if len(refused) == 0 {
		return stmts
	}
	out := make([]Statement, 0, len(stmts))
	for _, s := range stmts {
		if remintCredentialStatement(s, refused) {
			continue
		}
		if sh, ok := statementOnTable(s, "users"); ok && sh.Kind == KindInsert {
			if username, ok := insertParamString(s, sh, "username"); ok && refused[username] {
				continue
			}
		}
		out = append(out, s)
	}
	return out
}

// userCredentialOfRefusedRemint is the sensitive lane's check: the incoming
// user_credentials row carries the hash of a re-minted users row this node
// refused — or, where the refused row's old column had been cleared and this
// is the same exchange with the same peer (table.remints), a hash other than
// the one this node holds for the account it kept.
func (c *Client) userCredentialOfRefusedRemint(tx *sql.Tx, table syncTable, row []interface{}) (bool, error) {
	idx := columnIndexMap(table.Columns)
	username, hash := cellStr(row, idx, "username"), cellStr(row, idx, "password_hash")
	if c.remints.refused(username, hash) {
		return true, nil
	}
	if !table.remints.hashUnknown(username) {
		return false, nil
	}
	var oldVal string
	var credKey, credVal sql.NullString
	err := tx.QueryRow(
		`SELECT u.password_hash, c.username, c.password_hash
		   FROM users u LEFT JOIN user_credentials c ON c.username = u.username AND c.deleted_at IS NULL
		  WHERE u.username = ?`, username).Scan(&oldVal, &credKey, &credVal)
	if err == sql.ErrNoRows {
		return true, nil // no account of ours to compare with: refuse, never guess
	}
	if err != nil {
		return false, err
	}
	return hash != resolveCredential(credKey.Valid, credVal.String, oldVal), nil
}

// noteRemintCredentialRefused records a refused credential on the shared merge
// counters, beside the users refusal it belongs to.
func (c *Client) noteRemintCredentialRefused(path resolveTiePath) {
	c.observeMergeRejected("user_credentials", string(path), "admin_remint")
	slog.Warn("refused the credential of a re-minted admin account: the users row it belongs "+
		"to was refused as a DIFFERENT account under the same name. "+adminRemintAdvice,
		"table", "user_credentials", "reason", "admin_remint", "path", string(path))
}

// insertParamString returns the bound parameter an INSERT binds to col. It
// reports false for a column the statement does not set, or one bound to a
// literal rather than a parameter.
func insertParamString(s Statement, sh StmtShape, col string) (string, bool) {
	for i, c := range sh.InsertCols {
		if c != col || i >= len(sh.InsertVals) {
			continue
		}
		v := sh.InsertVals[i]
		if !v.isParam() || v.ParamIndex < 0 || v.ParamIndex >= len(s.Params) {
			return "", false
		}
		str, ok := s.Params[v.ParamIndex].(string)
		return str, ok
	}
	return "", false
}

// noteAdminRemintRefused records the refusal on both lanes' shared counters. The
// overwrite it replaces was completely silent, so being visible IS the fix.
func (c *Client) noteAdminRemintRefused(path resolveTiePath) {
	c.observeMergeRejected("users", string(path), "admin_remint")
	slog.Warn("refused a replicated users row that re-mints a live admin or local account: "+
		"its created_at does not match the local row's, so it is a DIFFERENT account "+
		"under the same name, not a password change. "+adminRemintAdvice,
		"table", "users", "reason", "admin_remint", "path", string(path))
}
