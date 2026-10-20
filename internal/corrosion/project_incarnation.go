package corrosion

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// A project's grants belong to the project they were made for
// (project_incarnation_v1).
//
// A project name can be deleted and created again. The delete retires the
// grants it can see, by id; a role binding a lagging node granted on the old
// project, which the deleting node never saw, used to reach the new project
// by the WAL or anti-entropy and grant there.
//
// Every birth of a name (a first create, a re-create over a tombstone) writes
// a fresh random incarnation into the projects row, in the same transaction,
// once project_incarnation_v1 has latched. Anti-entropy carries it with the
// row. Nothing else changes it: not created_at (kept by a revival) and not
// updated_at (moved by every write).
//
// A role binding under a project's RBAC path names, at the end of its id, the
// incarnation its writer held for that project (projectBindingTag). Whether
// it grants is decided from the rows alone, wherever and in whatever order
// they arrive (projectBindingHeld): while the project is live, a binding
// grants only when its tag is the project's incarnation. Any other is HELD:
// kept, listed with "(held)", granting nothing (the auth engine reads it as
// NoAccess, so its principal stays bound), and removed with lv role revoke.
//
// A node that sees a name's incarnation change also retires the bindings
// tagged with another incarnation: each becomes a NoAccess binding at its
// path (retireOlderProjectGrants). An untagged binding, granted before the
// latch, is never retired: it is held while the project holds an incarnation
// born after the latch, and grants as before while the project still holds
// the one it had (none).
//
// Grant and quota writes under a live project carry a project_incarnation_v1
// mutation guard naming the incarnation, checked in the writer's own
// transaction (ErrProjectChanged). A receiver skips a quota that names
// another incarnation. It applies a grant that names another one, which its
// tag then holds: a binding may be its principal's first, and skipping it
// would leave the principal unbound on that receiver, which falls back to its
// legacy role cluster-wide. A NoAccess binding is never guarded, for the same
// reason.

// SetProjectIncarnationGate injects the predicate that says
// project_incarnation_v1 has DURABLY latched. Nil-safe; unset reads false: the
// previous release's statements, no tags and no guards.
func (c *Client) SetProjectIncarnationGate(fn func() bool) {
	if fn == nil {
		c.projectIncarnationGate.Store(nil)
		return
	}
	c.projectIncarnationGate.Store(&fn)
}

// ProjectIncarnationOn reports whether this node writes project incarnations,
// binding tags and project guards.
func (c *Client) ProjectIncarnationOn() bool {
	fn := c.projectIncarnationGate.Load()
	return fn != nil && (*fn)()
}

const (
	projectIncarnationGuardV1 = "project_incarnation_v1"
	// projectGuardLive: the project is live and holds the guard's incarnation
	// (a quota).
	projectGuardLive = "project_live"
	// projectGuardGrant: a role binding granted for the guard's incarnation
	// of a live project. Its writer requires that incarnation
	// (insertProjectBinding); a receiver applies it whatever its project
	// holds, and the binding's tag decides whether it grants
	// (projectBindingHeld). TargetResourceID and TargetIncarnation, when set,
	// name the local account it is granted to, which must be live at that
	// incarnation (user_incarnation_v1's user_live), or the receiver skips it.
	projectGuardGrant = "project_grant"
	// projectGuardDeleted: the project is deleted, and its tombstone holds the
	// guard's incarnation (the orphan reaper's authority retirement).
	projectGuardDeleted = "project_deleted"
)

// ErrProjectChanged is a local write's refusal when the project it names was
// deleted or re-created between the writer's read and its write. Nothing was
// changed; the caller may read again and retry.
var ErrProjectChanged = errors.New("the project was deleted or re-created while this write was prepared; nothing was changed")

// An incarnation is a prefix and 32 hex digits (128 random bits). The prefix
// says how the name was born: projectFirstBirth for a create of a name no row
// spelled, projectRebirth for a create over a tombstone of the name. Only a
// first birth takes the bindings granted while no row existed (a pre-grant).
const (
	projectFirstBirth = "f"
	projectRebirth    = "r"
)

func newProjectIncarnation(first bool) string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("rand.Read: " + err.Error())
	}
	if first {
		return projectFirstBirth + hex.EncodeToString(buf)
	}
	return projectRebirth + hex.EncodeToString(buf)
}

// projectsInsertIncarnationSQL is a project's first create with its
// incarnation; the previous release's has no incarnation column.
const projectsInsertIncarnationSQL = `INSERT INTO projects (name, display, parent_name, created_at, updated_at, incarnation)
		 VALUES (?, ?, ?, ?, ?, ?)`

// projectsReviveIncarnationSQL re-creates a deleted name as a new
// incarnation. Its deleted_at is bound to NULL.
const projectsReviveIncarnationSQL = `UPDATE projects SET deleted_at = ?, incarnation = ?, updated_at = ? WHERE name = ?`

// A role binding's id ends in projectBindingTagSep and its tag once its
// writer has latched and its path is under a project.
const (
	projectBindingTagSep = "~p:"
	// projectTagNone: the writer held no row of the project (a pre-grant).
	projectTagNone = "none"
	// projectTagPre: the writer held the project at the incarnation it was
	// born with before the latch ('').
	projectTagPre = "pre"
)

// projectBindingTag is the tag a binding id carries, if any.
func projectBindingTag(id string) (string, bool) {
	i := strings.LastIndex(id, projectBindingTagSep)
	if i < 0 {
		return "", false
	}
	return id[i+len(projectBindingTagSep):], true
}

// projectIncarnationTag is the tag of a binding granted for incarnation inc.
func projectIncarnationTag(inc string) string {
	if inc == "" {
		return projectTagPre
	}
	return inc
}

// CarryProjectBindingTag returns newID with the tag oldID carries, so a copy
// of a binding (lv role normalize) names the incarnation the original did.
func CarryProjectBindingTag(oldID, newID string) string {
	if tag, ok := projectBindingTag(oldID); ok {
		return newID + projectBindingTagSep + tag
	}
	return newID
}

// projectOfRBACPath is the canonical name of the project whose RBAC subtree
// path is in: the segments under /projects up to the first resource
// namespace (vms, containers, ...). ok=false outside /projects, for the
// default project, and for a path with no valid project name.
func projectOfRBACPath(path string) (string, bool) {
	rest, ok := strings.CutPrefix(path, "/projects/")
	if !ok {
		return "", false
	}
	var segs []string
	for i, seg := range strings.Split(strings.Trim(rest, "/"), "/") {
		if i > 0 && safename.IsReservedProjectSegment(seg) {
			break
		}
		segs = append(segs, seg)
	}
	canon, err := safename.CanonicalProjectName("/" + strings.Join(segs, "/"))
	if err != nil || canon == "/" || canon == "/"+DefaultProject {
		return "", false
	}
	return canon, true
}

// projectState is what a node holds for one canonical project name, across
// its spellings ("acme", "/acme").
type projectState struct {
	live     []string // the incarnations of its live rows
	liveName []string // their names, sorted with live
	dead     []string // the incarnations of its tombstones
	deadAt   []string
}

func (st *projectState) exists() bool { return st != nil && (len(st.live) > 0 || len(st.dead) > 0) }

// writerTag is the tag a binding granted now for this project carries: its
// live incarnation (the first live spelling's), else its newest tombstone's,
// else none.
func (st *projectState) writerTag() string {
	switch {
	case st == nil || !st.exists():
		return projectTagNone
	case len(st.live) > 0:
		return projectIncarnationTag(st.live[0])
	}
	best := 0
	for i := range st.dead {
		if LWWNewer(st.deadAt[i], st.deadAt[best]) {
			best = i
		}
	}
	return projectIncarnationTag(st.dead[best])
}

// liveIncarnation reports whether inc is the incarnation of a live row.
func (st *projectState) liveIncarnation(inc string) bool {
	if st == nil {
		return false
	}
	for _, l := range st.live {
		if l == inc {
			return true
		}
	}
	return false
}

// projectStates indexes project rows (name, deleted_at, incarnation,
// updated_at) by canonical name. A row with no canonical form is skipped:
// projectOfRBACPath never names one.
func projectStates(rows [][4]string, deleted []bool) map[string]*projectState {
	type liveRow struct{ name, inc string }
	lives := map[string][]liveRow{}
	out := map[string]*projectState{}
	for i, r := range rows {
		canon, err := safename.CanonicalProjectName(r[0])
		if err != nil {
			continue
		}
		st := out[canon]
		if st == nil {
			st = &projectState{}
			out[canon] = st
		}
		if deleted[i] {
			st.dead = append(st.dead, r[2])
			st.deadAt = append(st.deadAt, r[3])
		} else {
			lives[canon] = append(lives[canon], liveRow{r[0], r[2]})
		}
	}
	for canon, ls := range lives {
		sort.Slice(ls, func(i, j int) bool { return ls[i].name < ls[j].name })
		for _, l := range ls {
			out[canon].live = append(out[canon].live, l.inc)
			out[canon].liveName = append(out[canon].liveName, l.name)
		}
	}
	return out
}

const projectStatesSQL = `SELECT name, deleted_at, incarnation, updated_at FROM projects`

// loadProjectStates reads every project row through the client.
func loadProjectStates(ctx context.Context, c *Client) (map[string]*projectState, error) {
	rows, err := c.Query(ctx, projectStatesSQL)
	if err != nil {
		return nil, err
	}
	vals := make([][4]string, len(rows))
	del := make([]bool, len(rows))
	for i, r := range rows {
		vals[i] = [4]string{r.String("name"), r.String("deleted_at"), r.String("incarnation"), r.String("updated_at")}
		del[i] = r.String("deleted_at") != ""
	}
	return projectStates(vals, del), nil
}

// loadProjectStatesTx reads every project row inside tx.
func loadProjectStatesTx(ctx context.Context, tx *sql.Tx) (map[string]*projectState, error) {
	rows, err := tx.QueryContext(ctx, projectStatesSQL)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var vals [][4]string
	var del []bool
	for rows.Next() {
		var name, inc, upd string
		var deleted sql.NullString
		if err := rows.Scan(&name, &deleted, &inc, &upd); err != nil {
			return nil, err
		}
		vals = append(vals, [4]string{name, deleted.String, inc, upd})
		del = append(del, deleted.Valid && deleted.String != "")
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return projectStates(vals, del), nil
}

// projectBindingHeld reports whether a live binding is held: under a live
// project that does not hold the incarnation it was granted for. A binding
// outside every project, or under one with no live row, is never held.
//
//   - untagged (granted before the latch, or by a host that had not latched):
//     grants only while the project holds its pre-latch incarnation;
//   - tagged none (granted while no row of the project existed): grants only
//     on a first birth, or a pre-latch incarnation;
//   - tagged with an incarnation: grants only on it.
func projectBindingHeld(b RoleBindingRecord, states map[string]*projectState) bool {
	proj, ok := projectOfRBACPath(b.Path)
	if !ok {
		return false
	}
	st := states[proj]
	if st == nil || len(st.live) == 0 {
		return false
	}
	tag, tagged := projectBindingTag(b.ID)
	for _, inc := range st.live {
		switch {
		case !tagged:
			if inc == "" {
				return false
			}
		case tag == projectTagNone:
			if inc == "" || strings.HasPrefix(inc, projectFirstBirth) {
				return false
			}
		case tag == projectIncarnationTag(inc):
			return false
		}
	}
	return true
}

// markHeldBindings sets Held on every binding projectBindingHeld holds.
func markHeldBindings(ctx context.Context, c *Client, bs []RoleBindingRecord) error {
	if len(bs) == 0 {
		return nil
	}
	states, err := loadProjectStates(ctx, c)
	if err != nil {
		return err
	}
	for i := range bs {
		bs[i].Held = projectBindingHeld(bs[i], states)
	}
	return nil
}

// ProjectBindingID is the id a role binding at path is written with: baseID,
// tagged with the incarnation this node holds for the path's project once
// project_incarnation_v1 has latched. InsertRoleBinding checks the tag again
// in its own transaction.
func ProjectBindingID(ctx context.Context, c *Client, path, baseID string) (string, error) {
	if !c.ProjectIncarnationOn() {
		return baseID, nil
	}
	proj, ok := projectOfRBACPath(path)
	if !ok {
		return baseID, nil
	}
	if _, tagged := projectBindingTag(baseID); tagged {
		return baseID, nil
	}
	states, err := loadProjectStates(ctx, c)
	if err != nil {
		return "", err
	}
	return baseID + projectBindingTagSep + states[proj].writerTag(), nil
}

// insertProjectBinding writes a role binding whose id carries a project tag,
// in one transaction that requires the tag to still be the one this node
// would write: a project re-created or deleted since the tag was read fails
// with ErrProjectChanged, and nothing is written. A grant under a live project
// carries a projectGuardGrant guard, naming the account it grants to when
// that is a local user (whose incarnation must hold too, or
// ErrUserAccountChanged). A NoAccess binding is never guarded.
func insertProjectBinding(ctx context.Context, c *Client, proj, tag string, params []interface{}, role string) error {
	var guard *MutationGuard
	if tag != projectTagNone && role != SentinelRole {
		inc := tag
		if tag == projectTagPre {
			inc = ""
		}
		guard = &MutationGuard{Protocol: projectIncarnationGuardV1, ResourceKind: projectGuardGrant, ResourceID: proj, Incarnation: inc}
		if user := roleBindingAccount(params); user != "" && c.UserIncarnationOn() {
			rows, err := c.Query(ctx, `SELECT created_at FROM users WHERE username = ?`, user)
			if err != nil {
				return err
			}
			if len(rows) > 0 && rows[0].String("created_at") != "" {
				guard.TargetResourceID, guard.TargetIncarnation = user, rows[0].String("created_at")
			}
		}
	}
	projectOK := false
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		states, err := loadProjectStatesTx(ctx, tx)
		if err != nil {
			return false, err
		}
		projectOK = states[proj].writerTag() == tag
		return projectOK, nil
	}, []Statement{{SQL: roleBindingInsertSQL, Params: params, Guard: guard}})
	if err != nil {
		return err
	}
	if !applied {
		if !projectOK {
			return ErrProjectChanged
		}
		return ErrUserAccountChanged
	}
	return nil
}

// projectWriteInterleaveHook, when set (tests only), runs after a guarded
// project write has read the incarnation it binds and before its
// transaction.
var projectWriteInterleaveHook func()

// upsertProjectQuotaGuarded writes a quota of a live project bound to the
// incarnation read here: ErrProjectChanged if the project is re-created or
// deleted before the write.
func upsertProjectQuotaGuarded(ctx context.Context, c *Client, params []interface{}) error {
	proj, err := safename.CanonicalProjectName(coerceString(params[0]))
	if err != nil || proj == "/" {
		return c.Execute(ctx, projectQuotaUpsertSQL, params...)
	}
	states, err := loadProjectStates(ctx, c)
	if err != nil {
		return err
	}
	st := states[proj]
	if st == nil || len(st.live) == 0 {
		return c.Execute(ctx, projectQuotaUpsertSQL, params...)
	}
	g := &MutationGuard{Protocol: projectIncarnationGuardV1, ResourceKind: projectGuardLive, ResourceID: proj, Incarnation: st.live[0]}
	if h := projectWriteInterleaveHook; h != nil {
		h()
	}
	applied, err := c.ExecuteBatchGuarded(ctx, func(*sql.Tx) (bool, error) { return true, nil },
		[]Statement{{SQL: projectQuotaUpsertSQL, Params: params, Guard: g}})
	if err != nil {
		return err
	}
	if !applied {
		return ErrProjectChanged
	}
	return nil
}

// projectIncarnationGuardMatches: the project (any spelling of the guard's
// canonical name) is live at the guard's incarnation (projectGuardLive), or
// deleted with a tombstone at it and no live spelling (projectGuardDeleted);
// a grant (projectGuardGrant) applies whatever the project holds, and only
// while the account it names, if any, is the incarnation it names.
func (c *Client) projectIncarnationGuardMatches(ctx context.Context, tx *sql.Tx, g *MutationGuard) (bool, error) {
	if g.ResourceID == "" {
		return false, invalidf("invalid project incarnation guard")
	}
	states, err := loadProjectStatesTx(ctx, tx)
	if err != nil {
		return false, err
	}
	st := states[g.ResourceID]
	switch g.ResourceKind {
	case projectGuardGrant:
	case projectGuardLive:
		if !st.liveIncarnation(g.Incarnation) {
			return false, nil
		}
	case projectGuardDeleted:
		if st == nil || len(st.live) > 0 || !containsString(st.dead, g.Incarnation) {
			return false, nil
		}
	default:
		return false, invalidf("invalid project incarnation guard kind %q", g.ResourceKind)
	}
	if g.TargetResourceID == "" {
		return true, nil
	}
	if g.TargetIncarnation == "" {
		return false, invalidf("project incarnation guard names an account with no incarnation")
	}
	v, err := c.userGuardVerdictOf(ctx, tx, &MutationGuard{Protocol: userIncarnationGuardV1,
		ResourceKind: userGuardLive, ResourceID: g.TargetResourceID, Incarnation: g.TargetIncarnation})
	if err != nil {
		return false, err
	}
	return v == userVerdictApply && !c.userHolds.newerKnown(g.TargetResourceID, g.TargetIncarnation), nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

var (
	fpRoleBindingInsert      = mustFingerprint(roleBindingInsertSQL)
	fpProjectQuotaUpsert     = mustFingerprint(projectQuotaUpsertSQL)
	fpRetireProjectAuthority = mustFingerprint(retireProjectAuthoritySQL)
)

// validateProjectIncarnationEntry checks an entry whose statements carry
// project_incarnation_v1 guards: no other protocol's guard beside them, and
// each guarded statement one this protocol binds, naming the guard's project
// (and, for a role binding, its tag and account).
func validateProjectIncarnationEntry(stmts []Statement) error {
	for _, s := range stmts {
		if s.Guard == nil {
			continue
		}
		g := s.Guard
		if g.Protocol != projectIncarnationGuardV1 {
			return invalidf("project incarnation entry mixes mutation guard protocols")
		}
		if g.ResourceID == "" {
			return invalidf("invalid project incarnation guard")
		}
		sh, _, err := parseResolved(s.SQL)
		if err != nil {
			return err
		}
		canonOf := func(v interface{}) string {
			n, err := safename.CanonicalProjectName(coerceString(v))
			if err != nil {
				return ""
			}
			return n
		}
		switch fp := stmtFingerprint(sh); {
		case fp == fpRoleBindingInsert && g.ResourceKind == projectGuardGrant && len(s.Params) == 6:
			proj, ok := projectOfRBACPath(coerceString(s.Params[1]))
			tag, tagged := projectBindingTag(coerceString(s.Params[0]))
			if !ok || proj != g.ResourceID || !tagged || tag != projectIncarnationTag(g.Incarnation) ||
				coerceString(s.Params[2]) == SentinelRole {
				return invalidf("project incarnation guard on a role binding it does not bind")
			}
			if g.TargetResourceID != "" && (roleBindingAccount(s.Params) != g.TargetResourceID || g.TargetIncarnation == "") {
				return invalidf("project incarnation guard names another account than its role binding")
			}
		case fp == fpProjectQuotaUpsert && g.ResourceKind == projectGuardLive && len(s.Params) == 8:
			if canonOf(s.Params[0]) != g.ResourceID || g.TargetResourceID != "" {
				return invalidf("project incarnation guard on a quota it does not bind")
			}
		case fp == fpRetireProjectAuthority && g.ResourceKind == projectGuardDeleted && len(s.Params) == 3:
			if canonOf(s.Params[2]) != g.ResourceID || g.TargetResourceID != "" {
				return invalidf("project incarnation guard on an authority retirement it does not bind")
			}
		default:
			return invalidf("project incarnation guard on a statement it does not bind (table %s)", sh.Table)
		}
	}
	return nil
}

// projectsStatementName is the project name a projects-table statement
// writes, or "".
func projectsStatementName(s Statement) string {
	if !strings.Contains(s.SQL, "projects") {
		return ""
	}
	sh, _, err := parseResolved(s.SQL)
	if err != nil || sh.Table != "projects" {
		return ""
	}
	if pk, ok := pkValuesFromShape(sh, s); ok && len(pk) == 1 {
		return coerceString(pk[0])
	}
	return ""
}

// projectNoRow is projectIncarnationHeld's answer for a name with no row.
const projectNoRow = "\x00"

// projectIncarnationHeld is the incarnation the projects row of name holds in
// tx, or projectNoRow.
func projectIncarnationHeld(ctx context.Context, tx *sql.Tx, name string) (string, error) {
	var inc string
	err := tx.QueryRowContext(ctx, `SELECT incarnation FROM projects WHERE name = ?`, name).Scan(&inc)
	if errors.Is(err, sql.ErrNoRows) {
		return projectNoRow, nil
	}
	return inc, err
}

// settleProjectName runs inside tx once the projects row of name may have
// moved; before is the incarnation it held first (projectIncarnationHeld).
// Only a change of incarnation retires anything: a delete, a display write or
// an anti-entropy merge of the same incarnation retires nothing.
func settleProjectName(ctx context.Context, tx *sql.Tx, name, before string) error {
	after, err := projectIncarnationHeld(ctx, tx, name)
	if err != nil {
		return err
	}
	if after == before || after == projectNoRow {
		return nil
	}
	return retireOlderProjectGrants(ctx, tx, name)
}

// retireOlderProjectGrants makes, on this node, every live binding under the
// project of name that is tagged with an incarnation none of its rows holds
// a NoAccess binding at its path: its principal stays bound and is granted
// nothing there. It is a local write stamped just after the binding's own
// updated_at, the same on every node that makes it, so anti-entropy carries
// it over the binding and any later write of it still wins. An untagged or
// none-tagged binding is left as it is (projectBindingHeld decides it).
func retireOlderProjectGrants(ctx context.Context, tx *sql.Tx, name string) error {
	canon, err := safename.CanonicalProjectName(name)
	if err != nil || canon == "/" {
		return nil
	}
	states, err := loadProjectStatesTx(ctx, tx)
	if err != nil {
		return err
	}
	st := states[canon]
	keep := map[string]bool{projectTagNone: true}
	if st != nil {
		for _, inc := range append(append([]string{}, st.live...), st.dead...) {
			keep[projectIncarnationTag(inc)] = true
		}
	}
	rows, err := tx.QueryContext(ctx, `SELECT id, path, updated_at FROM role_bindings
		WHERE deleted_at IS NULL AND role <> ? AND id LIKE ?`, SentinelRole, "%"+projectBindingTagSep+"%")
	if err != nil {
		return err
	}
	type retire struct{ id, at string }
	var out []retire
	for rows.Next() {
		var id, path, upd string
		if err := rows.Scan(&id, &path, &upd); err != nil {
			rows.Close()
			return err
		}
		if p, ok := projectOfRBACPath(path); !ok || p != canon {
			continue
		}
		if tag, ok := projectBindingTag(id); ok && !keep[tag] {
			if at, ok := justAfterTS(upd); ok {
				out = append(out, retire{id, at})
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	for _, r := range out {
		if _, err := tx.ExecContext(ctx, `UPDATE role_bindings SET role = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
			SentinelRole, r.at, r.id); err != nil {
			return err
		}
	}
	return nil
}
