package corrosion

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
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
// A grant's tag is checked in its writer's own transaction
// (ErrProjectChanged). It carries no project guard: a receiver applies it
// whatever its project holds, and the tag decides whether it grants. Skipping
// it could leave its principal unbound on that receiver, and an unbound
// principal falls back to its legacy role cluster-wide. A grant to a local
// account keeps user_incarnation_v1's guard, under which a receiver that has
// not reached the account holds the grant and replays it.
//
// A quota is keyed by its project name and the incarnation it was set for
// (projectQuotaKey: "<name>~p:<incarnation>"; the bare name for a project
// born before the latch). A project reads only its own incarnation's row
// (GetProjectQuota), so another incarnation's quota never displaces or
// overrides it, by the WAL or anti-entropy, and the new incarnation's own
// quota lands, whenever it arrives, on a row the project reads once it holds
// that incarnation. A quota write carries no guard; its writer checks the
// incarnation in its own transaction (ErrProjectChanged).
//
// A node writes these forms once project_incarnation_v1 has latched, and
// also, before it has, for a project that already carries an incarnation:
// only a latched writer makes one, so every replica already decodes them
// (projectFormsFor).

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
	// projectGuardDeleted: the project is deleted, and its tombstone holds the
	// guard's incarnation (the orphan reaper's authority retirement).
	projectGuardDeleted = "project_deleted"
)

// HeldRoleSuffix follows the role of a held binding where the API lists it.
const HeldRoleSuffix = " (held)"

// ErrProjectChanged is a local write's refusal when the project it names was
// deleted or re-created between the writer's read and its write. Nothing was
// changed; the caller may read again and retry.
var ErrProjectChanged = errors.New("the project was deleted or re-created while this write was prepared; nothing was changed")

// An incarnation is a prefix and 32 hex digits (128 random bits). The prefix
// says how the name was born: projectFirstBirth for a create of a name no row
// spelled, projectRebirth for a create over a tombstone of the name. A first
// birth carries the pre-grants its creator holds over to itself
// (carryPreGrants).
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

// projectFormsFor reports whether a write may use the incarnation-bearing
// forms: once the gate is on, or when any of incs (the incarnations the rows
// it acts on hold) is set, which only a latched writer does, so every replica
// already decodes them.
func (c *Client) projectFormsFor(incs ...string) bool {
	if c.ProjectIncarnationOn() {
		return true
	}
	for _, inc := range incs {
		if inc != "" {
			return true
		}
	}
	return false
}

// carried reports whether any row of the project carries an incarnation.
func (st *projectState) carried() bool {
	if st == nil {
		return false
	}
	for _, inc := range append(append([]string{}, st.live...), st.dead...) {
		if inc != "" {
			return true
		}
	}
	return false
}

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
//   - untagged (granted before the latch, or by a host that had not latched),
//     tagged none (granted while no row of the project existed) or tagged
//     pre (granted while the project held ""): grants only while the
//     project holds its pre-latch incarnation, "" or its adopted one
//     (projectPreIncarnation, project_adoption.go). A first birth carries
//     the pre-grants its creator holds over to itself (carryPreGrants); one
//     it did not hold is held;
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
		case !tagged || tag == projectTagNone || tag == projectTagPre:
			if projectPreIncarnation(proj, inc) {
				return false
			}
		case inc != "" && tag == inc:
			return false
		}
	}
	return true
}

// defaultProjectIncarnation is the identity of the default project, which
// has no projects row by design and can never be deleted or re-created: its
// one lifetime is this constant. It is never stored in projects, but
// dependent records (automation) store it, so its bytes are pinned by a
// test.
const defaultProjectIncarnation = "default"

// projectParentVerdict is what a project's rows say of a parent reference
// (name, incarnation) held by a dependent record. The zero value is no
// verdict, so a caller that drops an error cannot read it as Current.
type projectParentVerdict int

const (
	projectParentUnknown projectParentVerdict = iota
	// projectParentCurrent: exactly one live spelling of the canonical name,
	// spelled as asked, holding the incarnation asked; or the default
	// project asked with defaultProjectIncarnation.
	projectParentCurrent
	// projectParentConflict: live, but not as asked: another incarnation, the
	// name live under another spelling, or more than one live spelling
	// ("acme" beside "/acme", which a create with the gate off can leave).
	projectParentConflict
	// projectParentAbsent: no live row of the canonical name.
	projectParentAbsent
	// projectParentUnadopted: the one live spelling still holds the
	// pre-latch incarnation "", which is not a recordable identity. Retry
	// later: the adoption pass gives it its adopted incarnation
	// (project_adoption.go), unless enforcement.project_adoption is false on
	// every host. Never a sign the parent is gone.
	projectParentUnadopted
)

func (v projectParentVerdict) String() string {
	switch v {
	case projectParentCurrent:
		return "current"
	case projectParentConflict:
		return "conflict"
	case projectParentAbsent:
		return "absent"
	case projectParentUnadopted:
		return "unadopted"
	}
	return "unknown"
}

// projectParentVerdictTx judges a parent reference (name, inc) against the
// project rows in tx. It only reads, every project row, so it is safe inside a
// caller's guarded transaction and needs no gate.
//
// Equality only: incarnations are random (or, adopted, a function of the
// name), so one is never newer or older than another, and a mismatch is a
// Conflict, whatever arrives later. A live row still holding "" is Unadopted
// whatever inc is asked; an adopted row asked with "" is a Conflict.
//
// The default project ("", "/", "_default" or "/_default") is Current for
// defaultProjectIncarnation and a Conflict otherwise, never Absent. "/" is
// accepted only as the canonical form of "", which stored rows use for the
// default project; the root itself is not a project, and the two have one
// canonical form (safename.CanonicalProjectName).
//
// A tombstone and no row at all are both Absent: neither is a live parent, and
// a tombstone's incarnation never makes one current. They differ only in what
// comes next: a create over a tombstone is a rebirth, a create over no row a
// first birth. Production never removes a project row, so no row means the
// name was never created here (or has not replicated yet).
func projectParentVerdictTx(ctx context.Context, tx *sql.Tx, name, inc string) (projectParentVerdict, error) {
	cur, v, err := projectParentIncarnationTx(ctx, tx, name)
	if err != nil || v != projectParentCurrent {
		return v, err
	}
	if cur != inc {
		return projectParentConflict, nil
	}
	return projectParentCurrent, nil
}

// projectParentIncarnationTx is the identity a dependent record of project
// name records: the live incarnation of its one live spelling, spelled as
// asked (Current), or defaultProjectIncarnation for the default project
// (Current). Otherwise it returns "" with Unadopted, Conflict or Absent (or
// Unknown and the error of a name with no canonical form).
func projectParentIncarnationTx(ctx context.Context, tx *sql.Tx, name string) (string, projectParentVerdict, error) {
	canon, err := safename.CanonicalProjectName(name)
	if err != nil {
		return "", projectParentUnknown, err
	}
	if canon == "/" || canon == "/"+DefaultProject {
		return defaultProjectIncarnation, projectParentCurrent, nil
	}
	states, err := loadProjectStatesTx(ctx, tx)
	if err != nil {
		return "", projectParentUnknown, err
	}
	st := states[canon]
	switch {
	case st == nil || len(st.live) == 0:
		return "", projectParentAbsent, nil
	case len(st.live) > 1, st.liveName[0] != name:
		return "", projectParentConflict, nil
	case st.live[0] == "":
		return "", projectParentUnadopted, nil
	}
	return st.live[0], projectParentCurrent, nil
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
// project_incarnation_v1 has latched, or once the project carries one
// (projectFormsFor). InsertRoleBinding checks the tag again in its own
// transaction.
func ProjectBindingID(ctx context.Context, c *Client, path, baseID string) (string, error) {
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
	if !c.ProjectIncarnationOn() && !states[proj].carried() {
		return baseID, nil
	}
	return baseID + projectBindingTagSep + states[proj].writerTag(), nil
}

// insertProjectBinding writes a role binding whose id carries a project tag,
// in one transaction that requires the tag to still be the one this node
// would write: a project re-created or deleted since the tag was read fails
// with ErrProjectChanged, and nothing is written. The statement carries no
// project guard; a grant to a local account is stamped with
// user_incarnation_v1's guard by the write path as any other
// (ErrUserAccountChanged if that account moved).
func insertProjectBinding(ctx context.Context, c *Client, proj, tag string, params []interface{}) error {
	projectOK := false
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		states, err := loadProjectStatesTx(ctx, tx)
		if err != nil {
			return false, err
		}
		projectOK = states[proj].writerTag() == tag
		return projectOK, nil
	}, []Statement{{SQL: roleBindingInsertSQL, Params: params}})
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

// ErrNoLiveProject refuses a quota for a project with no live row once the
// incarnation forms apply: there is no incarnation it could belong to.
var ErrNoLiveProject = errors.New("project does not exist")

// projectQuotaKey is the project_quotas key of a quota set for incarnation
// inc of project name: the bare name for a project born before the latch
// (”), as every quota was keyed before, and "<name>~p:<inc>" otherwise.
//
// The adopted incarnation is the same lifetime as "" and keys the bare name
// too (project_adoption.go), so adoption needs no re-key and a late bare-key
// write still lands on the key that is read.
func projectQuotaKey(name, inc string) string {
	if projectPreIncarnationOfName(name, inc) {
		return name
	}
	return name + projectBindingTagSep + inc
}

// projectQuotaIncarnation is the incarnation of the live project name whose
// quota a reader enforces, and whether the name is a live project of this
// node's (a name that is not, such as _default, reads its bare key).
func projectQuotaIncarnation(ctx context.Context, c *Client, name string) (string, bool, error) {
	canon, err := safename.CanonicalProjectName(name)
	if err != nil || canon == "/" {
		return "", false, nil
	}
	states, err := loadProjectStates(ctx, c)
	if err != nil {
		return "", false, err
	}
	st := states[canon]
	if st == nil || len(st.live) == 0 {
		return "", false, nil
	}
	for i, n := range st.liveName {
		if n == name {
			return st.live[i], true, nil
		}
	}
	return st.live[0], true, nil
}

// upsertProjectQuota writes a quota. Once the incarnation forms apply
// (projectFormsFor), it is keyed by the incarnation of the live project
// (projectQuotaKey), in a transaction that requires the project still to
// hold it (ErrProjectChanged); a project with no live row is refused
// (ErrNoLiveProject). Before, and for the default project (which has no row),
// the bare name is the key, as before the latch.
func upsertProjectQuota(ctx context.Context, c *Client, q ProjectQuotaRecord, now string) error {
	canon, err := safename.CanonicalProjectName(q.ProjectName)
	// The default project has no projects row and no incarnation, by design:
	// its quota keeps the bare key and the previous form, as
	// projectQuotaIncarnation reads it.
	if err != nil || canon == "/" || canon == "/"+DefaultProject {
		return c.Execute(ctx, projectQuotaUpsertSQL, q.ProjectName, q.VCPULimit, q.MemMiBLimit, q.DiskGiBLimit,
			q.NICLimit, q.PublicIPLimit, q.BackupGiBLimit, now)
	}
	states, err := loadProjectStates(ctx, c)
	if err != nil {
		return err
	}
	st := states[canon]
	if !c.ProjectIncarnationOn() && !st.carried() {
		return c.Execute(ctx, projectQuotaUpsertSQL, q.ProjectName, q.VCPULimit, q.MemMiBLimit, q.DiskGiBLimit,
			q.NICLimit, q.PublicIPLimit, q.BackupGiBLimit, now)
	}
	inc, live, err := projectQuotaIncarnation(ctx, c, q.ProjectName)
	if err != nil {
		return err
	}
	if !live {
		return fmt.Errorf("quota for project %q: %w", q.ProjectName, ErrNoLiveProject)
	}
	if h := projectWriteInterleaveHook; h != nil {
		h()
	}
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		states, err := loadProjectStatesTx(ctx, tx)
		if err != nil {
			return false, err
		}
		return states[canon].liveIncarnation(inc), nil
	}, []Statement{{SQL: projectQuotaUpsertSQL, Params: []interface{}{projectQuotaKey(q.ProjectName, inc),
		q.VCPULimit, q.MemMiBLimit, q.DiskGiBLimit, q.NICLimit, q.PublicIPLimit, q.BackupGiBLimit, now}}})
	if err != nil {
		return err
	}
	if !applied {
		return ErrProjectChanged
	}
	return nil
}

// projectIncarnationGuardMatches: the project (any spelling of the guard's
// canonical name) is deleted, with a tombstone at the guard's incarnation and
// no live spelling (projectGuardDeleted).
func (c *Client) projectIncarnationGuardMatches(ctx context.Context, tx *sql.Tx, g *MutationGuard) (bool, error) {
	if g.ResourceID == "" || g.TargetResourceID != "" || g.ResourceKind != projectGuardDeleted {
		return false, invalidf("invalid project incarnation guard")
	}
	states, err := loadProjectStatesTx(ctx, tx)
	if err != nil {
		return false, err
	}
	st := states[g.ResourceID]
	if st == nil || len(st.live) != 0 {
		return false, nil
	}
	// "" and the name's adopted incarnation are one lifetime
	// (project_adoption.go): a reaper that read either retires a tombstone
	// holding the other, and a re-created name (r…) is still protected.
	pre := projectPreIncarnation(g.ResourceID, g.Incarnation)
	for _, d := range st.dead {
		if d == g.Incarnation || (pre && projectPreIncarnation(g.ResourceID, d)) {
			return true, nil
		}
	}
	return false, nil
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
	fpRetireProjectAuthority = mustFingerprint(retireProjectAuthoritySQL)
)

// validateProjectIncarnationEntry checks an entry whose statements carry
// project_incarnation_v1 guards: no other protocol's guard beside them, and
// each guarded statement one this protocol binds (the orphan reaper's
// authority retirement), naming the guard's project.
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
			// The adopted incarnation is the pre-latch lifetime named
			// (project_adoption.go): its pre-tagged grants stay.
			if projectPreIncarnation(canon, inc) {
				keep[projectTagPre] = true
			}
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

// createFirstBirth creates a project whose name no row spells, as a first
// birth (projectFirstBirth), and then carries over to it the pre-grants its
// creator holds for it (tagged none: granted, after this build latched,
// while no row existed): each is tombstoned and granted again, tagged with the new
// incarnation, in a transaction of its own that requires the project still
// to hold that incarnation and the pre-grant still to be live. One
// transaction per binding, so each names one account (user_incarnation_v1).
// A pre-grant left behind (a crash, a concurrent revoke) is held, as is one
// this node did not hold, made on a host that saw no row
// (projectBindingHeld): nothing ties it to this project.
func createFirstBirth(ctx context.Context, c *Client, p ProjectRecord) (bool, error) {
	inc := newProjectIncarnation(true)
	canon, cerr := safename.CanonicalProjectName(p.Name)
	applied, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		if cerr != nil {
			return true, nil
		}
		states, err := loadProjectStatesTx(ctx, tx)
		if err != nil {
			return false, err
		}
		return !states[canon].exists(), nil
	}, []Statement{{
		SQL:    projectsInsertIncarnationSQL,
		Params: []interface{}{p.Name, p.Display, p.ParentName, nowRFC3339(), c.NowTS(), inc},
	}})
	if err != nil || !applied {
		return applied, err
	}
	if _, ok := projectRBACRoot(p.Name); !ok || cerr != nil {
		return true, nil
	}
	rows, err := c.Query(ctx, `SELECT id, path, role, principal, propagate FROM role_bindings WHERE deleted_at IS NULL`)
	if err != nil {
		return true, err
	}
	for _, r := range rows {
		id := r.String("id")
		if proj, ok := projectOfRBACPath(r.String("path")); !ok || proj != canon {
			continue
		}
		// Only a pre-grant this build tagged none; an untagged binding may
		// be an earlier lifetime's, granted before the latch, whose row this
		// node never held. It stays held.
		if tag, tagged := projectBindingTag(id); !tagged || tag != projectTagNone {
			continue
		}
		if _, err := c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
			states, err := loadProjectStatesTx(ctx, tx)
			if err != nil || !states[canon].liveIncarnation(inc) {
				return false, err
			}
			var n int
			err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM role_bindings WHERE id = ? AND deleted_at IS NULL`, id).Scan(&n)
			return err == nil && n == 1, err
		}, []Statement{
			{SQL: roleBindingDeleteSQL, Params: []interface{}{nowRFC3339(), c.NowTS(), id}},
			{SQL: roleBindingInsertSQL, Params: []interface{}{newSentinelID() + projectBindingTagSep + inc,
				r.String("path"), r.String("role"), r.String("principal"), r.Int("propagate"), c.NowTS()}},
		}); err != nil {
			slog.Warn("project create: a pre-grant was not carried over to the new project; it is held",
				"project", p.Name, "binding", id, "error", err)
		}
	}
	return true, nil
}

// projectsDumpDecision keeps a local projects row that carries a born
// incarnation over an incoming row of a dump without the column. Such a dump
// comes from a node whose every row has none (withoutUnsetIncarnation): it
// has never held a birth made after the latch, so its row is of an earlier
// lifetime of the name, whatever its clock says. A local row holding the
// name's adopted incarnation is the same lifetime as the incoming "" row
// (project_adoption.go), so it merges by LWW like any other row.
func projectsDumpDecision(tx *sql.Tx, table syncTable, row []interface{}) (mergeAuthorityDecision, error) {
	idx := columnIndexMap(table.Columns)
	if _, ok := idx["incarnation"]; ok {
		return mergeAuthorityNormal, nil
	}
	var local string
	err := tx.QueryRow(`SELECT incarnation FROM projects WHERE name = ?`, cellStr(row, idx, "name")).Scan(&local)
	if errors.Is(err, sql.ErrNoRows) {
		return mergeAuthorityNormal, nil
	}
	if err != nil {
		return mergeAuthorityKeepLocal, err
	}
	if !projectPreIncarnationOfName(cellStr(row, idx, "name"), local) {
		return mergeAuthorityKeepLocal, nil
	}
	return mergeAuthorityNormal, nil
}
