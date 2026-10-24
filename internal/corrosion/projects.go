package corrosion

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/safename"
)

// DefaultProject is the implicit bucket every VM lands in when no
// project: tag is set in compose or the CLI. Single-tenant clusters
// never need to interact with the projects table.
const DefaultProject = "_default"

// ProjectRecord is one row in the projects table — a hierarchical
// path like "/acme/team-foo".
type ProjectRecord struct {
	Name       string // canonical path; PRIMARY KEY
	Display    string
	ParentName string // "" for root
	CreatedAt  string
	UpdatedAt  string
	// Incarnation is the project's incarnation: a random id written by each
	// birth of the name, '' for one born before project_incarnation_v1
	// (project_incarnation.go). Read-only.
	Incarnation string
}

// ProjectQuotaRecord caps one project's resource usage. Zero = unbounded.
type ProjectQuotaRecord struct {
	ProjectName    string
	VCPULimit      int
	MemMiBLimit    int
	DiskGiBLimit   int
	NICLimit       int
	PublicIPLimit  int
	BackupGiBLimit int
}

// projectLifecycleInterleaveHook, when set (tests only), runs after a project
// create/delete has read the state it will act on and before its guarded
// transaction: the window a concurrent lifecycle change has to be tolerated in.
var projectLifecycleInterleaveHook func()

// InsertProject creates a new project. Parent must already exist
// (or be empty for a root project). Use UpsertProjectQuota afterwards
// to set quotas; without quotas the project is unbounded.
func InsertProject(ctx context.Context, c *Client, p ProjectRecord) error {
	if p.Name == "" {
		return fmt.Errorf("project name required")
	}
	if p.ParentName != "" {
		existing, err := GetProject(ctx, c, p.ParentName)
		if err != nil {
			return fmt.Errorf("check parent: %w", err)
		}
		if existing == nil {
			return fmt.Errorf("parent project %q does not exist", p.ParentName)
		}
	}
	// A tombstone under this name is a previous incarnation. It is revived in
	// place with the statement shape DeleteProject already replicates, bound with
	// a NULL deleted_at: no new shape, so no peer needs upgrading and nothing is
	// gated. The HLC updated_at makes the revive beat the old tombstone on every
	// replica, and a late copy of that tombstone (older clock) lose; a delete
	// issued after seeing the revive carries a newer clock and wins.
	old, err := c.Query(ctx, `SELECT display, parent_name, updated_at FROM projects WHERE name = ? AND deleted_at IS NOT NULL`, p.Name)
	if err != nil {
		return fmt.Errorf("check previous incarnation: %w", err)
	}
	// A live project is refused before any statement is built.
	live, err := c.Query(ctx, `SELECT 1 FROM projects WHERE name = ? AND deleted_at IS NULL`, p.Name)
	if err != nil {
		return fmt.Errorf("check existing project: %w", err)
	}
	if len(live) > 0 {
		return fmt.Errorf("project %q already exists", p.Name)
	}
	if len(old) == 0 {
		// Another spelling of the name ("acme" for a deleted "/acme") shares its
		// RBAC root, so a tombstone under it is a previous incarnation too.
		prev, perr := tombstonedSpellings(ctx, c, p.Name)
		if perr != nil {
			return perr
		}
		if !prev {
			now := c.NowTS()
			if c.ProjectIncarnationOn() {
				// A first birth, carrying over the pre-grants this node holds
				// (project_incarnation.go).
				applied, err := createFirstBirth(ctx, c, p)
				if err != nil {
					return err
				}
				if !applied {
					return projectLostRace(ctx, c, p.Name)
				}
				return nil
			}
			return c.Execute(ctx,
				`INSERT INTO projects (name, display, parent_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
				p.Name, p.Display, p.ParentName, nowRFC3339(), now)
		}
		if err := refuseOwnedResources(ctx, c, p.Name); err != nil {
			return err
		}
		// The previous incarnation's grants go in the SAME transaction as the
		// create, and only if the name is still absent in it. A create that loses
		// has retired nothing.
		if h := projectLifecycleInterleaveHook; h != nil {
			h()
		}
		applied, err := commitProjectLifecycle(ctx, c, lifecycleCreate, p, projectRowGuard(ctx, p.Name, false, ""))
		if err != nil {
			return fmt.Errorf("retire previous incarnation's grants: %w", err)
		}
		if !applied {
			return projectLostRace(ctx, c, p.Name)
		}
		return nil
	}
	// The revive can only clear the tombstone, not rewrite the row, so display
	// and parent are those of the old incarnation. Never keep them silently.
	oldDisplay, oldParent := old[0].String("display"), old[0].String("parent_name")
	if p.Display != "" && p.Display != oldDisplay {
		if oldDisplay == "" {
			return fmt.Errorf("project %q was deleted with no display name and a re-created project keeps that; "+
				"create it without --display", p.Name)
		}
		return fmt.Errorf("project %q was deleted with display %q and a re-created project keeps it; "+
			"create it with --display %q, or with no --display", p.Name, oldDisplay, oldDisplay)
	}
	if !sameProjectPath(p.ParentName, oldParent) {
		return fmt.Errorf("project %q was deleted under parent %q (%q now); a re-created project keeps its parent",
			p.Name, oldParent, p.ParentName)
	}
	// Project-owned resources an older build let outlive the delete would be
	// inherited by the new incarnation: refuse, as DeleteProject does.
	if err := refuseOwnedResources(ctx, c, p.Name); err != nil {
		return err
	}
	// The revive wins or loses ATOMICALLY with the retirement: the guard requires
	// the tombstone we read (same updated_at) to still be the row, so a concurrent
	// re-create that won leaves this request with nothing retired, and the grants
	// it retires are those of the incarnation it actually revives.
	if h := projectLifecycleInterleaveHook; h != nil {
		h()
	}
	applied, err := commitProjectLifecycle(ctx, c, lifecycleRevive, p, projectRowGuard(ctx, p.Name, true, old[0].String("updated_at")))
	if err != nil {
		return fmt.Errorf("retire previous incarnation's grants: %w", err)
	}
	if !applied {
		return projectLostRace(ctx, c, p.Name)
	}
	return nil
}

// projectLostRace names why a guarded create did not apply.
func projectLostRace(ctx context.Context, c *Client, name string) error {
	if live, err := c.Query(ctx, `SELECT 1 FROM projects WHERE name = ? AND deleted_at IS NULL`, name); err == nil && len(live) > 0 {
		return fmt.Errorf("project %q already exists", name)
	}
	return fmt.Errorf("project %q was changed concurrently; retry", name)
}

// projectRowGuard is the in-transaction condition of a project lifecycle batch.
// tombstoned=true: the row exists, is deleted and still has updated_at == at (the
// incarnation the caller read). tombstoned=false with at=="": no row of this
// name exists. A live row (at=="", tombstoned=true is not asked for) never
// matches either.
func projectRowGuard(ctx context.Context, name string, tombstoned bool, at string) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var deleted sql.NullString
		var upd string
		err := tx.QueryRowContext(ctx, `SELECT deleted_at, updated_at FROM projects WHERE name = ?`, name).Scan(&deleted, &upd)
		if errors.Is(err, sql.ErrNoRows) {
			return !tombstoned, nil
		}
		if err != nil {
			return false, err
		}
		return tombstoned && deleted.Valid && upd == at, nil
	}
}

// projectLiveRowGuard: the row is live and still has updated_at == at.
func projectLiveRowGuard(ctx context.Context, name, at string) func(tx *sql.Tx) (bool, error) {
	return func(tx *sql.Tx) (bool, error) {
		var deleted sql.NullString
		var upd string
		err := tx.QueryRowContext(ctx, `SELECT deleted_at, updated_at FROM projects WHERE name = ?`, name).Scan(&deleted, &upd)
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return !deleted.Valid && upd == at, nil
	}
}

// projectRBACRoot is the RBAC path root of a project name, built like
// safename.ProjectRBACPath(CanonicalProjectName(name)). ok=false for a name
// that has no valid canonical form.
func projectRBACRoot(name string) (string, bool) {
	canon, err := safename.CanonicalProjectName(name)
	if err != nil {
		return "", false
	}
	// A name the validator refuses to create ("/", "/_default", a segment named
	// like a resource namespace such as "/acme/vms") has a canonical root that is
	// not the row's own: "/projects", the default project's, or a live parent
	// project's resource namespace. A row that already carries one (an older
	// build made it) derives no prefix retirement. One predicate, the creator's.
	if safename.ValidateNewProjectName(name) != nil {
		return "", false
	}
	return safename.ProjectRBACPath(canon), true
}

// sameProjectPath reports whether two project names are one project: equal
// after canonicalisation ("acme" and "/acme"), or equal as raw strings when
// either has no canonical form. "" is only equal to "".
func sameProjectPath(a, b string) bool {
	if a == b {
		return true
	}
	if a == "" || b == "" {
		return false
	}
	ca, ea := safename.CanonicalProjectName(a)
	cb, eb := safename.CanonicalProjectName(b)
	return ea == nil && eb == nil && ca == cb
}

// tombstonedSpellings reports whether a TOMBSTONED project of another spelling
// of name exists with no LIVE sibling spelling left: the previous incarnation of
// the same RBAC root.
func tombstonedSpellings(ctx context.Context, c *Client, name string) (bool, error) {
	rows, err := c.Query(ctx, `SELECT name, deleted_at FROM projects WHERE name <> ?`, name)
	if err != nil {
		return false, err
	}
	dead := false
	for _, r := range rows {
		if !sameProjectPath(r.String("name"), name) {
			continue
		}
		if r.String("deleted_at") == "" {
			return false, nil
		}
		dead = true
	}
	return dead, nil
}

// refuseOwnedResources refuses while a live resource still belongs to the
// project, naming each with the command that removes it. These carry the
// project name in a column and resolve under the project's RBAC root, so a
// project of the same name created later would inherit them — and with them
// whatever their owner chose (a network's config, a storage pool and its
// content, a backup repo, a notification target).
func refuseOwnedResources(ctx context.Context, c *Client, name string) error {
	owned := func(p string) bool { return p != "" && sameProjectPath(p, name) }
	var found []string

	nets, err := c.Query(ctx, `SELECT name, COALESCE(project, '') AS project FROM networks WHERE deleted_at IS NULL`)
	if err != nil {
		return err
	}
	for _, r := range nets {
		if owned(r.String("project")) {
			found = append(found, fmt.Sprintf("network %q (lv network rm %s)", r.String("name"), r.String("name")))
		}
	}
	pools, err := c.Query(ctx, `SELECT DISTINCT name, COALESCE(project, '') AS project FROM storage_pools WHERE deleted_at IS NULL`)
	if err != nil {
		return err
	}
	for _, r := range pools {
		if owned(r.String("project")) {
			found = append(found, fmt.Sprintf("storage pool %q (lv pool delete %s)", r.String("name"), r.String("name")))
		}
	}
	scheds, err := c.Query(ctx, `SELECT vm_name, repo, scope, COALESCE(project_name, '') AS project_name
		FROM backup_schedules WHERE deleted_at IS NULL AND scope IN ('project', 'container')`)
	if err != nil {
		return err
	}
	for _, r := range scheds {
		rec := BackupScheduleRecord{VMName: r.String("vm_name"), Scope: r.String("scope"), ProjectName: r.String("project_name")}
		proj := rec.ProjectName
		if rec.Scope == "container" {
			proj = ContainerScheduleProject(rec)
		}
		if owned(proj) {
			found = append(found, fmt.Sprintf("%s backup schedule %q to repo %q (lv backup schedule ls; lv backup schedule rm)",
				rec.Scope, rec.VMName, r.String("repo")))
		}
	}
	routes, err := c.Query(ctx, `SELECT id, COALESCE(project, '') AS project FROM notification_routes WHERE deleted_at IS NULL`)
	if err != nil {
		return err
	}
	for _, r := range routes {
		if owned(r.String("project")) {
			found = append(found, fmt.Sprintf("notification route %q (lv notify route rm %s)", r.String("id"), r.String("id")))
		}
	}
	if len(found) > 0 {
		return fmt.Errorf("project %q still owns %s; delete them first", name, strings.Join(found, ", "))
	}
	return nil
}

// bindingSentinelPath is where the NoAccess binding retireProjectGrants leaves
// for a principal sits: the root, which no project's RBAC root is under, so a
// later re-create (which retires everything under ITS root) never removes it.
const bindingSentinelPath = "/"

// commitProjectLifecycle (below) retires everything granting
// authority over a project NAME, so a later project of the same name starts with
// none: its admission authority, every role binding at or under its RBAC path,
// and its quota. All three are keyed by the name, not by an incarnation. It builds the
// statements and runs them in the same guarded transaction as the project row's
// own change (kind), so they apply with it or not at all. Existing
// statement shapes only.
//
// Every principal that loses a binding is left a NoAccess sentinel (bound, no
// verbs) at the root, unless it already has one. RequirePerm treats a principal
// with no bindings at all as "use the legacy role, cluster-wide", so retiring the
// last binding of a principal must never leave it unbound — and "the last" cannot
// be decided from a snapshot: two projects deleted at once, each seeing the
// other's binding as the survivor, would both skip the sentinel. Leaving one
// whenever a binding is retired is correct under any interleaving; a duplicate
// grants nothing (RevokeRoleBindingLeavingSentinel does the same).
type projectLifecycleKind int

const (
	lifecycleCreate projectLifecycleKind = iota // INSERT a project whose name has no row
	lifecycleRevive                             // clear the tombstone of the row read
	lifecycleDelete                             // tombstone the live row read
)

func commitProjectLifecycle(ctx context.Context, c *Client, kind projectLifecycleKind, p ProjectRecord, guard func(tx *sql.Tx) (bool, error)) (bool, error) {
	name := p.Name
	stmts := []Statement{{
		SQL:    retireProjectAuthoritySQL,
		Params: []interface{}{nowRFC3339(), c.NowTS(), projectOrDefault(name)},
	}}
	// Two spellings of one project ("acme", "/acme") are two rows but one RBAC
	// path: another LIVE spelling still owns these bindings, so leave them.
	spelled, err := c.Query(ctx, `SELECT name FROM projects WHERE name <> ? AND deleted_at IS NULL`, name)
	if err != nil {
		return false, err
	}
	root, ok := projectRBACRoot(name)
	liveSpellings := liveSpellingsOf(name, spelled)
	for _, r := range spelled {
		if other, oerr := projectRBACRoot(r.String("name")); oerr && other == root {
			ok = false
		}
	}
	if h := projectSpellingsReadHook; h != nil {
		h()
	}
	if ok {
		rows, err := c.Query(ctx,
			`SELECT id, path, role, principal FROM role_bindings WHERE deleted_at IS NULL`)
		if err != nil {
			return false, err
		}
		// A binding outside /projects/ cannot be retired by any project delete (the
		// sentinel itself, at "/", is one, so a principal gets at most one), so
		// a principal that holds one keeps its authority whatever the deletes do:
		// root-scope and group-held grants (group:admin@local at "/") need no
		// sentinel, and giving one would turn a later revoke of that grant into a
		// lockout instead of a fall-back to the legacy role.
		stable := map[string]bool{}
		for _, r := range rows {
			if pth := r.String("path"); pth != "/projects" && !strings.HasPrefix(pth, "/projects/") {
				stable[r.String("principal")] = true
			}
		}
		losing := map[string]bool{}
		var order []string
		for _, r := range rows {
			path, who := r.String("path"), r.String("principal")
			if path == root || strings.HasPrefix(path, root+"/") {
				stmts = append(stmts, Statement{
					SQL:    roleBindingDeleteSQL,
					Params: []interface{}{nowRFC3339(), c.NowTS(), r.String("id")},
				})
				if !losing[who] {
					losing[who] = true
					order = append(order, who)
				}
			}
		}
		for _, who := range order {
			if stable[who] {
				continue
			}
			// A local account is matched with its legacy role's group too
			// (group:<role>@local), so a binding that group holds outside
			// /projects/ keeps the account bound as it keeps the group's other
			// members: a later revoke of it returns them all to the legacy role
			// together.
			if groupStable, err := legacyGroupStable(ctx, c, who, stable); err != nil {
				return false, err
			} else if groupStable {
				continue
			}
			stmts = append(stmts, Statement{
				SQL:    roleBindingInsertSQL,
				Params: []interface{}{newSentinelID(), bindingSentinelPath, SentinelRole, who, 0, c.NowTS()},
			})
		}
	}
	// project_quotas has no deleted_at, so a quota is reset to unbounded (the
	// state of a new project) rather than tombstoned.
	q, err := GetProjectQuota(ctx, c, name)
	if err != nil {
		return false, err
	}
	// A birth over a tombstone of the name (this spelling's or another's) is a
	// new incarnation once project_incarnation_v1 has latched, or once a row
	// of the name carries one, written with the row in this transaction
	// (project_incarnation.go). Its quota is keyed by it, so the old one's
	// needs no reset: no incarnation ever reads it again.
	states, err := loadProjectStates(ctx, c)
	if err != nil {
		return false, err
	}
	canonName, _ := safename.CanonicalProjectName(name)
	incarnations := c.ProjectIncarnationOn() || states[canonName].carried()
	born := newProjectIncarnation(false)
	if q != nil && !incarnations {
		stmts = append(stmts, Statement{
			SQL:    projectQuotaUpsertSQL,
			Params: []interface{}{name, 0, 0, 0, 0, 0, 0, c.NowTS()},
		})
	}
	switch {
	case kind == lifecycleCreate && incarnations:
		stmts = append(stmts, Statement{
			SQL:    projectsInsertIncarnationSQL,
			Params: []interface{}{p.Name, p.Display, p.ParentName, nowRFC3339(), c.NowTS(), born},
		})
	case kind == lifecycleCreate:
		stmts = append(stmts, Statement{
			SQL: `INSERT INTO projects (name, display, parent_name, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)`,
			Params: []interface{}{p.Name, p.Display, p.ParentName, nowRFC3339(), c.NowTS()},
		})
	case kind == lifecycleRevive && incarnations:
		stmts = append(stmts, Statement{
			SQL:    projectsReviveIncarnationSQL,
			Params: []interface{}{nil, born, c.NowTS(), p.Name},
		})
	case kind == lifecycleRevive:
		stmts = append(stmts, Statement{
			SQL:    `UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`,
			Params: []interface{}{nil, c.NowTS(), p.Name},
		})
	case kind == lifecycleDelete:
		stmts = append(stmts, Statement{
			SQL:    `UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?`,
			Params: []interface{}{nowRFC3339(), c.NowTS(), p.Name},
		})
	}
	// The retirement was decided with these live spellings of the name; the
	// transaction must still see exactly them, or a sibling revived since would
	// have its fresh grants retired by a statement list that predates it.
	pinned := func(tx *sql.Tx) (bool, error) {
		ok, err := guard(tx)
		if err != nil || !ok {
			return ok, err
		}
		rows, err := tx.QueryContext(ctx, `SELECT name FROM projects WHERE name <> ? AND deleted_at IS NULL`, name)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		var now []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return false, err
			}
			if sameProjectPath(n, name) {
				now = append(now, n)
			}
		}
		if err := rows.Err(); err != nil {
			return false, err
		}
		sort.Strings(now)
		return slices.Equal(now, liveSpellings), nil
	}
	return c.ExecuteBatchGuarded(ctx, pinned, stmts)
}

// legacyGroupStable reports whether principal is a local account whose legacy
// role's group (group:<role>@local, which the auth engine matches it as)
// holds a binding outside /projects/. A directory account's groups are known
// only at its login, so it is never stable this way.
func legacyGroupStable(ctx context.Context, c *Client, principal string, stable map[string]bool) (bool, error) {
	user, ok := strings.CutPrefix(principal, "user:")
	if !ok {
		return false, nil
	}
	if local, isLocal := strings.CutSuffix(user, "@local"); isLocal {
		user = local
	} else if strings.Contains(user, "@") {
		return false, nil
	}
	rows, err := c.Query(ctx, `SELECT role FROM users WHERE username = ? AND deleted_at IS NULL`, user)
	if err != nil || len(rows) == 0 {
		return false, err
	}
	role := rows[0].String("role")
	return role != "" && stable["group:"+role+"@local"], nil
}

// liveSpellingsOf returns the sorted names, among the live rows read, that are
// another spelling of name.
func liveSpellingsOf(name string, rows []Row) []string {
	var out []string
	for _, r := range rows {
		if n := r.String("name"); sameProjectPath(n, name) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// projectSpellingsReadHook, when set (tests only), runs after a lifecycle has
// read which other spellings of the name are live and before it reads the
// bindings it will retire.
var projectSpellingsReadHook func()

func newSentinelID() string {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		panic("rand.Read: " + err.Error())
	}
	return hex.EncodeToString(buf)
}

// GetProject returns the project by name (canonical path) or nil if
// absent. Treats _default as always existing — never returns nil for it.
func GetProject(ctx context.Context, c *Client, name string) (*ProjectRecord, error) {
	if name == DefaultProject {
		return &ProjectRecord{Name: DefaultProject, Display: "default"}, nil
	}
	rows, err := c.Query(ctx,
		`SELECT name, display, parent_name, created_at, updated_at, incarnation
		 FROM projects WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &ProjectRecord{
		Name:        r.String("name"),
		Display:     r.String("display"),
		ParentName:  r.String("parent_name"),
		CreatedAt:   r.String("created_at"),
		UpdatedAt:   r.String("updated_at"),
		Incarnation: r.String("incarnation"),
	}, nil
}

// ListProjects returns every non-deleted project. _default is
// surfaced as the first entry even when no row exists for it.
func ListProjects(ctx context.Context, c *Client) ([]ProjectRecord, error) {
	rows, err := c.Query(ctx,
		`SELECT name, display, parent_name, created_at, updated_at, incarnation
		 FROM projects WHERE deleted_at IS NULL
		 ORDER BY name`)
	if err != nil {
		return nil, err
	}
	out := []ProjectRecord{{Name: DefaultProject, Display: "default"}}
	for _, r := range rows {
		out = append(out, ProjectRecord{
			Name:        r.String("name"),
			Display:     r.String("display"),
			ParentName:  r.String("parent_name"),
			CreatedAt:   r.String("created_at"),
			UpdatedAt:   r.String("updated_at"),
			Incarnation: r.String("incarnation"),
		})
	}
	return out, nil
}

// DeleteProject soft-deletes a project. Refuses if any VM still
// carries the project label — admission would let resources leak
// otherwise. Children must be deleted first.
func DeleteProject(ctx context.Context, c *Client, name string) error {
	if name == DefaultProject {
		return fmt.Errorf("cannot delete the default project")
	}
	// Deleting a name with no live project has no business revoking anything: it
	// would retire pre-grants for a project not yet created and bump the clock of
	// an already-deleted row.
	liveRow, err := c.Query(ctx, `SELECT updated_at FROM projects WHERE name = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return err
	}
	if len(liveRow) == 0 {
		return fmt.Errorf("project %q not found", name)
	}
	// Refuse if children exist.
	children, err := c.Query(ctx,
		`SELECT 1 FROM projects WHERE parent_name = ? AND deleted_at IS NULL LIMIT 1`, name)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return fmt.Errorf("project %q has children; delete them first", name)
	}
	// Refuse if VMs still carry the label.
	vmRows, err := c.Query(ctx,
		`SELECT 1 FROM vms WHERE project = ? AND deleted_at IS NULL LIMIT 1`, name)
	if err != nil {
		return err
	}
	if len(vmRows) > 0 {
		return fmt.Errorf("project %q still owns VMs; reassign or delete them first", name)
	}
	// Refuse if containers still carry the project — deleting the project would
	// orphan their project association (quota accounting + RBAC paths). Mirrors
	// the VM guard above; added when containers gained a project column (v25).
	ctRows, err := c.Query(ctx,
		`SELECT 1 FROM containers WHERE project = ? AND deleted_at IS NULL LIMIT 1`, name)
	if err != nil {
		return err
	}
	if len(ctRows) > 0 {
		return fmt.Errorf("project %q still owns containers; reassign or delete them first", name)
	}
	// Refuse if security groups still belong to it: a later project of the
	// same name would otherwise inherit them and their rules.
	sgRows, err := c.Query(ctx,
		`SELECT 1 FROM security_groups WHERE project = ? AND deleted_at IS NULL LIMIT 1`, name)
	if err != nil {
		return err
	}
	if len(sgRows) > 0 {
		return fmt.Errorf("project %q still owns security groups; delete them first (lv sg ls --project %s)", name, name)
	}
	// Refuse if networks, storage pools, backup schedules or notification routes
	// still belong to it: a later project of the same name would inherit them.
	if err := refuseOwnedResources(ctx, c, name); err != nil {
		return err
	}
	// The grants go with the tombstone, in ONE guarded transaction that requires
	// the row we validated above (same updated_at) to still be live: a delete that
	// lost a race retires nothing, and a crash cannot leave a gone project holding
	// live authority or a live one without it.
	if h := projectLifecycleInterleaveHook; h != nil {
		h()
	}
	applied, err := commitProjectLifecycle(ctx, c, lifecycleDelete, ProjectRecord{Name: name}, projectLiveRowGuard(ctx, name, liveRow[0].String("updated_at")))
	if err != nil {
		return fmt.Errorf("retire project grants: %w", err)
	}
	if !applied {
		return fmt.Errorf("project %q was changed concurrently; retry", name)
	}
	return nil
}

// UpsertProjectQuota writes a quota row for the project. Zero in
// any field means "unbounded" — that's the default state for
// new projects.
func UpsertProjectQuota(ctx context.Context, c *Client, q ProjectQuotaRecord) error {
	if q.ProjectName == "" {
		return fmt.Errorf("project_name required")
	}
	// Bound to the incarnation of a live project (project_incarnation.go).
	return upsertProjectQuota(ctx, c, q, c.NowTS())
}

const projectQuotaUpsertSQL = `INSERT INTO project_quotas
		   (project_name, vcpu_limit, mem_mib_limit, disk_gib_limit,
		    nic_limit, public_ip_limit, backup_gib_limit, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(project_name) DO UPDATE SET
		   vcpu_limit       = excluded.vcpu_limit,
		   mem_mib_limit    = excluded.mem_mib_limit,
		   disk_gib_limit   = excluded.disk_gib_limit,
		   nic_limit        = excluded.nic_limit,
		   public_ip_limit  = excluded.public_ip_limit,
		   backup_gib_limit = excluded.backup_gib_limit,
		   updated_at       = excluded.updated_at`

// GetProjectQuota returns the quota row or nil if unset. The default
// project has no quotas (every limit = 0 = unbounded) — returns nil. A live
// project reads the quota of the incarnation it holds (projectQuotaKey), so
// a re-created project starts with none, as a new project does, and never
// reads the old one's (project_incarnation.go).
func GetProjectQuota(ctx context.Context, c *Client, name string) (*ProjectQuotaRecord, error) {
	inc, _, err := projectQuotaIncarnation(ctx, c, name)
	if err != nil {
		return nil, err
	}
	rows, err := c.Query(ctx,
		`SELECT project_name, vcpu_limit, mem_mib_limit, disk_gib_limit,
		        nic_limit, public_ip_limit, backup_gib_limit
		 FROM project_quotas WHERE project_name = ?`, projectQuotaKey(name, inc))
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}
	r := rows[0]
	return &ProjectQuotaRecord{
		ProjectName:    name,
		VCPULimit:      r.Int("vcpu_limit"),
		MemMiBLimit:    r.Int("mem_mib_limit"),
		DiskGiBLimit:   r.Int("disk_gib_limit"),
		NICLimit:       r.Int("nic_limit"),
		PublicIPLimit:  r.Int("public_ip_limit"),
		BackupGiBLimit: r.Int("backup_gib_limit"),
	}, nil
}

// ProjectUsage is the live resource consumption of one project,
// computed by summing the VMs that carry the project label.
type ProjectUsage struct {
	ProjectName   string
	VCPUUsed      int
	MemMiBUsed    int
	DiskGiBUsed   int
	NICUsed       int
	VMCount       int
	PublicIPsUsed int // interfaces whose address is non-private (routable)
	BackupGiBUsed int // summed backup size across the project's VMs
}

// SumProjectUsage returns the current usage by walking vms +
// vm_disks + vm_interfaces. Cheap on small clusters; the admission
// path calls this on every CreateVM to gate against the quota.
func SumProjectUsage(ctx context.Context, c *Client, name string) (*ProjectUsage, error) {
	u := &ProjectUsage{ProjectName: name}

	// VM count + summed spec CPU/RAM via JSON extraction. We persist
	// VMSpec as a JSON blob in vms.spec — sqlite json_extract is
	// the cheapest path.
	rows, err := c.Query(ctx,
		`SELECT
		   COUNT(*)                                    AS vm_count,
		   COALESCE(SUM(json_extract(spec,'$.cpu')),0)        AS cpu,
		   COALESCE(SUM(json_extract(spec,'$.memory_mib')),0) AS mem
		 FROM vms WHERE project = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		u.VMCount = rows[0].Int("vm_count")
		u.VCPUUsed = rows[0].Int("cpu")
		u.MemMiBUsed = rows[0].Int("mem")
	}

	// Containers share the project's vCPU/Mem budget (one joint tenant limit).
	// They carry plain cpu_limit/memory_mib columns; an allocation counts whether
	// running or stopped (matching VMs). A container created with no explicit
	// --cpu/--memory (limit 0 = unbounded) contributes 0 to that dimension —
	// only declared limits are quota-accounted.
	ctRows, err := c.Query(ctx,
		`SELECT COALESCE(SUM(cpu_limit),0)  AS cpu,
		        COALESCE(SUM(memory_mib),0) AS mem
		 FROM containers WHERE project = ? AND deleted_at IS NULL`, name)
	if err != nil {
		return nil, err
	}
	if len(ctRows) > 0 {
		u.VCPUUsed += ctRows[0].Int("cpu")
		u.MemMiBUsed += ctRows[0].Int("mem")
	}

	diskRows, err := c.Query(ctx,
		`SELECT `+quotaDiskGiBSum("vm_disks.size_bytes")+` AS gib
		 FROM vm_disks
		 JOIN vms ON vm_disks.vm_name = vms.name
		 WHERE vms.project = ? AND vms.deleted_at IS NULL AND vm_disks.deleted_at IS NULL`,
		name)
	if err == nil && len(diskRows) > 0 {
		u.DiskGiBUsed = diskRows[0].Int("gib")
	}

	// NIC count + public-IP count from the same interface set. Public-IP
	// classification matches the admission path: any parseable, non-private
	// address counts (net.IP.IsPrivate covers RFC1918 + ULA).
	ipRows, err := c.Query(ctx,
		`SELECT vm_interfaces.ip AS ip
		 FROM vm_interfaces
		 JOIN vms ON vm_interfaces.vm_name = vms.name
		 WHERE vms.project = ? AND vms.deleted_at IS NULL AND vm_interfaces.deleted_at IS NULL`,
		name)
	if err == nil {
		u.NICUsed = len(ipRows)
		for _, r := range ipRows {
			if ip := net.ParseIP(r.String("ip")); ip != nil && !ip.IsPrivate() {
				u.PublicIPsUsed++
			}
		}
	}
	// Container NICs count toward the same NIC / public-IP budget (v35: containers
	// are now first-class network citizens via container_interfaces).
	ctIPRows, err := c.Query(ctx,
		`SELECT container_interfaces.ip AS ip
		 FROM container_interfaces
		 JOIN containers ON container_interfaces.host_name = containers.host_name
		                AND container_interfaces.ct_name = containers.name
		 WHERE containers.project = ? AND containers.deleted_at IS NULL AND container_interfaces.deleted_at IS NULL`,
		name)
	if err == nil {
		u.NICUsed += len(ctIPRows)
		for _, r := range ctIPRows {
			if ip := net.ParseIP(r.String("ip")); ip != nil && !ip.IsPrivate() {
				u.PublicIPsUsed++
			}
		}
	}

	// Backup footprint: VMs and containers draw down the SAME backup_gib budget.
	// Sum the latest backup size per (vm, disk, repo) from vm_backups and per
	// (container, repo) from container_backups (both populated on each push;
	// manifests themselves live on-disk in pbsstore repos, not in Corrosion).
	var backupBytes int64
	bkRows, err := c.Query(ctx,
		`SELECT COALESCE(SUM(vm_backups.total_bytes), 0) AS bytes
		 FROM vm_backups
		 JOIN vms ON vm_backups.vm_name = vms.name
		 WHERE vms.project = ? AND vms.deleted_at IS NULL`,
		name)
	if err == nil && len(bkRows) > 0 {
		backupBytes += bkRows[0].Int64("bytes")
	}
	if ctBytes, err := containerBackupUsage(ctx, c, name); err == nil {
		backupBytes += ctBytes
	}
	u.BackupGiBUsed = int(backupBytes / (1 << 30))

	return u, nil
}

// UpsertVMBackup records the latest backup size for one (vm, disk, repo) into
// the vm_backups index, so the tenancy backup_gib quota can be summed cheaply
// (backup manifests live on-disk in pbsstore repos, not in Corrosion). Called
// after a successful backup push; total_bytes is the manifest's logical size.
// Replicated via the mutation log like other writes, so the footprint is
// visible cluster-wide for project-quota admission on any host.
func UpsertVMBackup(ctx context.Context, c *Client, vmName, diskName, repo string, totalBytes int64) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO vm_backups (vm_name, disk_name, repo, total_bytes, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(vm_name, disk_name, repo) DO UPDATE SET
		   total_bytes = excluded.total_bytes,
		   updated_at  = excluded.updated_at`,
		vmName, diskName, repo, totalBytes, now)
}

// UpsertContainerBackup records the latest backup size for one (container,
// repo) into the container_backups index — the container analogue of
// UpsertVMBackup, so the tenancy backup_gib quota sums container footprints
// alongside VMs.
//
// The row is keyed by the PROJECT-QUALIFIED name (ContainerBackupKey), the
// project being the one the backup's manifest records for its container.
// Container names are per host and per project, so a key of the bare name was
// shared by every same-named container: another project's backups were
// charged to this project (and could block its creates), and inspect showed
// them.
func UpsertContainerBackup(ctx context.Context, c *Client, project, ctName, repo string, totalBytes int64) error {
	now := c.NowTS()
	return c.Execute(ctx,
		`INSERT INTO container_backups (ct_name, repo, total_bytes, updated_at)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(ct_name, repo) DO UPDATE SET
		   total_bytes = excluded.total_bytes,
		   updated_at  = excluded.updated_at`,
		ContainerBackupKey(project, ctName), repo, totalBytes, now)
}

// containerBackupKeySep separates project and name in a container_backups
// key. A unit separator: it appears in neither a project nor a container name.
const containerBackupKeySep = "\x1f"

// ContainerBackupKey is the container_backups key of (project, name).
func ContainerBackupKey(project, name string) string {
	return normalizeProject(project) + containerBackupKeySep + name
}

// containerBackupUsage sums the container backup footprint charged to
// project: its own project-keyed rows (ContainerBackupKey) for containers it
// still has.
func containerBackupUsage(ctx context.Context, c *Client, project string) (int64, error) {
	rows, err := c.Query(ctx,
		`SELECT COALESCE(SUM(total_bytes), 0) AS bytes FROM container_backups
		 WHERE ct_name IN (SELECT ? || name FROM containers WHERE project = ? AND deleted_at IS NULL)`,
		normalizeProject(project)+containerBackupKeySep, project)
	if err != nil || len(rows) == 0 {
		return 0, err
	}
	return rows[0].Int64("bytes"), nil
}

// QuotaCheck describes a proposed resource request. The admission
// path builds one from a CreateVM call and passes it to
// CheckProjectQuota; if any dimension would push the project over
// its quota, the call is rejected.
type QuotaCheck struct {
	VCPU    int
	MemMiB  int
	DiskGiB int
	NIC     int
}

// bytesPerGiB is the quota accounting unit for disk.
const bytesPerGiB = 1 << 30

// DiskQuotaGiB is THE bytes→GiB rule for project disk quota: each disk rounds
// UP, so a partial GiB occupies a whole one.
//
// Every site that measures disk against the quota must use it — admission, the
// committed-usage sum, and the per-workload contribution the settle rule reads.
// They diverged once: admission rounded up while usage truncated the summed
// bytes, so a 512 MiB disk was charged 1 GiB and counted 0. The charge could
// never be observed as paid, so its lease rode out the whole settle grace and
// then freed a GiB that committed usage had never picked up — double-counted
// first, uncounted after.
func DiskQuotaGiB(sizeBytes int64) int {
	if sizeBytes <= 0 {
		return 0
	}
	// Divide first, then carry the remainder: adding bytesPerGiB-1 up front
	// overflows int64 for a size near the maximum.
	gib := sizeBytes / bytesPerGiB
	if sizeBytes%bytesPerGiB != 0 {
		gib++
	}
	return int(gib)
}

// quotaDiskGiBSum is DiskQuotaGiB as a SQL aggregate over col — the round-up
// applies PER ROW, then sums, so it matches DiskQuotaGiB applied per disk.
// Rounding after the sum would be a different (and smaller) number.
func quotaDiskGiBSum(col string) string {
	return "COALESCE(SUM((" + col + " + " + strconv.Itoa(bytesPerGiB-1) + ") / " + strconv.Itoa(bytesPerGiB) + "), 0)"
}

// QuotaAmount is an amount of project quota in EVERY dimension a project quota
// bounds. It is the shape the serialized admission path passes around: a
// requested delta, a summed reservation total, and one workload's contribution
// are all the same four numbers, so admission compares like with like.
//
// Carrying all four together is the point. Reserving only cpu/mem while
// checking disk/NIC with an unserialized read left those two dimensions
// enforceable one request at a time: two concurrent creates each read a view
// containing neither, both fit, and both committed.
type QuotaAmount struct {
	VCPU    int
	MemMiB  int
	DiskGiB int
	NIC     int
}

// IsZero reports whether the amount asks for nothing in any dimension — the
// admission fast path (nothing to reserve, nothing to check).
func (a QuotaAmount) IsZero() bool {
	return a.VCPU <= 0 && a.MemMiB <= 0 && a.DiskGiB <= 0 && a.NIC <= 0
}

// Add returns the dimension-wise sum.
func (a QuotaAmount) Add(b QuotaAmount) QuotaAmount {
	return QuotaAmount{
		VCPU:    a.VCPU + b.VCPU,
		MemMiB:  a.MemMiB + b.MemMiB,
		DiskGiB: a.DiskGiB + b.DiskGiB,
		NIC:     a.NIC + b.NIC,
	}
}

// CheckProjectQuota returns nil if the proposed allocation would fit
// under the project's quotas, or a descriptive error otherwise.
// Empty/missing quota row means unbounded — admission passes.
func CheckProjectQuota(ctx context.Context, c *Client, projectName string, req QuotaCheck) error {
	q, err := GetProjectQuota(ctx, c, projectName)
	if err != nil {
		return fmt.Errorf("get quota: %w", err)
	}
	if q == nil {
		return nil // unbounded
	}
	u, err := SumProjectUsage(ctx, c, projectName)
	if err != nil {
		return fmt.Errorf("get usage: %w", err)
	}
	var violations []string
	if q.VCPULimit > 0 && u.VCPUUsed+req.VCPU > q.VCPULimit {
		violations = append(violations,
			fmt.Sprintf("vcpu (used %d + new %d > limit %d)",
				u.VCPUUsed, req.VCPU, q.VCPULimit))
	}
	if q.MemMiBLimit > 0 && u.MemMiBUsed+req.MemMiB > q.MemMiBLimit {
		violations = append(violations,
			fmt.Sprintf("mem_mib (used %d + new %d > limit %d)",
				u.MemMiBUsed, req.MemMiB, q.MemMiBLimit))
	}
	if q.DiskGiBLimit > 0 && u.DiskGiBUsed+req.DiskGiB > q.DiskGiBLimit {
		violations = append(violations,
			fmt.Sprintf("disk_gib (used %d + new %d > limit %d)",
				u.DiskGiBUsed, req.DiskGiB, q.DiskGiBLimit))
	}
	if q.NICLimit > 0 && u.NICUsed+req.NIC > q.NICLimit {
		violations = append(violations,
			fmt.Sprintf("nic (used %d + new %d > limit %d)",
				u.NICUsed, req.NIC, q.NICLimit))
	}
	if len(violations) > 0 {
		return fmt.Errorf("project %q quota exceeded: %s",
			projectName, strings.Join(violations, "; "))
	}
	return nil
}

// Workload kinds for quota observation. A name alone is NOT a unique identity: a VM
// and a container may share a name, and container names are unique only per HOST.
// Retiring a charge on the wrong row would free quota that is still owed.
const (
	WorkloadVM        = "vm"
	WorkloadContainer = "container"
)

// WorkloadQuotaContribution reports what one specific workload contributes to a
// project's quota usage on THIS node's replica, and whether its row is visible here.
//
// This is the observation primitive the settle rule needs: a lease held for a
// committed-but-unreplicated workload may only be retired by seeing THAT workload,
// at (or above) the size it was admitted for. Aggregate usage growth is not a sound
// substitute — any unrelated increase (a workload that replicated late, or one
// admitted through a fail-open path) would clear the charge early and let the next
// request over-admit.
//
// Identity is (kind, host, name), not name alone. kind separates a VM from a
// same-named container; host disambiguates containers, whose names are unique only
// per host, so a container of the same name elsewhere cannot retire this charge.
//
// The accounting mirrors SumProjectUsage exactly, so "contributes at least what it
// was admitted for" is comparable against the same numbers the quota check uses: VMs
// count their spec cpu/memory_mib plus their disk and interface rows, containers
// their declared limits plus their interface rows (containers contribute no disk
// quota), and a soft-deleted row — of the workload or of an individual disk/NIC —
// counts as absent.
func WorkloadQuotaContribution(ctx context.Context, c *Client, project, kind, host, workload string) (QuotaAmount, bool, error) {
	project = projectOrDefault(project)
	switch kind {
	case WorkloadContainer:
		rows, err := c.Query(ctx,
			`SELECT COALESCE(cpu_limit,0)  AS cpu,
			        COALESCE(memory_mib,0) AS mem
			 FROM containers
			 WHERE name = ? AND host_name = ? AND project = ? AND deleted_at IS NULL`,
			workload, host, project)
		if err != nil {
			return QuotaAmount{}, false, err
		}
		if len(rows) == 0 {
			return QuotaAmount{}, false, nil
		}
		amt := QuotaAmount{VCPU: rows[0].Int("cpu"), MemMiB: rows[0].Int("mem")}
		nicRows, err := c.Query(ctx,
			`SELECT COUNT(*) AS n FROM container_interfaces
			 WHERE ct_name = ? AND host_name = ? AND deleted_at IS NULL`, workload, host)
		if err != nil {
			return QuotaAmount{}, false, err
		}
		if len(nicRows) > 0 {
			amt.NIC = nicRows[0].Int("n")
		}
		return amt, true, nil
	default: // WorkloadVM
		rows, err := c.Query(ctx,
			`SELECT COALESCE(json_extract(spec,'$.cpu'),0)        AS cpu,
			        COALESCE(json_extract(spec,'$.memory_mib'),0) AS mem
			 FROM vms WHERE name = ? AND project = ? AND deleted_at IS NULL`, workload, project)
		if err != nil {
			return QuotaAmount{}, false, err
		}
		if len(rows) == 0 {
			return QuotaAmount{}, false, nil
		}
		amt := QuotaAmount{VCPU: rows[0].Int("cpu"), MemMiB: rows[0].Int("mem")}
		diskRows, err := c.Query(ctx,
			`SELECT `+quotaDiskGiBSum("size_bytes")+` AS gib FROM vm_disks
			 WHERE vm_name = ? AND deleted_at IS NULL`, workload)
		if err != nil {
			return QuotaAmount{}, false, err
		}
		if len(diskRows) > 0 {
			// Measured by the SAME rule as the usage this contribution is compared
			// against — a contribution counted differently from the charge could
			// never be observed as paid, so the lease would ride out its whole
			// grace and then free a charge usage had never picked up.
			amt.DiskGiB = diskRows[0].Int("gib")
		}
		nicRows, err := c.Query(ctx,
			`SELECT COUNT(*) AS n FROM vm_interfaces
			 WHERE vm_name = ? AND deleted_at IS NULL`, workload)
		if err != nil {
			return QuotaAmount{}, false, err
		}
		if len(nicRows) > 0 {
			amt.NIC = nicRows[0].Int("n")
		}
		return amt, true, nil
	}
}
