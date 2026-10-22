package auth

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/litevirt/litevirt/internal/auth/policy"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Path canonicalization. Paths in litevirt RBAC look like:
//
//	/                              cluster root
//	/hosts                         all hosts
//	/hosts/host-a                  one host
//	/projects/acme                 a project
//	/projects/acme/vms/web-1       a single VM
//	/storage/main                  a storage pool
//	/sdn/zones/prod                an SDN zone
//
// Trailing slashes are stripped; case is preserved (Linux conventions).
// Empty string and "/" both refer to the cluster root.
func canonicalPath(p string) string {
	return policy.CanonicalPath(p)
}

// pathPrefixOf reports whether `prefix` is an ancestor of (or equal to)
// `path`. Used by propagation: a binding on /projects/acme with
// propagate=true applies to /projects/acme/vms/web-1.
//
// "/foo/bar" is a prefix of "/foo/bar/baz" but NOT of "/foo/barred".
func pathPrefixOf(prefix, path string) bool {
	return policy.PathPrefixOf(prefix, path)
}

// verbMatches reports whether a role's grant matches the requested verb.
// Granted verbs may be exact ("vm.start") or wildcarded:
//
//	"*"          — every verb
//	"vm.*"       — every verb in the vm namespace (vm.start, vm.read, …)
//	"*.read"     — read on every namespace (vm.read, lb.read, …)
//	"vm.start"   — only vm.start
//
// We explicitly do NOT support arbitrary glob (e.g. "v*.read") to keep the
// matcher fast and the security review surface small.
func verbMatches(grants []string, verb string) bool {
	return policy.VerbMatches(grants, verb)
}

// VerbPermModify is the delegated-administration verb (Proxmox:
// Permissions.Modify). A principal holding it at a path may grant and revoke
// role bindings at that path and below — never a role carrying a verb it does
// not itself hold there. GrantRole / RevokeRole enforce the rest
// (internal/grpcapi/role_delegation.go).
const VerbPermModify = "perm.modify"

// VerbContainerRoot is exec, and a compose image change, in a container that
// runs as root on the host or with legacy confinement: a privileged one (no
// user namespace) or a legacy-confined one. It is outside the ct namespace
// so that ct.* (Operator) does not carry it, and no "*.exec" grant carries
// it (suffixWildcardExempt); Admin holds it through "*", and the
// ContainerRoot role grants it per container.
const VerbContainerRoot = "ctroot.exec"

// VerbFirewallLogView reads the firewall log (lv firewall log). A record
// names any tenant's addresses and ports, so the verb is outside every
// namespace a built-in role grants: "*.read" does not match it (Viewer,
// Auditor), nor does "sg.*" (NetworkAdmin). Among the built-in roles only
// Admin ("*") holds it; an admin grants it to others through a custom role.
const VerbFirewallLogView = "firewall.log.view"

// GrantCovers reports whether holding grant `held` covers grant `requested`:
// every verb `requested` matches (verbMatches) is matched by `held` too. It
// is the no-escalation test of a delegated grant, so it errs towards "no": a
// pair it cannot prove is a subset is not one.
//
//	held "*"        covers everything
//	held == requested
//	held "ns.*"     covers any requested grant under "ns." ("ns.x", "ns.*", "ns.x.*")
//	held "*.sfx"    covers any requested grant ending ".sfx" ("vm.sfx", "*.x.sfx")
//
// "*" requested is covered only by "*".
func GrantCovers(held, requested string) bool {
	if held == "*" || held == requested {
		return true
	}
	if requested == "*" {
		return false
	}
	if strings.HasSuffix(held, ".*") && !strings.HasPrefix(held, "*") {
		return strings.HasPrefix(requested, held[:len(held)-1]) // "ns.*" -> "ns."
	}
	if strings.HasPrefix(held, "*.") && !strings.HasSuffix(held, ".*") {
		return strings.HasSuffix(requested, held[1:]) && !suffixWildcardExempt(requested) // "*.read" -> ".read"
	}
	return false
}

// suffixWildcardExempt reports whether verb is outside every "*.<verb>"
// grant: VerbContainerRoot's namespace. A role written as "*.exec" for
// vm.exec and ct.exec must not become a root shell on the host in every
// privileged container; ctroot.* is granted by name, "ctroot.*" or "*".
func suffixWildcardExempt(verb string) bool {
	return strings.HasPrefix(verb, "ctroot.")
}

// UncoveredGrants returns every grant in requested that no grant in held
// covers (GrantCovers). Empty means requested is no more than held.
func UncoveredGrants(held, requested []string) []string {
	var out []string
	for _, r := range requested {
		covered := false
		for _, h := range held {
			if GrantCovers(h, r) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, r)
		}
	}
	return out
}

// engineSnapshot is the atomic unit of Engine state. We swap the entire
// snapshot on Reload so readers never see a torn (half-updated) view of
// roleVerbs vs bindings.
type engineSnapshot struct {
	roleVerbs map[string][]string
	bindings  []corrosion.RoleBindingRecord
}

// Engine resolves "may principal P perform verb V on path R?". One per
// daemon. Keeps an in-memory snapshot of role definitions + bindings,
// refreshed on every Reload() (called whenever role/binding tables mutate).
//
// The snapshot is held in an atomic.Pointer so concurrent reads (every
// authenticated RPC consults Allowed/HasAnyBinding) never need to lock,
// and Reload's swap is atomic.
type Engine struct {
	db *corrosion.Client
	// mu serializes every snapshot PRODUCER (Reload + the RemoveBinding/
	// RemovePrincipal deltas). Held across the DB read AND the Store so a
	// reload that read stale state can never publish after — and thus
	// resurrect — a newer delta. Readers (Allowed/HasAnyBinding) stay
	// lock-free via the atomic snapshot pointer.
	mu   sync.Mutex
	snap atomic.Pointer[engineSnapshot]
	// lastReload is the unix time of the last SUCCESSFUL reload; retained
	// (never reset) across failed reloads so operators can alert on a
	// stalled reload service.
	lastReload atomic.Int64
}

// NewEngine returns an engine reading from db. Caller must call Reload()
// after registering built-in roles.
func NewEngine(db *corrosion.Client) *Engine {
	e := &Engine{db: db}
	e.snap.Store(&engineSnapshot{roleVerbs: map[string][]string{}})
	return e
}

// Reload re-reads the roles and role_bindings tables. Cheap (ms on
// thousand-binding clusters) so it's safe to call after every mutation
// and on the periodic backstop. On error the prior snapshot is retained
// (we only Store on success), so a transient DB failure degrades to
// staleness, never to an empty policy.
func (e *Engine) Reload(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	roles, err := corrosion.ListRoles(ctx, e.db)
	if err != nil {
		return err
	}
	rv := make(map[string][]string, len(roles))
	for _, r := range roles {
		rv[r.Name] = r.Verbs
	}
	bindings, err := corrosion.ListRoleBindings(ctx, e.db)
	if err != nil {
		return err
	}
	for i := range bindings {
		// A binding granted for an earlier project of the name grants
		// nothing, and still keeps its principal bound, as a NoAccess binding
		// does (corrosion/project_incarnation.go).
		if bindings[i].Held {
			bindings[i].Role = corrosion.SentinelRole
		}
	}
	e.snap.Store(&engineSnapshot{roleVerbs: rv, bindings: bindings})
	e.lastReload.Store(time.Now().Unix())
	return nil
}

// RemoveBinding drops the binding with the given id from the live snapshot,
// in memory, without touching the database. RevokeRole uses this so a revoke
// takes effect IMMEDIATELY — even if a subsequent DB reload fails — while the
// caller's DB tombstone makes it durable and keeps a later reload from
// resurrecting it. Bindings other than the named one are preserved, so a
// principal keeps whatever perms their remaining bindings supply.
func (e *Engine) RemoveBinding(id string) {
	e.removeWhere(func(b corrosion.RoleBindingRecord) bool { return b.ID != id })
}

// ReplaceBinding drops the binding with id and adds repl, in one snapshot
// swap, so no reader sees the principal with neither. A delegated revoke uses
// it for the NoAccess sentinel it leaves.
func (e *Engine) ReplaceBinding(id string, repl corrosion.RoleBindingRecord) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cur := e.snap.Load()
	if cur == nil {
		return
	}
	kept := make([]corrosion.RoleBindingRecord, 0, len(cur.bindings)+1)
	for _, b := range cur.bindings {
		if b.ID != id {
			kept = append(kept, b)
		}
	}
	kept = append(kept, repl)
	e.snap.Store(&engineSnapshot{roleVerbs: cur.roleVerbs, bindings: kept})
}

// RemovePrincipal drops every binding for the given principal from the live
// snapshot, in memory. DeleteUser uses this (once per resolvable principal
// form) so a deleted user loses access immediately.
func (e *Engine) RemovePrincipal(principal string) {
	e.removeWhere(func(b corrosion.RoleBindingRecord) bool { return b.Principal != principal })
}

// removeWhere rebuilds the snapshot keeping only bindings for which keep()
// returns true. Held under the same mutex as Reload, so an in-flight reload
// that read pre-mutation state cannot store after — and clobber — this delta.
func (e *Engine) removeWhere(keep func(corrosion.RoleBindingRecord) bool) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	cur := e.snap.Load()
	if cur == nil {
		return
	}
	kept := make([]corrosion.RoleBindingRecord, 0, len(cur.bindings))
	changed := false
	for _, b := range cur.bindings {
		if keep(b) {
			kept = append(kept, b)
			continue
		}
		changed = true
	}
	if !changed {
		return
	}
	// roleVerbs is immutable once built, so sharing it with the new
	// snapshot is safe.
	e.snap.Store(&engineSnapshot{roleVerbs: cur.roleVerbs, bindings: kept})
}

// LastReloadUnix returns the unix time of the last successful reload (0 if the
// engine has never reloaded). Exposed for a "last successful reload" metric so
// a stalled reload service is observable.
func (e *Engine) LastReloadUnix() int64 {
	if e == nil {
		return 0
	}
	return e.lastReload.Load()
}

// Allowed reports whether a principal (and their groups) hold a binding
// that grants `verb` at `path`. Bindings with `propagate=true` apply to
// the path and all descendants; bindings with `propagate=false` apply
// only to the exact path.
//
// principalIDs should include the user-principal AND any group-principals
// (e.g. ["user:alice@local", "group:admins@local"]).
//
// Cluster-root bindings (path = "/") with propagate=true grant on every
// path — this is how the built-in Admin role works (one root binding
// gives full access).
func (e *Engine) Allowed(principalIDs []string, verb, path string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	path = canonicalPath(path)
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if !pSet[b.Principal] {
			continue
		}
		bp := canonicalPath(b.Path)
		if b.Propagate {
			if !pathPrefixOf(bp, path) {
				continue
			}
		} else {
			if bp != path {
				continue
			}
		}
		grants := snap.roleVerbs[b.Role]
		if len(grants) == 0 {
			continue
		}
		if verbMatches(grants, verb) {
			return true
		}
	}
	return false
}

// RoleVerbs returns a role's grants as the live snapshot holds them, and
// whether the role exists there.
func (e *Engine) RoleVerbs(role string) ([]string, bool) {
	if e == nil {
		return nil, false
	}
	snap := e.snap.Load()
	if snap == nil {
		return nil, false
	}
	v, ok := snap.roleVerbs[role]
	return append([]string(nil), v...), ok
}

// GrantsAt returns the union of the grants principalIDs hold at path. With
// mustPropagate it counts only bindings that also apply to every DESCENDANT
// of path — a propagating binding at path or an ancestor — because a
// propagating grant made at path reaches all of them, and a holder whose own
// binding stops at path holds nothing below it.
func (e *Engine) GrantsAt(principalIDs []string, path string, mustPropagate bool) []string {
	if e == nil {
		return nil
	}
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	path = canonicalPath(path)
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	var out []string
	for _, b := range snap.bindings {
		if !pSet[b.Principal] {
			continue
		}
		bp := canonicalPath(b.Path)
		switch {
		case b.Propagate && pathPrefixOf(bp, path):
		case !b.Propagate && !mustPropagate && bp == path:
		default:
			continue
		}
		out = append(out, snap.roleVerbs[b.Role]...)
	}
	return out
}

// BindingsOf returns the bindings the live snapshot holds for any of
// principalIDs, for audit: which binding a principal set holds.
func (e *Engine) BindingsOf(principalIDs []string) []corrosion.RoleBindingRecord {
	if e == nil {
		return nil
	}
	snap := e.snap.Load()
	if snap == nil {
		return nil
	}
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	var out []corrosion.RoleBindingRecord
	for _, b := range snap.bindings {
		if pSet[b.Principal] {
			out = append(out, b)
		}
	}
	return out
}

// HasAnyBindingExcept is HasAnyBinding ignoring the binding with id exceptID:
// whether principalIDs would still hold a binding once that one is revoked.
func (e *Engine) HasAnyBindingExcept(principalIDs []string, exceptID string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if b.ID != exceptID && pSet[b.Principal] {
			return true
		}
	}
	return false
}

// explicitGrantMatches is verbMatches without the broad wildcards: a grant
// matches verb only when it names it, or names its namespace ("perm.*"). "*",
// "*.<suffix>" and wildcards spanning namespaces do not. Delegation is checked
// this way (t1-auth-review I7): an Admin ("*") binding that predates
// delegation meant "full control of these resources", and must not become
// "may also hand out any role here" on upgrade.
func explicitGrantMatches(grants []string, verb string) bool {
	for _, g := range grants {
		if g == verb {
			return true
		}
		if strings.HasSuffix(g, ".*") && len(g) > 2 && !strings.Contains(g[:len(g)-2], "*") &&
			strings.HasPrefix(verb, g[:len(g)-1]) {
			return true
		}
	}
	return false
}

// AllowedExplicit is Allowed with explicitGrantMatches: the verb must be
// granted by name (or namespace) at path, not through "*".
func (e *Engine) AllowedExplicit(principalIDs []string, verb, path string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	path = canonicalPath(path)
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if !pSet[b.Principal] {
			continue
		}
		bp := canonicalPath(b.Path)
		if b.Propagate {
			if !pathPrefixOf(bp, path) {
				continue
			}
		} else if bp != path {
			continue
		}
		if explicitGrantMatches(snap.roleVerbs[b.Role], verb) {
			return true
		}
	}
	return false
}

// HoldsVerbExplicitlyAnywhere is HoldsVerbAnywhere with explicitGrantMatches.
func (e *Engine) HoldsVerbExplicitlyAnywhere(principalIDs []string, verb string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if pSet[b.Principal] && explicitGrantMatches(snap.roleVerbs[b.Role], verb) {
			return true
		}
	}
	return false
}

// HoldsVerbAnywhere reports whether principalIDs hold verb through any binding
// at any path — a cheap "could this caller ever be authorized" precheck.
func (e *Engine) HoldsVerbAnywhere(principalIDs []string, verb string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if pSet[b.Principal] && verbMatches(snap.roleVerbs[b.Role], verb) {
			return true
		}
	}
	return false
}

// HasAnyBinding reports whether the engine has at least one binding for
// any of the given principals. Used by the transitional RequirePerm
// bridge to decide whether to fall back to legacy admin/operator/viewer.
func (e *Engine) HasAnyBinding(principalIDs []string) bool {
	if e == nil {
		return false
	}
	snap := e.snap.Load()
	if snap == nil {
		return false
	}
	pSet := make(map[string]bool, len(principalIDs))
	for _, p := range principalIDs {
		pSet[p] = true
	}
	for _, b := range snap.bindings {
		if pSet[b.Principal] {
			return true
		}
	}
	return false
}

// SeedBuiltinRoles installs (or refreshes) litevirt's standard roles. Idempotent.
func SeedBuiltinRoles(ctx context.Context, db *corrosion.Client) error {
	for _, r := range BuiltinRoles {
		rec := corrosion.RoleRecord{
			Name:        r.Name,
			Verbs:       r.Verbs,
			Description: r.Description,
			BuiltIn:     true,
		}
		if err := corrosion.InsertRole(ctx, db, rec); err != nil {
			return err
		}
	}
	return nil
}

// BuiltinRole is one of litevirt's pre-defined roles.
type BuiltinRole struct {
	Name        string
	Verbs       []string
	Description string
}

// BuiltinRoles is the list of roles seeded on every daemon start.
//
// Verb names are stable: an external automation (Terraform provider,
// scripts) may reference them. Wildcards collapse common cases.
var BuiltinRoles = []BuiltinRole{
	{
		Name:        "Admin",
		Verbs:       []string{"*"},
		Description: "Full access — every verb on every path. The cluster's superuser.",
	},
	{
		Name: "Operator",
		Verbs: []string{
			"vm.*", "ct.*",
			policy.OwnerManage,
			"network.read", "network.create", "network.delete",
			"lb.*",
			"image.read", "image.pull", "image.import", "image.push", "image.build",
			"backup.*",
			"snapshot.*",
			"sg.read",
			"audit.read",
			"host.read",
			"storage.pool.read", "storage.pool.write",
			"storage.content.read", "storage.content.write",
			"resourcemap.read", "resourcemap.write",
			// The ONLY cluster.* verb Operator holds, and deliberately not
			// cluster.update: acknowledging a contested lease term clears
			// evidence tracking on one node and picks no winner, so it is a
			// day-to-day remedy for the ha.lww.unresolved condition rather
			// than a cluster mutation. Granting cluster.update here would
			// hand Operator every cluster verb added later.
			"cluster.lww.acknowledge",
		},
		Description: "Day-to-day VM operations: create, start, stop, snapshot, backup, attach networks/LBs.",
	},
	{
		Name: "VMOperator",
		Verbs: []string{
			"vm.start", "vm.stop", "vm.restart",
			"vm.console", "vm.read", "vm.exec",
		},
		Description: "Restricted VM lifecycle: start/stop/console only. Cannot create or delete VMs.",
	},
	{
		Name:        "Auditor",
		Verbs:       []string{"*.read", "audit.export"},
		Description: "Read-only across all resources, plus audit-log export. Distinct from Viewer once audit becomes hash-chained; functionally equivalent to Viewer today.",
	},
	{
		Name:        "Viewer",
		Verbs:       []string{"*.read"},
		Description: "Read-only across all resources. Today this includes audit.read; will narrow this to non-audit reads.",
	},
	{
		Name: "BackupOperator",
		Verbs: []string{
			"backup.*",
			"snapshot.*",
			"vm.read",
		},
		Description: "Backup and snapshot operations only. Read-only on VMs.",
	},
	{
		Name: "NetworkAdmin",
		Verbs: []string{
			"network.*",
			"lb.*",
			"sg.*", // security groups
		},
		Description: "Networking and load balancing. No VM lifecycle access.",
	},
	{
		Name:  "ContainerRoot",
		Verbs: []string{"ct.exec", VerbContainerRoot},
		Description: "Exec in, and a compose image change of, a privileged or legacy-confined container, which " +
			"runs as root on the host or with nesting allowed. Bind it on one container's path, e.g. " +
			"/projects/acme/containers/build; Operator's ct.* does not carry it.",
	},
	{
		Name:  "PermissionAdmin",
		Verbs: []string{VerbPermModify},
		Description: "Delegated administration (Proxmox: Permissions.Modify): grant and revoke roles at the " +
			"bound path and below, never a role carrying a verb the holder does not itself hold there. " +
			"Bind it beside the roles to delegate, e.g. Operator + PermissionAdmin on /projects/acme.",
	},
	{
		Name:  "NoAccess",
		Verbs: []string{},
		Description: "Grants nothing. Bindings are union-only, so it cannot deny what another binding grants; " +
			"what it does is keep a principal bound, and so off its cluster-wide legacy-role fallback. " +
			"A delegated revoke leaves one as a sentinel.",
	},
}
