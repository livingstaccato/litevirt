package grpcapi

// Delegated administration (Proxmox: Permissions.Modify on a path).
//
// A principal holding auth.VerbPermModify at a path may grant and revoke role
// bindings there and below without being a cluster admin. Everything here is
// about what that must NOT let it do. Each rule below closes a way a
// delegated administrator could reach beyond the path it was given:
//
//  1. Escalation by role. The role granted may carry no grant the caller does
//     not itself hold at that path (auth.GrantCovers). A project admin holding
//     Operator cannot hand out Admin ("*") there, and cannot hand out
//     PermissionAdmin unless it holds perm.modify — which it does, so it can
//     delegate delegation, but only of what it holds.
//
//  2. Escalation by propagation. A propagating grant at P reaches every path
//     below P. If the caller's own grant stops at P (propagate=false), it
//     holds nothing below P, so the grant is measured against the caller's
//     PROPAGATING grants only (Engine.GrantsAt mustPropagate).
//
//  3. Escaping the path. The path is canonicalized and must not contain "."
//     or ".." segments, empty segments or control characters: the engine
//     matches paths by prefix, literally, so "/projects/acme/../other" is
//     under /projects/acme to the engine's prefix test and names another
//     project to anything that ever cleans a path. A scoped API token may
//     only act inside its scope.
//
//  4. Changing access OUTSIDE the path through the legacy fallback. A caller
//     with no role binding at all is authorized by its legacy role
//     (admin/operator/viewer) CLUSTER-WIDE; the first binding a principal
//     receives switches it to the engine, which ends that cluster-wide
//     access, and revoking a principal's last binding switches it back, which
//     restores it. Either is a change to access at paths the caller does not
//     administer — the revoke direction an escalation (a principal pinned to
//     Viewer on one project reverts to a cluster-wide legacy operator). So a
//     delegated grant must not be a principal's first, and a delegated revoke
//     must not remove a principal's last; a cluster admin makes those.
//
//  5. Unresolvable principals. A bare user:<name> is inert today and can be
//     rewritten to an effective form later (`lv role normalize`), and a user
//     that does not exist yet would be created into the binding by whoever
//     creates it. A delegated grant names an existing user with its realm, or
//     a group.
//
// What it does not stop: a cluster admin who later widens a custom role's
// verbs widens every binding of it, delegated ones included. Roles are
// cluster-admin territory (built-ins cannot be changed).

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// delegablePath canonicalizes an RBAC path for a delegated grant and refuses
// any path whose meaning could differ between the engine's literal prefix
// match and a path cleaner.
func delegablePath(p string) (string, error) {
	if !strings.HasPrefix(p, "/") {
		return "", fmt.Errorf("path must start with /")
	}
	for _, r := range p {
		if r < 0x20 || r == 0x7f || r == '\\' {
			return "", fmt.Errorf("path contains a control character or backslash")
		}
	}
	for len(p) > 1 && strings.HasSuffix(p, "/") {
		p = strings.TrimSuffix(p, "/")
	}
	if p == "/" {
		return p, nil
	}
	for _, seg := range strings.Split(p[1:], "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", fmt.Errorf("path has an empty, \".\" or \"..\" segment")
		}
	}
	return p, nil
}

// callerPrincipals is principalsForCaller for the request's caller.
func callerPrincipals(ctx context.Context) []string {
	return principalsForCaller(callerUsername(ctx), callerRole(ctx), callerRealm(ctx))
}

// callerMayDelegate reports whether the caller holds perm.modify anywhere,
// so a caller who could never be authorized by delegation keeps getting the
// plain admin-required refusal it always got.
func (s *Server) callerMayDelegate(ctx context.Context) bool {
	return s != nil && s.authEngine != nil && callerUsername(ctx) != "" &&
		s.authEngine.HoldsVerbAnywhere(callerPrincipals(ctx), auth.VerbPermModify)
}

// authorizeDelegatedPath checks rule 3 and that the caller holds perm.modify
// at path, and returns the canonical path.
func (s *Server) authorizeDelegatedPath(ctx context.Context, path string) (string, error) {
	cpath, err := delegablePath(path)
	if err != nil {
		return "", status.Errorf(codes.InvalidArgument, "delegated grant path %q: %v", path, err)
	}
	if scopes := callerScopePaths(ctx); len(scopes) > 0 && !pathAllowedByScopes(cpath, scopes) {
		return "", status.Errorf(codes.PermissionDenied, "token scope does not cover %q", cpath)
	}
	if !s.authEngine.Allowed(callerPrincipals(ctx), auth.VerbPermModify, cpath) {
		return "", status.Errorf(codes.PermissionDenied,
			"caller %q lacks %s on %q: role grants there need a cluster admin or %s on that path",
			callerUsername(ctx), auth.VerbPermModify, cpath, auth.VerbPermModify)
	}
	return cpath, nil
}

// refuseEscalation checks rules 1 and 2: role's grants are all held by the
// caller at path (propagating grants only when the binding propagates).
func (s *Server) refuseEscalation(ctx context.Context, path, role string, propagate bool) error {
	verbs, ok := s.authEngine.RoleVerbs(role)
	if !ok {
		return status.Errorf(codes.PermissionDenied,
			"role %q is not defined; a delegated grant may only name an existing role", role)
	}
	held := s.authEngine.GrantsAt(callerPrincipals(ctx), path, propagate)
	if missing := auth.UncoveredGrants(held, verbs); len(missing) > 0 {
		where := "at " + path
		if propagate {
			where += " and every path below it"
		}
		return status.Errorf(codes.PermissionDenied,
			"role %q carries %v, which you do not hold %s: a delegated grant can give no more than its "+
				"grantor holds", role, missing, where)
	}
	return nil
}

// principalSet resolves a binding principal to the principal set of every
// caller it applies to that could change engine status with it (rule 4/5):
// for a realm-qualified user, that user's full set; for a group, the group
// alone. ok=false is a principal a delegated grant may not name.
func (s *Server) principalSet(ctx context.Context, principal string) (set []string, ok bool, err error) {
	if body, isUser := strings.CutPrefix(principal, "user:"); isUser {
		name, realm, qualified := classifyUserPrincipal(body)
		if !qualified {
			return nil, false, nil
		}
		u, err := corrosion.GetUser(ctx, s.db, name)
		if err != nil {
			return nil, false, err
		}
		if u == nil {
			return nil, false, nil
		}
		return principalsForCaller(name, u.Role, realm), true, nil
	}
	return []string{principal}, true, nil
}

// authorizeDelegatedGrant applies every rule to a grant from a caller who is
// not a cluster admin, and returns the canonical path to store.
func (s *Server) authorizeDelegatedGrant(ctx context.Context, path, role, principal string, propagate bool) (string, error) {
	if s.authEngine == nil {
		return "", status.Error(codes.PermissionDenied, "role grants require admin (no RBAC engine on this node)")
	}
	cpath, err := s.authorizeDelegatedPath(ctx, path)
	if err != nil {
		return "", err
	}
	if err := s.refuseEscalation(ctx, cpath, role, propagate); err != nil {
		return "", err
	}
	set, ok, err := s.principalSet(ctx, principal)
	if err != nil {
		return "", status.Errorf(codes.Internal, "resolve principal %q: %v", principal, err)
	}
	if !ok {
		return "", status.Errorf(codes.PermissionDenied,
			"a delegated grant must name an existing user with its realm (user:<name>@<realm>) or a "+
				"group (group:<group>@<realm>); %q is neither", principal)
	}
	if !s.authEngine.HasAnyBinding(set) {
		return "", status.Errorf(codes.PermissionDenied,
			"%s has no role binding yet, so it is authorized by its legacy role cluster-wide; its first "+
				"binding changes its access outside %s, and only a cluster admin may make it", principal, cpath)
	}
	return cpath, nil
}

// authorizeDelegatedRevoke applies the rules to a revoke from a caller who is
// not a cluster admin. A binding to an undefined role grants nothing, so
// revoking it cannot exceed the caller; the last-binding rule still applies.
func (s *Server) authorizeDelegatedRevoke(ctx context.Context, b *corrosion.RoleBindingRecord) error {
	if s.authEngine == nil {
		return status.Error(codes.PermissionDenied, "role revokes require admin (no RBAC engine on this node)")
	}
	cpath, err := s.authorizeDelegatedPath(ctx, b.Path)
	if err != nil {
		return err
	}
	if _, defined := s.authEngine.RoleVerbs(b.Role); defined {
		if err := s.refuseEscalation(ctx, cpath, b.Role, b.Propagate); err != nil {
			return err
		}
	}
	set, ok, err := s.principalSet(ctx, b.Principal)
	if err != nil {
		return status.Errorf(codes.Internal, "resolve principal %q: %v", b.Principal, err)
	}
	if !ok {
		// A bare or unknown-user binding is inert: removing it changes no
		// caller's engine status.
		return nil
	}
	if !s.authEngine.HasAnyBindingExcept(set, b.ID) {
		return status.Errorf(codes.PermissionDenied,
			"binding %s is the last role binding of %s; removing it returns that principal to its legacy "+
				"role cluster-wide, and only a cluster admin may do that", b.ID, b.Principal)
	}
	return nil
}
