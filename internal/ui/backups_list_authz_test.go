package ui

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// /backups listed a repo's manifests by opening ?repo= in-process, so the
// page answered to no authorization at all: any session could name an
// arbitrary absolute path — probing the daemon host's filesystem for repos —
// and read every project's snapshot list out of it. The daemon's own repo
// resolution (resolveBackupRepoPath) refuses a custom absolute path to anyone
// but an admin, and a repo holds every project's backups, so it is checked at
// `/` where a project-scoped grant does not reach.

// newUIBoundAt is newUIBoundToSvc with the binding at path rather than `/`.
func newUIBoundAt(t *testing.T, user, path, role string) (*Server, *corrosion.Client, *grpcapi.Server) {
	t.Helper()
	s, db, svc := newUIOverRealDaemonSvc(t, user, "viewer")
	ctx := context.Background()
	if err := auth.SeedBuiltinRoles(ctx, db); err != nil {
		t.Fatalf("SeedBuiltinRoles: %v", err)
	}
	if err := corrosion.InsertRoleBinding(ctx, db, corrosion.RoleBindingRecord{
		ID: user + "@" + path, Path: path, Role: role, Principal: "user:" + user + "@local", Propagate: true,
	}); err != nil {
		t.Fatalf("InsertRoleBinding: %v", err)
	}
	engine := auth.NewEngine(db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	svc.SetAuthEngine(engine)
	return s, db, svc
}

// The seeded "main" repo holds three snapshots of vm1; a page that shows any of
// them has listed the repo.
func listedManifests(body string) bool { return strings.Contains(body, "2026-01-01T00:00:00Z") }

func TestUIBackupsList_AnAbsolutePathNeedsAdmin(t *testing.T) {
	s, _, svc := newUIOverRealDaemonSvc(t, "vic", "viewer")
	repos := seedBackupRepos(t, s, svc)

	w := serveRequest(s, uiSessionReq(t, "GET", "/backups?repo="+url.QueryEscape(repos.main), nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("a viewer browsing a repo by absolute path: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if listedManifests(w.Body.String()) {
		t.Error("a viewer read a repo's manifests by naming its path on disk")
	}
}

func TestUIBackupsList_AProjectScopedGrantCannotListARepo(t *testing.T) {
	s, _, svc := newUIBoundAt(t, "carol", "/projects/acme", "Admin")
	seedBackupRepos(t, s, svc)

	w := serveRequest(s, uiSessionReq(t, "GET", "/backups?repo=main", nil))
	if w.Code != http.StatusForbidden {
		t.Errorf("a project-scoped grant browsing a repo: status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if listedManifests(w.Body.String()) {
		t.Error("a project-scoped grant listed every project's snapshots in a repo")
	}
	// Nor does the overview count them for it.
	w = serveRequest(s, uiSessionReq(t, "GET", "/backups", nil))
	if strings.Contains(w.Body.String(), "<dt>Snapshots</dt><dd>3</dd>") {
		t.Error("the repo overview counted a repo's snapshots for a project-scoped grant")
	}
}

// The legitimate paths: a cluster-wide reader browses a registered repo by
// name, an admin browses by path, and the overview counts both repos.
func TestUIBackupsList_ClusterReadersStillBrowse(t *testing.T) {
	s, _, svc := newUIBoundToSvc(t, "vera", "Viewer")
	seedBackupRepos(t, s, svc)
	w := serveRequest(s, uiSessionReq(t, "GET", "/backups?repo=main", nil))
	assertStatus(t, w, http.StatusOK)
	if !listedManifests(w.Body.String()) {
		t.Errorf("a cluster Viewer could not browse a registered repo: %s", truncBody(w))
	}
	w = serveRequest(s, uiSessionReq(t, "GET", "/backups", nil))
	assertStatus(t, w, http.StatusOK)
	mustContain(t, w.Body.String(), "<dt>Snapshots</dt><dd>3</dd>", `href="/backups?repo=main"`)

	a, _, asvc := newUIOverRealDaemonSvc(t, "ada", "admin")
	arepos := seedBackupRepos(t, a, asvc)
	w = serveRequest(a, uiSessionReq(t, "GET", "/backups?repo="+url.QueryEscape(arepos.main), nil))
	assertStatus(t, w, http.StatusOK)
	if !listedManifests(w.Body.String()) {
		t.Errorf("an admin could not browse a repo by path: %s", truncBody(w))
	}
}
