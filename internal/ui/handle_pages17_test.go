package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// TestHandleSecurityGroups_Empty renders the page with no SGs — the
// empty-state CTA should appear so brand-new clusters have a hint instead of a
// blank table.
func TestHandleSecurityGroups_Empty(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())

	r := withAuth(httptest.NewRequest(http.MethodGet, "/security-groups", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	mustContain(t, w.Body.String(), "No security groups defined", "Create group")
}

// TestHandleSecurityGroups_RendersRows lists two SGs and their rules from
// ListSecurityGroups and asserts each rule lands under its own group.
func TestHandleSecurityGroups_RendersRows(t *testing.T) {
	m := newDefaultMock()
	m.listSGsResp = &pb.ListSecurityGroupsResponse{
		Groups: []*pb.SecurityGroup{{Id: "sg-web", Name: "web"}, {Id: "sg-db", Name: "db", StackName: "shop"}},
		Rules: []*pb.SecurityGroupRule{
			{Id: "r1", SgId: "sg-web", Direction: "ingress", Proto: "tcp", Port: "443", Action: "accept"},
			{Id: "r2", SgId: "sg-db", Direction: "egress", Proto: "udp", Port: "53", Cidr: "10.0.0.0/8", Action: "drop"},
		},
	}
	s := newTestUIServer(t, m)

	r := withAuth(httptest.NewRequest(http.MethodGet, "/security-groups", nil))
	body := serveRequest(s, r).Body.String()
	mustContain(t, body, "web", "ingress", "tcp", ":443", "accept", "stack shop", ":53", "10.0.0.0/8", "drop")
	web, db := strings.Index(body, "sg-web"), strings.Index(body, "sg-db")
	r1, r2 := strings.Index(body, "rules/r1"), strings.Index(body, "rules/r2")
	if web < 0 || db < 0 || r1 < 0 || r2 < 0 || !(web < r1 && r1 < db && db < r2) {
		t.Errorf("rules not rendered under their own groups (sg-web@%d r1@%d sg-db@%d r2@%d)", web, r1, db, r2)
	}
}

// TestHandleContainers_Empty exercises the empty-state branch via the
// default mock returning no containers.
func TestHandleContainers_Empty(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/containers", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "No containers yet", "lv ct create")
}

// TestHandleContainers_RendersRows wires the mock to return one entry
// and asserts the table renders it.
func TestHandleContainers_RendersRows(t *testing.T) {
	mock := newDefaultMock()
	mock.listContainersResp = &pb.ListContainersResponse{Containers: []*pb.Container{{
		HostName: "host-a", Name: "ct-1", State: "running",
		Image: "alpine:3.19", CpuLimit: 2, MemoryMib: 256,
	}}}
	s := newTestUIServer(t, mock)
	r := withAuth(httptest.NewRequest(http.MethodGet, "/containers", nil))
	w := serveRequest(s, r)
	mustContain(t, w.Body.String(), "host-a", "ct-1", "running", "alpine:3.19")
}

// TestHandleBackups_NoRepoQuery shows the prompt+hint when no repos
// have been configured.
func TestHandleBackups_NoRepoQuery(t *testing.T) {
	s := newTestUIServer(t, newDefaultMock())
	r := withAuth(httptest.NewRequest(http.MethodGet, "/backups", nil))
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	mustContain(t, w.Body.String(), "No repos configured", "Browse")
}

// TestHandleBackups_ConfiguredRepos init-s two real pbsstore repos,
// hands them to the UI server and the daemon via SetBackupRepos, then renders
// /backups (no query string) and asserts BOTH appear in the configured-repos
// table with their snapshot counts. The page lists through the daemon's
// ListBackupRepoSnapshots, so it runs over a real one.
func TestHandleBackups_ConfiguredRepos(t *testing.T) {
	s, _, svc := newUIOverRealDaemonSvc(t, "ada", "admin")
	mainDir := filepath.Join(t.TempDir(), "main")
	dr2Dir := filepath.Join(t.TempDir(), "dr")
	mainRepo, err := pbsstore.Init(mainDir)
	if err != nil {
		t.Fatalf("Init main: %v", err)
	}
	if _, err := pbsstore.Init(dr2Dir); err != nil {
		t.Fatalf("Init dr: %v", err)
	}
	if err := mainRepo.PutManifest(&pbsstore.Manifest{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-10T01:23:45Z",
		TotalSize: 4096,
	}); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}
	s.SetBackupRepos(map[string]string{"main": mainDir, "dr": dr2Dir})
	svc.SetBackupRepos(map[string]string{"main": mainDir, "dr": dr2Dir})

	r := uiSessionReq(t, http.MethodGet, "/backups", nil)
	w := serveRequest(s, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	body := w.Body.String()
	// Repos now render as cards (name + path + snapshot count) rather than a table.
	mustContain(t, body, "main", "dr", mainDir, dr2Dir, "<dt>Snapshots</dt><dd>1</dd>")
}

// TestHandleBackups_RealRepo init-s a real pbsstore, pushes one
// snapshot, then renders /backups?repo=… as an admin (a custom absolute path
// is admin-only) and asserts the manifest row appears.
func TestHandleBackups_RealRepo(t *testing.T) {
	s, _, _ := newUIOverRealDaemonSvc(t, "ada", "admin")
	repoDir := filepath.Join(t.TempDir(), "repo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatalf("pbsstore.Init: %v", err)
	}
	m := &pbsstore.Manifest{
		VMName: "vm1", DiskName: "root", Timestamp: "2026-05-10T01:23:45Z",
		TotalSize: 4096, Chunks: []pbsstore.ChunkRef{{ID: strings.Repeat("a", 64), Size: 4096, Offset: 0}},
	}
	if err := repo.PutManifest(m); err != nil {
		t.Fatalf("PutManifest: %v", err)
	}

	r := uiSessionReq(t, http.MethodGet, "/backups?repo="+url.QueryEscape(repoDir), nil)
	w := serveRequest(s, r)
	mustContain(t, w.Body.String(), "vm1", "root", "2026-05-10T01:23:45Z")
}

// newCorrosionForUITest spins up an in-memory Corrosion suitable for
// UI handlers that read directly from the DB.
func newCorrosionForUITest(t *testing.T) *corrosion.Client {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	return db
}

func mustContain(t *testing.T, body string, needles ...string) {
	t.Helper()
	for _, n := range needles {
		if !strings.Contains(body, n) {
			t.Errorf("expected %q in body; got:\n%s", n, body)
		}
	}
}
