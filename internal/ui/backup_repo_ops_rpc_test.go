package ui

import (
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// The /backups page's repo actions — verify, GC, prune and sync — ran
// internal/pbsstore in-process behind nothing but a session with some role. A
// Viewer could prune a repo's manifests and garbage-collect the chunks they
// referenced, which destroys the backups outright, and none of it reached the
// audit log. The page now calls the daemon's VerifyBackupRepo,
// GarbageCollectBackupRepo, PruneBackupRepo and SyncBackupRepo with the
// session's bearer, so it is held to backup.verify / backup.gc / backup.prune /
// backup.sync and every action is the RPC's audited one.

type seededRepos struct {
	main, dr string
	orphan   string // chunk id no manifest references, aged past the GC grace
}

// seedBackupRepos builds two real repos: "main" with three snapshots of one
// disk, each its own chunk, plus one unreferenced chunk; "dr" empty. Every
// chunk is aged past pbsstore.DefaultChunkGracePeriod so a GC sweeps what it
// may sweep. Both the UI and the daemon are given the same name → path map, as
// the daemon wiring does from one config.
func seedBackupRepos(t *testing.T, s *Server, svc *grpcapi.Server) seededRepos {
	t.Helper()
	base := t.TempDir()
	out := seededRepos{main: filepath.Join(base, "main"), dr: filepath.Join(base, "dr")}
	main, err := pbsstore.Init(out.main)
	if err != nil {
		t.Fatalf("Init main: %v", err)
	}
	if _, err := pbsstore.Init(out.dr); err != nil {
		t.Fatalf("Init dr: %v", err)
	}
	for i, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"} {
		data := []byte("snapshot payload " + ts)
		id, _, err := main.PutChunk(data)
		if err != nil {
			t.Fatalf("PutChunk %d: %v", i, err)
		}
		if err := main.PutManifest(&pbsstore.Manifest{
			VMName: "vm1", DiskName: "root", Timestamp: ts, TotalSize: int64(len(data)),
			Chunks: []pbsstore.ChunkRef{{ID: id, Size: int64(len(data)), Offset: 0}},
		}); err != nil {
			t.Fatalf("PutManifest %d: %v", i, err)
		}
	}
	if out.orphan, _, err = main.PutChunk([]byte("left behind by an aborted push")); err != nil {
		t.Fatalf("PutChunk orphan: %v", err)
	}
	old := time.Now().Add(-2 * pbsstore.DefaultChunkGracePeriod)
	if err := filepath.WalkDir(filepath.Join(out.main, "chunks"), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		return os.Chtimes(p, old, old)
	}); err != nil {
		t.Fatalf("age chunks: %v", err)
	}
	repos := map[string]string{"main": out.main, "dr": out.dr}
	s.SetBackupRepos(repos)
	svc.SetBackupRepos(repos)
	return out
}

func manifestCount(t *testing.T, path string) int {
	t.Helper()
	r, err := pbsstore.Open(path)
	if err != nil {
		t.Fatalf("Open %s: %v", path, err)
	}
	ms, err := r.ListManifests()
	if err != nil {
		t.Fatalf("ListManifests %s: %v", path, err)
	}
	return len(ms)
}

func chunkExists(t *testing.T, repoPath, id string) bool {
	t.Helper()
	r, err := pbsstore.Open(repoPath)
	if err != nil {
		t.Fatalf("Open %s: %v", repoPath, err)
	}
	return r.HasChunk(id)
}

func repoOpRequests(t *testing.T) map[string]*http.Request {
	t.Helper()
	keep := url.Values{"keep_last": {"1"}}
	apply := url.Values{"keep_last": {"1"}, "apply": {"1"}}
	return map[string]*http.Request{
		"verify":        uiSessionReq(t, "POST", "/ui/backups/verify?repo=main", nil),
		"gc":            uiSessionReq(t, "POST", "/ui/backups/gc?repo=main", nil),
		"prune preview": uiSessionReq(t, "POST", "/ui/backups/prune?repo=main", keep),
		"prune apply":   uiSessionReq(t, "POST", "/ui/backups/prune?repo=main", apply),
		"sync":          uiSessionReq(t, "POST", "/ui/backups/sync?repo=main", url.Values{"dest": {"dr"}}),
	}
}

func TestUIBackupRepoOps_ViewerRefused(t *testing.T) {
	cases := map[string]func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server){
		"bound Viewer": func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIBoundToSvc(t, "vic", "Viewer")
		},
		"legacy viewer": func(t *testing.T) (*Server, *corrosion.Client, *grpcapi.Server) {
			return newUIOverRealDaemonSvc(t, "vic", "viewer")
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s, db, svc := mk(t)
			repos := seedBackupRepos(t, s, svc)

			for what, r := range repoOpRequests(t) {
				if w := serveRequest(s, r); w.Code != http.StatusForbidden {
					t.Errorf("%s: status = %d, want %d; body = %s", what, w.Code, http.StatusForbidden, truncBody(w))
				}
			}

			if n := manifestCount(t, repos.main); n != 3 {
				t.Errorf("a viewer pruned main: %d manifests left, want 3", n)
			}
			if !chunkExists(t, repos.main, repos.orphan) {
				t.Errorf("a viewer garbage-collected main: the unreferenced chunk is gone")
			}
			if n := manifestCount(t, repos.dr); n != 0 {
				t.Errorf("a viewer synced main into dr: %d manifests there, want 0", n)
			}

			// Each refusal is on the record against the session user, and
			// nothing is recorded as done.
			for _, action := range []string{"backup.repo.verify", "backup.repo.gc", "backup.repo.prune", "backup.repo.sync"} {
				rows := rpcAuditRows(t, db, action)
				if len(rows) == 0 {
					t.Errorf("%s: no audit row for a refused attempt", action)
				}
				for _, row := range rows {
					if row.result != "denied" || row.user != "vic" || row.host != "test-host" {
						t.Errorf("%s: audit row %+v, want a denied row for vic from test-host", action, row)
					}
				}
			}
		})
	}
}

// BackupOperator is the narrowest built-in role holding the four verbs, so it
// is the one to prove the page works for. Operator holds backup.* too.
func TestUIBackupRepoOps_BackupOperatorAllowedAndAudited(t *testing.T) {
	for _, role := range []string{"BackupOperator", "Operator"} {
		t.Run(role, func(t *testing.T) {
			s, db, svc := newUIBoundToSvc(t, "bo", role)
			repos := seedBackupRepos(t, s, svc)
			reqs := repoOpRequests(t)

			w := serveRequest(s, reqs["verify"])
			assertStatus(t, w, http.StatusOK)
			wantRPCAudit(t, db, "backup.repo.verify", "bo", "main", "chunks_checked=3 mismatched=0 missing=0")

			w = serveRequest(s, reqs["sync"])
			assertStatus(t, w, http.StatusOK)
			if n := manifestCount(t, repos.dr); n != 3 {
				t.Errorf("sync: dr has %d manifests, want 3", n)
			}
			wantRPCAudit(t, db, "backup.repo.sync", "bo", "main -> dr", wantSyncDetail())

			// A preview changes nothing and is not audited.
			w = serveRequest(s, reqs["prune preview"])
			assertStatus(t, w, http.StatusOK)
			mustContain(t, w.Body.String(), "keep 1, delete 2")
			if n := manifestCount(t, repos.main); n != 3 {
				t.Errorf("prune preview deleted manifests: %d left, want 3", n)
			}
			if rows := rpcAuditRows(t, db, "backup.repo.prune"); len(rows) != 0 {
				t.Errorf("prune preview wrote audit rows: %+v", rows)
			}

			w = serveRequest(s, reqs["prune apply"])
			assertStatus(t, w, http.StatusOK)
			if n := manifestCount(t, repos.main); n != 1 {
				t.Errorf("prune: %d manifests left, want 1", n)
			}
			wantRPCAudit(t, db, "backup.repo.prune", "bo", "main",
				"keep_last=1 keep_daily=0 keep_weekly=0 keep_monthly=0 keep_yearly=0 kept=1 deleted=2")

			w = serveRequest(s, reqs["gc"])
			assertStatus(t, w, http.StatusOK)
			if chunkExists(t, repos.main, repos.orphan) {
				t.Errorf("gc: the unreferenced chunk survived")
			}
			rows := rpcAuditRows(t, db, "backup.repo.gc")
			if len(rows) != 1 || rows[0].user != "bo" || rows[0].host != "test-host" ||
				rows[0].target != "main" || rows[0].result != "ok" ||
				!regexp.MustCompile(`^manifests_scanned=1 chunks_deleted=3 bytes_reclaimed=[1-9][0-9]* retained_young=0 manifests_invalid=0$`).MatchString(rows[0].detail) {
				t.Errorf("gc audit rows = %+v, want one ok row for bo on main counting 3 chunks deleted", rows)
			}
		})
	}
}

// wantSyncDetail is the detail a sync of the seeded main into an empty dr
// writes: all three manifests and their three chunks; the orphan is not copied
// because no manifest names it.
func wantSyncDetail() string {
	var bytes int64
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"} {
		bytes += int64(len("snapshot payload " + ts))
	}
	return "manifests_copied=3 chunks_copied=3 chunks_skipped=0 bytes_copied=" + strconv.FormatInt(bytes, 10)
}

// A legacy operator (no bindings) meets the operator floor of every verb.
func TestUIBackupRepoOps_LegacyOperatorAllowed(t *testing.T) {
	s, db, svc := newUIOverRealDaemonSvc(t, "olga", "operator")
	repos := seedBackupRepos(t, s, svc)
	w := serveRequest(s, repoOpRequests(t)["prune apply"])
	assertStatus(t, w, http.StatusOK)
	if n := manifestCount(t, repos.main); n != 1 {
		t.Errorf("prune: %d manifests left, want 1", n)
	}
	wantRPCAudit(t, db, "backup.repo.prune", "olga", "main",
		"keep_last=1 keep_daily=0 keep_weekly=0 keep_monthly=0 keep_yearly=0 kept=1 deleted=2")
}

// A custom absolute path is admin-only at the RPC (resolveBackupRepoPath); the
// page used to open whatever path the query string named.
func TestUIBackupRepoOps_AbsolutePathNeedsAdmin(t *testing.T) {
	s, _, svc := newUIBoundToSvc(t, "bo", "BackupOperator")
	repos := seedBackupRepos(t, s, svc)
	w := serveRequest(s, uiSessionReq(t, "POST", "/ui/backups/prune?repo="+url.QueryEscape(repos.main),
		url.Values{"keep_last": {"1"}, "apply": {"1"}}))
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if n := manifestCount(t, repos.main); n != 3 {
		t.Errorf("prune by absolute path ran: %d manifests left, want 3", n)
	}
}
