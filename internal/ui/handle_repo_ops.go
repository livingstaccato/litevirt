package ui

import (
	"fmt"
	"net/http"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Repo maintenance actions for /backups. Each calls the daemon's RPC with the
// session's bearer — VerifyBackupRepo, GarbageCollectBackupRepo,
// PruneBackupRepo, SyncBackupRepo — so the daemon checks backup.verify /
// backup.gc / backup.prune / backup.sync against the caller's own credential
// and writes the audit row, exactly as for any other caller of those RPCs.
// They used to run internal/pbsstore in-process behind nothing but a session
// with some role, so a Viewer could prune or garbage-collect a repo. The repo
// is passed by the name in ?repo=; the daemon resolves it, and refuses a custom
// absolute path to anyone but an admin.

// repoParam is the ?repo= the /backups page puts on every action.
func repoParam(r *http.Request) string { return strings.TrimSpace(r.URL.Query().Get("repo")) }

// backupInFlight reports whether a backup to the named repo is currently
// running — GC must not race a push to the same repo (a just-written chunk
// whose manifest hasn't landed looks like garbage).
func (s *Server) backupInFlight(repoName string) bool {
	inflight := false
	s.backupOps.Range(func(_, v any) bool {
		st := v.(*backupOpState)
		if st.Kind == "backup" && st.Repo == repoName && !st.Done {
			inflight = true
			return false
		}
		return true
	})
	return inflight
}

func (s *Server) handleRepoVerify(w http.ResponseWriter, r *http.Request) {
	name := repoParam(r)
	if name == "" {
		sendToast(w, "Verify failed: repo required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp, err := s.grpc.VerifyBackupRepo(s.uiBearerCtx(r), &pb.VerifyBackupRepoRequest{Repo: name})
	if err != nil {
		sendToast(w, "Verify failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	mismatched, missing := len(resp.GetMismatched()), len(resp.GetMissing())
	if mismatched+missing > 0 {
		sendToast(w, fmt.Sprintf("Repo %s: %d chunks checked, %d mismatched, %d missing", name, resp.GetChunksChecked(), mismatched, missing), "error")
	} else {
		sendToast(w, fmt.Sprintf("Repo %s verified: %d chunks OK", name, resp.GetChunksChecked()), "success")
	}
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRepoGC(w http.ResponseWriter, r *http.Request) {
	name := repoParam(r)
	if name == "" {
		sendToast(w, "GC failed: repo required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// A courtesy for backups this page started. The RPC's chunk grace period is
	// what keeps a sweep off an in-flight push from any source.
	if s.backupInFlight(name) {
		sendToast(w, "A backup to this repo is in progress — try GC again when it finishes", "error")
		w.WriteHeader(http.StatusConflict)
		return
	}
	resp, err := s.grpc.GarbageCollectBackupRepo(s.uiBearerCtx(r), &pb.GarbageCollectBackupRepoRequest{Repo: name})
	if err != nil {
		sendToast(w, "GC failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	sendToast(w, fmt.Sprintf("GC on %s: removed %d chunks, reclaimed %s", name, resp.GetChunksDeleted(), formatBytes(resp.GetBytesReclaimed())), "success")
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRepoSyncModal(w http.ResponseWriter, r *http.Request) {
	src := r.URL.Query().Get("repo")
	var dests []string
	for _, n := range s.repoNames() {
		if n != src {
			dests = append(dests, n)
		}
	}
	s.renderFragment(w, "repo_sync_modal.html", map[string]any{"Src": src, "Dests": dests})
}

func (s *Server) handleRepoSync(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	srcName := repoParam(r)
	dstName := strings.TrimSpace(r.FormValue("dest"))
	if srcName == "" || dstName == "" {
		sendToast(w, "Sync failed: source and destination repo required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	resp, err := s.grpc.SyncBackupRepo(s.uiBearerCtx(r), &pb.SyncBackupRepoRequest{Source: srcName, Destination: dstName})
	if err != nil {
		sendToast(w, "Sync failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	sendToast(w, fmt.Sprintf("Synced %s → %s: %d manifests, %d chunks (%s), %d already present",
		srcName, dstName, resp.GetManifestsCopied(), resp.GetChunksCopied(), formatBytes(resp.GetBytesCopied()), resp.GetChunksSkipped()), "success")
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleRepoPruneModal(w http.ResponseWriter, r *http.Request) {
	s.renderFragment(w, "repo_prune_modal.html", map[string]any{"Repo": r.URL.Query().Get("repo")})
}

// handleRepoPrune previews (apply=0) or applies (apply=1) a retention prune.
// Both go through PruneBackupRepo, so the preview needs backup.prune too.
func (s *Server) handleRepoPrune(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	name := repoParam(r)
	if name == "" {
		sendToast(w, "Prune failed: repo required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	apply := r.FormValue("apply") == "1"
	resp, err := s.grpc.PruneBackupRepo(s.uiBearerCtx(r), &pb.PruneBackupRepoRequest{
		Repo:        name,
		KeepLast:    atoi32(r.FormValue("keep_last")),
		KeepDaily:   atoi32(r.FormValue("keep_daily")),
		KeepWeekly:  atoi32(r.FormValue("keep_weekly")),
		KeepMonthly: atoi32(r.FormValue("keep_monthly")),
		KeepYearly:  atoi32(r.FormValue("keep_yearly")),
		Apply:       apply,
	})
	if err != nil {
		sendToast(w, "Prune failed: "+err.Error(), "error")
		w.WriteHeader(httpStatusFor(err))
		return
	}
	if !apply {
		// Preview: render the plan for confirmation.
		s.renderFragment(w, "repo_prune_preview.html", map[string]any{
			"Repo": name, "Keep": resp.GetKeep(), "Delete": resp.GetDelete(), "Policy": r.Form,
		})
		return
	}
	sendToast(w, fmt.Sprintf("Pruned %s: kept %d, deleted %d manifests (run GC to reclaim space)", name, len(resp.GetKeep()), len(resp.GetDelete())), "success")
	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}
