package ui

import (
	"log/slog"
	"net/http"
	"sort"

	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// handleBackups renders /backups. Two modes:
//
//   - With ?repo=<name>: list that repo's snapshots. An absolute path also
//     works, for an admin only.
//   - Without ?repo=: enumerate the daemon's configured `backup_repos:`
//     map (set via SetBackupRepos at startup) and render each repo's
//     snapshot count + total size.
//
// Both list through the daemon's ListBackupRepoSnapshots with the session's
// bearer, so the daemon decides: backup.read at `/`, and a custom absolute
// path only for an admin. This page used to open ?repo= in-process behind
// nothing but a session, so any viewer could probe the host's filesystem by
// path and read every project's snapshot list.
//
// Failures are surfaced per-repo so a single broken or forbidden repo doesn't
// blank the whole page.
func (s *Server) handleBackups(w http.ResponseWriter, r *http.Request) {
	data := s.pageData("Backups", "backups")
	repoName := r.URL.Query().Get("repo")
	data["RepoPath"] = repoName

	if repoName != "" {
		s.renderBackupsForRepo(w, r, data, repoName)
		return
	}

	if len(s.backupRepos) == 0 {
		data["Hint"] = "No repos configured. Add a `backup_repos:` block to /etc/litevirt/config.yaml or append ?repo=<path> to this URL."
		s.renderPage(w, "backups.html", data)
		return
	}

	type repoEntry struct {
		Name       string
		Path       string
		Encryption string
		Count      int
		TotalBytes int64
		Error      string
	}

	names := make([]string, 0, len(s.backupRepos))
	for name := range s.backupRepos {
		names = append(names, name)
	}
	sort.Strings(names)

	ctx := s.uiBearerCtx(r)
	entries := make([]repoEntry, 0, len(names))
	for _, name := range names {
		entry := repoEntry{Name: name, Path: s.backupRepos[name]}
		resp, err := s.grpc.ListBackupRepoSnapshots(ctx, &pb.ListBackupRepoSnapshotsRequest{Repo: name})
		if err != nil {
			slog.Info("ui: list backup repo", "name", name, "error", err)
			entry.Error = status.Convert(err).Message()
			entries = append(entries, entry)
			continue
		}
		entry.Encryption = resp.GetEncryption()
		entry.Count = len(resp.GetSnapshots())
		for _, m := range resp.GetSnapshots() {
			entry.TotalBytes += m.GetTotalSize()
		}
		entries = append(entries, entry)
	}
	data["Repos"] = entries
	s.renderPage(w, "backups.html", data)
}

// renderBackupsForRepo handles the single-repo ?repo= view.
func (s *Server) renderBackupsForRepo(w http.ResponseWriter, r *http.Request, data map[string]any, repoName string) {
	resp, err := s.grpc.ListBackupRepoSnapshots(s.uiBearerCtx(r), &pb.ListBackupRepoSnapshotsRequest{Repo: repoName})
	if err != nil {
		slog.Info("ui: list backup repo", "repo", repoName, "error", err)
		data["Error"] = status.Convert(err).Message()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(httpStatusFor(err))
		s.renderPage(w, "backups.html", data)
		return
	}
	data["Encryption"] = resp.GetEncryption()
	data["Manifests"] = resp.GetSnapshots()
	s.renderPage(w, "backups.html", data)
}
