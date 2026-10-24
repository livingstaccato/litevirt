package ui

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// backupOpState tracks the progress of an in-flight PBS-style backup,
// restore, or live-restore for HTMX polling. One struct serves all three;
// only the relevant counters are populated per kind.
//
// The op's goroutine writes while the poll handlers and backupInFlight read,
// so every access goes through update / snapshot; the data fields are never
// touched directly after the state is stored.
type backupOpState struct {
	mu sync.Mutex
	backupOpData
}

// backupOpData is the progress a poll renders; the template reads it from a
// snapshot, never from the live state.
type backupOpData struct {
	Kind           string // "backup" | "restore" | "restore-live"
	VMName         string
	Repo           string
	Phase          string
	Status         string
	BytesProcessed int64
	BytesRead      int64
	BytesWritten   int64
	ChunksTotal    int32
	ChunksDeduped  int32
	ChunksDone     int32
	ManifestTS     string
	NBDURL         string
	TargetPath     string
	PollURL        string // HTMX self-poll endpoint for the progress partial
	Error          string
	Done           bool
}

// update applies fn to the progress under the lock.
func (st *backupOpState) update(fn func(d *backupOpData)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	fn(&st.backupOpData)
}

// snapshot returns a consistent copy of the progress for rendering.
func (st *backupOpState) snapshot() *backupOpData {
	st.mu.Lock()
	defer st.mu.Unlock()
	d := st.backupOpData
	return &d
}

// repoNames returns the configured backup-repo names, sorted, for dropdowns.
func (s *Server) repoNames() []string {
	out := make([]string, 0, len(s.backupRepos))
	for name := range s.backupRepos {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// resolveRepoPath maps a logical repo name to its on-disk path. If the value
// is already an absolute path (manual entry) it's returned as-is.
func (s *Server) resolveRepoPath(repo string) string {
	if p, ok := s.backupRepos[repo]; ok {
		return p
	}
	return repo
}

// ── C1: create backup (BackupSnapshot) ───────────────────────────────────────

// handleBackupModal renders the "Create backup" modal for a VM: repo select,
// optional disk, incremental toggle. Replaces the old raw-disk download.
func (s *Server) handleBackupModal(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var disks []string
	if vm, err := s.grpc.InspectVM(s.uiBearerCtx(r), &pb.InspectVMRequest{Name: name}); err == nil {
		for _, d := range vm.GetDisks() {
			disks = append(disks, d.GetName())
		}
	}
	s.renderFragment(w, "backup_create_modal.html", map[string]any{
		"VMName": name,
		"Disks":  disks,
		"Repos":  s.repoNames(),
	})
}

// handleCreateBackupSnapshot kicks off a deduplicated BackupSnapshot to a repo
// in the background and returns the progress panel for polling. Mirrors
// `lv backup snapshot <vm> --repo … [--incremental]`.
func (s *Server) handleCreateBackupSnapshot(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	repo := strings.TrimSpace(r.FormValue("repo"))
	if repo == "" {
		sendToast(w, "A repo is required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	disk := strings.TrimSpace(r.FormValue("disk"))
	incremental := r.FormValue("incremental") == "on"
	quiesce := "auto"
	if r.FormValue("no_quiesce") == "on" {
		quiesce = "off"
	}
	repoPath := s.resolveRepoPath(repo)

	st := &backupOpState{backupOpData: backupOpData{Kind: "backup", VMName: name, Repo: repo, Phase: "SNAPSHOT", Status: "Starting backup…",
		PollURL: "/ui/vms/" + name + "/backup-progress"}}
	s.backupOps.Store(backupOpKey("backup", name), st)

	// Detached from the request (survives the handler returning) but still
	// carries the operator's session bearer, so the daemon authorizes the op
	// as them rather than falling through to the host-cert admin identity.
	opCtx := context.WithoutCancel(s.uiBearerCtx(r))
	go func() {
		defer st.update(func(d *backupOpData) { d.Done = true })
		stream, err := s.grpc.BackupSnapshot(opCtx, &pb.BackupSnapshotRequest{
			VmName:      name,
			DiskName:    disk,
			RepoPath:    repoPath,
			Incremental: incremental,
			Quiesce:     quiesce,
		})
		if err != nil {
			st.update(func(d *backupOpData) {
				d.Error = err.Error()
				d.Status = "Backup failed"
			})
			return
		}
		for {
			prog, recvErr := stream.Recv()
			if recvErr != nil {
				st.update(func(d *backupOpData) {
					if !isEOF(recvErr) {
						d.Error = recvErr.Error()
						d.Status = "Backup failed"
					} else if d.Error == "" {
						d.Status = "Backup complete"
					}
				})
				return
			}
			st.update(func(d *backupOpData) {
				d.Phase = prog.Phase.String()
				d.Status = prog.Status
				d.BytesProcessed = prog.BytesProcessed
				d.BytesRead = prog.BytesRead
				d.ChunksTotal = prog.ChunksTotal
				d.ChunksDeduped = prog.ChunksDeduped
				if prog.ManifestTs != "" {
					d.ManifestTS = prog.ManifestTs
				}
				if prog.Error != "" {
					d.Error = prog.Error
					d.Status = "Backup failed"
				}
			})
		}
	}()

	s.renderFragment(w, "backup_progress.html", st.snapshot())
}

// handleBackupProgress returns the current backup progress for HTMX polling.
func (s *Server) handleBackupProgress(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	val, ok := s.backupOps.Load(backupOpKey("backup", name))
	if !ok {
		w.Header().Set("HX-Redirect", "/vms/"+name)
		w.WriteHeader(http.StatusOK)
		return
	}
	s.renderFragment(w, "backup_progress.html", val.(*backupOpState).snapshot())
}

// ── C3: restore (RestoreFromBackup) and live restore (RestoreLive) ────────────

// handleRestoreFromModal renders the per-manifest "Restore" modal.
func (s *Server) handleRestoreFromModal(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.renderFragment(w, "backup_restore_from_modal.html", map[string]any{
		"RepoPath":  q.Get("repo"),
		"VMName":    q.Get("vm"),
		"DiskName":  q.Get("disk"),
		"Timestamp": q.Get("ts"),
	})
}

// handleRestoreFrom runs RestoreFromBackup into a target path in the background.
func (s *Server) handleRestoreFrom(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	repoPath := strings.TrimSpace(r.FormValue("repo_path"))
	vm := strings.TrimSpace(r.FormValue("vm_name"))
	disk := strings.TrimSpace(r.FormValue("disk_name"))
	ts := strings.TrimSpace(r.FormValue("timestamp"))
	target := strings.TrimSpace(r.FormValue("target_path"))
	inPlace := r.FormValue("in_place") == "on"
	if repoPath == "" || vm == "" || ts == "" {
		sendToast(w, "repo, vm and timestamp are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	opID := restoreOpID(vm, disk, ts)
	st := &backupOpState{backupOpData: backupOpData{Kind: "restore", VMName: vm, Phase: "RESTORE", Status: "Starting restore…", TargetPath: target,
		PollURL: "/ui/backups/op-progress?id=" + url.QueryEscape(opID)}}
	s.backupOps.Store(opID, st)

	opCtx := context.WithoutCancel(s.uiBearerCtx(r))
	go func() {
		defer st.update(func(d *backupOpData) { d.Done = true })
		stream, err := s.grpc.RestoreFromBackup(opCtx, &pb.RestoreFromBackupRequest{
			RepoPath: repoPath, VmName: vm, DiskName: disk, Timestamp: ts, TargetPath: target,
			InPlace: inPlace,
		})
		if err != nil {
			st.update(func(d *backupOpData) {
				d.Error = err.Error()
				d.Status = "Restore failed"
			})
			return
		}
		for {
			prog, recvErr := stream.Recv()
			if recvErr != nil {
				st.update(func(d *backupOpData) {
					if !isEOF(recvErr) {
						d.Error = recvErr.Error()
						d.Status = "Restore failed"
					} else if d.Error == "" {
						d.Status = "Restore complete"
					}
				})
				return
			}
			st.update(func(d *backupOpData) {
				d.Phase = prog.Phase.String()
				d.Status = prog.Status
				d.BytesWritten = prog.BytesWritten
				d.ChunksDone = prog.ChunksDone
				d.ChunksTotal = prog.ChunksTotal
				if prog.TargetPath != "" {
					d.TargetPath = prog.TargetPath
				}
				if prog.Error != "" {
					d.Error = prog.Error
					d.Status = "Restore failed"
				}
			})
		}
	}()

	s.renderFragment(w, "backup_progress.html", st.snapshot())
}

// handleRestoreLiveModal renders the live-restore (NBD overlay) modal.
func (s *Server) handleRestoreLiveModal(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.renderFragment(w, "restore_live_modal.html", map[string]any{
		"RepoPath":  q.Get("repo"),
		"VMName":    q.Get("vm"),
		"DiskName":  q.Get("disk"),
		"Timestamp": q.Get("ts"),
	})
}

// handleRestoreLive runs RestoreLive (NBD server + qcow2 overlay) in the
// background. With auto_start+blockpull it self-terminates; otherwise the
// stream stays open and the progress panel surfaces the NBD URL.
func (s *Server) handleRestoreLive(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	repoPath := strings.TrimSpace(r.FormValue("repo_path"))
	vm := strings.TrimSpace(r.FormValue("vm_name"))
	disk := strings.TrimSpace(r.FormValue("disk_name"))
	ts := strings.TrimSpace(r.FormValue("timestamp"))
	target := strings.TrimSpace(r.FormValue("target_path"))
	if repoPath == "" || vm == "" || ts == "" {
		sendToast(w, "repo, vm and timestamp are required", "error")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	opID := restoreOpID(vm, disk, ts) + ":live"
	st := &backupOpState{backupOpData: backupOpData{Kind: "restore-live", VMName: vm, Phase: "STARTING_NBD", Status: "Starting NBD overlay…", TargetPath: target,
		PollURL: "/ui/backups/op-progress?id=" + url.QueryEscape(opID)}}
	s.backupOps.Store(opID, st)

	opCtx := context.WithoutCancel(s.uiBearerCtx(r))
	go func() {
		defer st.update(func(d *backupOpData) { d.Done = true })
		stream, err := s.grpc.RestoreLive(opCtx, &pb.RestoreLiveRequest{
			RepoPath:   repoPath,
			VmName:     vm,
			DiskName:   disk,
			Timestamp:  ts,
			TargetPath: target,
			NewName:    strings.TrimSpace(r.FormValue("new_name")),
			AutoStart:  r.FormValue("auto_start") == "on",
			Blockpull:  r.FormValue("blockpull") == "on",
			// Meaningful only with auto_start; the daemon refuses it alone.
			WithoutDevices: r.FormValue("auto_start") == "on" && r.FormValue("without_devices") == "on",
		})
		if err != nil {
			st.update(func(d *backupOpData) {
				d.Error = err.Error()
				d.Status = "Live restore failed"
			})
			return
		}
		for {
			prog, recvErr := stream.Recv()
			if recvErr != nil {
				st.update(func(d *backupOpData) {
					if !isEOF(recvErr) {
						d.Error = recvErr.Error()
						d.Status = "Live restore failed"
					} else if d.Error == "" {
						d.Status = "Live restore finished"
					}
				})
				return
			}
			st.update(func(d *backupOpData) {
				d.Phase = prog.Phase.String()
				d.Status = prog.Status
				if prog.NbdUrl != "" {
					d.NBDURL = prog.NbdUrl
				}
				if prog.TargetPath != "" {
					d.TargetPath = prog.TargetPath
				}
			})
		}
	}()

	s.renderFragment(w, "backup_progress.html", st.snapshot())
}

// handleRestoreProgress polls restore / live-restore progress by op id.
func (s *Server) handleRestoreProgress(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	val, ok := s.backupOps.Load(id)
	if !ok {
		w.Header().Set("HX-Refresh", "true")
		w.WriteHeader(http.StatusOK)
		return
	}
	s.renderFragment(w, "backup_progress.html", val.(*backupOpState).snapshot())
}

// vmBackupRow is one PBS manifest for a VM, surfaced on the VM detail page.
type vmBackupRow struct {
	RepoName    string
	RepoPath    string
	Timestamp   string
	DiskName    string
	TotalSize   int64
	Incremental bool
}

// vmBackupManifests returns this VM's snapshots across all configured repos,
// newest first. Best-effort: an unreadable repo is skipped, not fatal.
func (s *Server) vmBackupManifests(vm string) []vmBackupRow {
	var out []vmBackupRow
	for _, name := range s.repoNames() {
		path := s.backupRepos[name]
		repo, err := pbsstore.Open(path)
		if err != nil {
			continue
		}
		manifests, err := repo.ListManifests()
		if err != nil {
			continue
		}
		for _, m := range manifests {
			if m.VMName != vm {
				continue
			}
			out = append(out, vmBackupRow{
				RepoName: name, RepoPath: path,
				Timestamp: m.Timestamp, DiskName: m.DiskName,
				TotalSize: m.TotalSize, Incremental: m.BasedOn != "",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Timestamp > out[j].Timestamp })
	return out
}

func backupOpKey(kind, vm string) string { return kind + ":" + vm }

func restoreOpID(vm, disk, ts string) string {
	return "restore:" + vm + ":" + disk + ":" + ts
}

func isEOF(err error) bool {
	return err != nil && (err == io.EOF || err.Error() == "EOF")
}
