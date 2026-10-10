package grpcapi

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/filerestore"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Single-file restore (docs/design/backup-file-restore.md).
//
// The RPCs authorize exactly as a full restore of the same VM or container
// does (authorizeVMRestore / authorizeContainerRestore: the backup's own
// project, backup.restore), and then hand the backup — served read-only from
// the repo over NBD — to a throwaway restore VM. The host never mounts or
// parses the backed-up filesystem; it validates what the VM returns.

// fileRestoreConn is one restore VM session.
type fileRestoreConn interface {
	List(path string) ([]filerestore.Entry, bool, int, error)
	Tar(dst io.Writer, paths []string, lim filerestore.TarLimits) (filerestore.TarStats, error)
	Broken() bool
	Close()
}

// fileRestorer starts restore VM sessions. Production: *filerestore.Launcher.
type fileRestorer interface {
	Preflight() error
	Open(ctx context.Context, dev filerestore.BlockDevice, kind, format string) (fileRestoreConn, error)
}

// launcherAdapter adapts *filerestore.Launcher to fileRestorer.
type launcherAdapter struct{ l *filerestore.Launcher }

func (a launcherAdapter) Preflight() error { return a.l.Preflight() }
func (a launcherAdapter) Open(ctx context.Context, dev filerestore.BlockDevice, kind, format string) (fileRestoreConn, error) {
	s, err := a.l.Open(ctx, dev, kind, format)
	if err != nil {
		return nil, err
	}
	return s, nil
}

// FileRestoreOptions configures single-file restore on this daemon.
type FileRestoreOptions struct {
	Launcher        *filerestore.Launcher
	IdleTimeout     time.Duration // a browsing session's restore VM is killed after this long unused
	MaxSessions     int           // restore VMs at once on this host (browsing and extracting)
	MaxExtractions  int           // extractions at once on this host
	MaxExtractBytes int64         // per extraction
}

// SetFileRestore enables single-file restore. Without it the RPCs refuse
// with FailedPrecondition.
func (s *Server) SetFileRestore(o FileRestoreOptions) {
	var fr fileRestorer
	if o.Launcher != nil {
		fr = launcherAdapter{o.Launcher}
	}
	s.setFileRestorer(fr, o)
}

func (s *Server) setFileRestorer(fr fileRestorer, o FileRestoreOptions) {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	if o.MaxSessions <= 0 {
		o.MaxSessions = 2
	}
	if o.MaxExtractions <= 0 {
		o.MaxExtractions = 1
	}
	if o.MaxExtractBytes <= 0 {
		o.MaxExtractBytes = filerestore.DefaultMaxBytes
	}
	s.fileRestore.mu.Lock()
	s.fileRestore.fr = fr
	s.fileRestore.opts = o
	if s.fileRestore.m == nil {
		s.fileRestore.m = map[frKey]*frEntry{}
	}
	s.fileRestore.mu.Unlock()
}

type frKey struct{ repo, name, disk, ts string }

// frEntry is a cached browsing session. ready is closed once the boot ends;
// conn is nil if it failed (err says why).
type frEntry struct {
	ready chan struct{}
	conn  fileRestoreConn
	err   error
	last  time.Time
	busy  int
}

// fileRestoreSessions holds the restore VMs of this host:
//   - browsing sessions, cached per backup, so listing a directory and then
//     its subdirectories boots once; killed after IdleTimeout unused;
//   - extractions, each on a fresh VM of its own that is killed when it
//     completes (never a cached one: another caller may be browsing it).
//
// Slots (MaxSessions in all, MaxExtractions of them extracting) are reserved
// before a boot and released if it fails; no lock is held while a VM boots.
type fileRestoreSessions struct {
	mu         sync.Mutex
	fr         fileRestorer
	opts       FileRestoreOptions
	m          map[frKey]*frEntry
	booting    int // slots reserved by boots in progress (browse)
	extracting int // extraction sessions running or booting
	reaper     bool
}

// used is the number of restore VM slots taken. Caller holds mu.
func (fs *fileRestoreSessions) used() int {
	return len(fs.m) + fs.booting + fs.extracting
}

// fileRestoreTarget is a resolved, authorized backup to read files from.
type fileRestoreTarget struct {
	key      frKey
	repo     *pbsstore.Repo
	manifest *pbsstore.Manifest
	project  string
	kind     string // filerestore.KindFS / KindArchive
	format   string // raw / qcow2
	isCT     bool
}

// resolveFileRestoreTarget opens the backup, authorizes the caller as for a
// full restore, and decides how the restore VM reads it.
func (s *Server) resolveFileRestoreTarget(ctx context.Context, repoRef, name, disk, ts string) (*fileRestoreTarget, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	if repoRef == "" || name == "" || ts == "" {
		return nil, status.Error(codes.InvalidArgument, "repo_path, name and timestamp are required")
	}
	if disk == "" {
		disk = "root"
	}
	repoPath, err := s.resolveBackupRepoPath(ctx, repoRef)
	if err != nil {
		return nil, err
	}
	repo, err := pbsstore.Open(repoPath)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "open repo: %v", err)
	}
	m, err := repo.GetManifest(name, ts, disk)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "manifest: %v", err)
	}
	t := &fileRestoreTarget{key: frKey{repoPath, name, disk, ts}, repo: repo, manifest: m}
	if m.ContainerSpecJSON != "" {
		t.isCT = true
		if t.project, err = s.authorizeContainerRestore(ctx, name, m); err != nil {
			return nil, err
		}
		t.kind, t.format = filerestore.KindArchive, "raw"
		return t, nil
	}
	if t.project, err = s.authorizeVMRestore(ctx, name, m); err != nil {
		return nil, err
	}
	t.kind = filerestore.KindFS
	format, err := backupContentFormat(m)
	if err != nil {
		return nil, err
	}
	switch format {
	case pbsstore.ContentGuestRaw:
		t.format = "raw"
	case pbsstore.ContentDiskFile:
		if err := diskFileReadable(repo, m); err != nil {
			return nil, err
		}
		t.format = "qcow2"
	default:
		return nil, status.Errorf(codes.FailedPrecondition, "backup content format %q cannot be browsed", format)
	}
	return t, nil
}

// diskFileReadable admits a disk-file backup (a stopped VM's image file)
// only when the restore VM's qemu can read it without opening anything the
// header names: a standalone qcow2. An overlay backup holds only the delta
// over its base, so its files cannot be read from it alone.
func diskFileReadable(repo *pbsstore.Repo, m *pbsstore.Manifest) error {
	if m.BaseIdentity != nil {
		return status.Error(codes.FailedPrecondition,
			"this backup is an overlay's delta over its base image; files cannot be read from it alone — restore the disk instead (lv backup restore-from)")
	}
	r, err := pbsstore.NewManifestReader(repo, m)
	if err != nil {
		return status.Errorf(codes.Internal, "read backup: %v", err)
	}
	head := make([]byte, 64<<10)
	n, err := r.ReadAt(head, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return status.Errorf(codes.Internal, "read backup header: %v", err)
	}
	head = head[:n]
	if len(head) < 4 || binary.BigEndian.Uint32(head[:4]) != qcow2.Magic {
		return status.Error(codes.FailedPrecondition, "this disk-file backup is not a qcow2 image; files cannot be read from it — restore the disk instead")
	}
	if err := qcow2.AssertStandaloneHeader(head); err != nil {
		return status.Errorf(codes.FailedPrecondition, "files cannot be read from this backup: %v — restore the disk instead", err)
	}
	return nil
}

// fileRestorePreflight refuses, naming the cause, when this host cannot run
// a restore VM.
func (s *Server) fileRestorePreflight() (fileRestorer, FileRestoreOptions, error) {
	s.fileRestore.mu.Lock()
	fr, opts := s.fileRestore.fr, s.fileRestore.opts
	s.fileRestore.mu.Unlock()
	if fr == nil {
		return nil, opts, status.Error(codes.FailedPrecondition,
			"file restore is not available on this daemon (no restore VM support); a full restore still works")
	}
	if err := fr.Preflight(); err != nil {
		return nil, opts, status.Errorf(codes.FailedPrecondition, "%v; a full restore still works", err)
	}
	return fr, opts, nil
}

func (s *Server) slotsExhausted(n int, opts FileRestoreOptions) error {
	return status.Errorf(codes.ResourceExhausted,
		"%d file restore sessions are already open on this host; retry when one ends (idle sessions close after %v)", n, opts.IdleTimeout)
}

func (s *Server) openRestoreVM(ctx context.Context, fr fileRestorer, t *fileRestoreTarget) (fileRestoreConn, error) {
	reader, err := pbsstore.NewManifestReader(t.repo, t.manifest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read backup: %v", err)
	}
	conn, err := fr.Open(ctx, reader, t.kind, t.format)
	if err != nil {
		if errors.Is(err, filerestore.ErrUnavailable) {
			return nil, status.Errorf(codes.FailedPrecondition, "%v; a full restore still works", err)
		}
		return nil, status.Errorf(codes.Internal, "start restore VM: %v", err)
	}
	return conn, nil
}

// acquireBrowse returns the browsing session for t, booting a restore VM
// when there is none. Concurrent callers for the same backup wait for one
// boot. release must be called.
func (s *Server) acquireBrowse(ctx context.Context, t *fileRestoreTarget) (fileRestoreConn, func(), error) {
	fr, opts, err := s.fileRestorePreflight()
	if err != nil {
		return nil, nil, err
	}
	fs := &s.fileRestore
	for {
		fs.mu.Lock()
		e := fs.m[t.key]
		if e != nil {
			select {
			case <-e.ready:
				if e.conn != nil && !e.conn.Broken() {
					e.busy++
					fs.mu.Unlock()
					return e.conn, s.releaseBrowse(t.key, e), nil
				}
				// A failed or broken session: drop it and boot afresh.
				delete(fs.m, t.key)
				if e.conn != nil && e.busy == 0 {
					go e.conn.Close()
				}
				fs.mu.Unlock()
				continue
			default:
				fs.mu.Unlock()
				select {
				case <-e.ready:
					continue
				case <-ctx.Done():
					return nil, nil, ctx.Err()
				}
			}
		}
		if n := fs.used(); n >= opts.MaxSessions {
			fs.mu.Unlock()
			return nil, nil, s.slotsExhausted(n, opts)
		}
		e = &frEntry{ready: make(chan struct{}), busy: 1}
		fs.m[t.key] = e
		if !fs.reaper {
			fs.reaper = true
			go s.reapFileRestore()
		}
		fs.mu.Unlock()

		conn, oerr := s.openRestoreVM(ctx, fr, t)
		fs.mu.Lock()
		e.conn, e.err, e.last = conn, oerr, time.Now()
		if oerr != nil {
			if fs.m[t.key] == e {
				delete(fs.m, t.key)
			}
		}
		close(e.ready)
		fs.mu.Unlock()
		if oerr != nil {
			return nil, nil, oerr
		}
		return conn, s.releaseBrowse(t.key, e), nil
	}
}

func (s *Server) releaseBrowse(key frKey, e *frEntry) func() {
	fs := &s.fileRestore
	var once sync.Once
	return func() {
		once.Do(func() {
			fs.mu.Lock()
			e.busy--
			e.last = time.Now()
			drop := e.conn.Broken() && e.busy == 0
			if drop && fs.m[key] == e {
				delete(fs.m, key)
			}
			fs.mu.Unlock()
			if drop {
				e.conn.Close()
			}
		})
	}
}

// acquireExtraction boots a restore VM of its own for one extraction. The
// returned release kills it.
func (s *Server) acquireExtraction(ctx context.Context, t *fileRestoreTarget) (fileRestoreConn, func(), error) {
	fr, opts, err := s.fileRestorePreflight()
	if err != nil {
		return nil, nil, err
	}
	fs := &s.fileRestore
	fs.mu.Lock()
	if fs.extracting >= opts.MaxExtractions {
		n := fs.extracting
		fs.mu.Unlock()
		return nil, nil, status.Errorf(codes.ResourceExhausted,
			"%d file restore extractions are already running on this host (file_restore.max_extractions); retry when one ends", n)
	}
	if n := fs.used(); n >= opts.MaxSessions {
		fs.mu.Unlock()
		return nil, nil, s.slotsExhausted(n, opts)
	}
	fs.extracting++
	fs.mu.Unlock()
	free := func() {
		fs.mu.Lock()
		fs.extracting--
		fs.mu.Unlock()
	}
	conn, err := s.openRestoreVM(ctx, fr, t)
	if err != nil {
		free()
		return nil, nil, err
	}
	var once sync.Once
	return conn, func() {
		once.Do(func() {
			conn.Close()
			free()
		})
	}, nil
}

// reapFileRestore kills browsing restore VMs idle longer than the idle
// timeout.
func (s *Server) reapFileRestore() {
	fs := &s.fileRestore
	for {
		fs.mu.Lock()
		timeout := fs.opts.IdleTimeout
		fs.mu.Unlock()
		tick := timeout / 4
		if tick < time.Second {
			tick = time.Second
		}
		if tick > 30*time.Second {
			tick = 30 * time.Second
		}
		time.Sleep(tick)
		s.reapFileRestoreOnce(time.Now())
	}
}

func (s *Server) reapFileRestoreOnce(now time.Time) {
	fs := &s.fileRestore
	var dead []fileRestoreConn
	fs.mu.Lock()
	for k, e := range fs.m {
		select {
		case <-e.ready:
		default:
			continue // still booting
		}
		if e.conn != nil && e.busy == 0 && (e.conn.Broken() || now.Sub(e.last) > fs.opts.IdleTimeout) {
			dead = append(dead, e.conn)
			delete(fs.m, k)
		}
	}
	fs.mu.Unlock()
	for _, c := range dead {
		c.Close()
	}
}

// ListBackupFiles lists a directory inside a backup.
func (s *Server) ListBackupFiles(ctx context.Context, req *pb.ListBackupFilesRequest) (*pb.ListBackupFilesResponse, error) {
	p, err := filerestore.CleanArchivePath(req.Path)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	t, err := s.resolveFileRestoreTarget(ctx, req.RepoPath, req.Name, req.DiskName, req.Timestamp)
	if err != nil {
		return nil, err
	}
	conn, release, err := s.acquireBrowse(ctx, t)
	if err != nil {
		return nil, err
	}
	defer release()
	entries, truncated, skipped, err := conn.List(p)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "list %s: %v", p, err)
	}
	out := &pb.ListBackupFilesResponse{Path: p, Truncated: truncated, Skipped: int32(skipped)}
	for _, e := range entries {
		out.Entries = append(out.Entries, &pb.BackupFileEntry{
			Name: e.Name, Type: e.Type, Size: e.Size, Mode: e.Mode, MtimeUnix: e.MTime, LinkTarget: e.Target,
		})
	}
	return out, nil
}

// chunkWriter turns the sanitized archive into stream frames.
type chunkWriter struct {
	send func(*pb.RestoreBackupFilesChunk) error
	buf  []byte
}

const restoreFilesFrame = 256 << 10

func (w *chunkWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		room := restoreFilesFrame - len(w.buf)
		take := len(p)
		if take > room {
			take = room
		}
		w.buf = append(w.buf, p[:take]...)
		p = p[take:]
		if len(w.buf) == restoreFilesFrame {
			if err := w.flush(); err != nil {
				return 0, err
			}
		}
	}
	return n, nil
}

func (w *chunkWriter) flush() error {
	if len(w.buf) == 0 {
		return nil
	}
	err := w.send(&pb.RestoreBackupFilesChunk{Data: w.buf})
	w.buf = make([]byte, 0, restoreFilesFrame)
	return err
}

// RestoreBackupFiles streams a tar archive of the selected paths out of a
// backup. The archive is rebuilt by the host from the restore VM's output
// (filerestore.SanitizeStream) and goes only to the caller.
func (s *Server) RestoreBackupFiles(req *pb.RestoreBackupFilesRequest, stream grpc.ServerStreamingServer[pb.RestoreBackupFilesChunk]) (retErr error) {
	ctx := stream.Context()
	if _, err := filerestore.SelectionNames(req.Paths); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	t, err := s.resolveFileRestoreTarget(ctx, req.RepoPath, req.Name, req.DiskName, req.Timestamp)
	if err != nil {
		if status.Code(err) == codes.PermissionDenied {
			s.audit(ctx, "backup.file_restore", req.Name, fileRestoreAuditDetail(req, "", nil), "denied")
		}
		return err
	}
	var st filerestore.TarStats
	defer func() {
		outcome := "ok"
		if retErr != nil {
			outcome = "error"
		}
		s.audit(ctx, "backup.file_restore", req.Name, fileRestoreAuditDetail(req, t.project, &st), outcome)
	}()
	_, opts, err := s.fileRestorePreflight()
	if err != nil {
		return err
	}
	lim := filerestore.TarLimits{MaxBytes: opts.MaxExtractBytes}
	if req.MaxBytes > 0 && req.MaxBytes < lim.MaxBytes {
		lim.MaxBytes = req.MaxBytes
	}
	conn, release, err := s.acquireExtraction(ctx, t)
	if err != nil {
		return err
	}
	// An extraction runs on a VM of its own, killed on completion — and at
	// once if the caller goes away or the extraction outlives its wall
	// clock, which also ends a read the agent is stalling.
	defer release()
	wall := extractWallClock(lim.MaxBytes)
	if extractWallClockOverride > 0 {
		wall = extractWallClockOverride
	}
	ectx, cancel := context.WithTimeout(ctx, wall)
	defer cancel()
	stop := context.AfterFunc(ectx, conn.Close)
	defer stop()
	w := &chunkWriter{send: stream.Send, buf: make([]byte, 0, restoreFilesFrame)}
	st, err = conn.Tar(w, req.Paths, lim)
	if err != nil && !errors.Is(err, filerestore.ErrLimit) {
		if errors.Is(ectx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return status.Errorf(codes.DeadlineExceeded, "extract: stopped after %v (the extraction's wall-clock limit); select less", wall)
		}
		return status.Errorf(codes.FailedPrecondition, "extract: %v", err)
	}
	if ferr := w.flush(); ferr != nil {
		return ferr
	}
	msg := fmt.Sprintf("%d entries, %d bytes", st.Entries, st.Bytes)
	if st.Truncated {
		msg += fmt.Sprintf("; stopped at the %d-byte extraction limit — select less", lim.MaxBytes)
	}
	if st.Skipped > 0 {
		msg += fmt.Sprintf("; %d entries left out (unsafe names, links or types)", st.Skipped)
	}
	slog.Info("file restore: extracted", "name", req.Name, "ts", req.Timestamp, "entries", st.Entries, "bytes", st.Bytes)
	return stream.Send(&pb.RestoreBackupFilesChunk{
		Done: true, Entries: int32(st.Entries), Bytes: st.Bytes, Skipped: int32(st.Skipped),
		Truncated: st.Truncated, Status: msg,
	})
}

// extractWallClock bounds one extraction's total time: ten minutes, or the
// byte limit at 1 MiB/s if that is longer. The progress deadline alone
// would let an agent trickling a byte a minute hold a slot forever.
func extractWallClock(maxBytes int64) time.Duration {
	d := time.Duration(maxBytes/(1<<20)) * time.Second
	if d < 10*time.Minute {
		d = 10 * time.Minute
	}
	return d
}

// extractWallClockOverride, when set, replaces extractWallClock (tests).
var extractWallClockOverride time.Duration

func fileRestoreAuditDetail(req *pb.RestoreBackupFilesRequest, project string, st *filerestore.TarStats) string {
	paths := strings.Join(req.Paths, ",")
	if len(paths) > 512 {
		paths = paths[:512] + "…"
	}
	d := fmt.Sprintf("repo=%s ts=%s disk=%s paths=%s", req.RepoPath, req.Timestamp, req.DiskName, paths)
	if project != "" {
		d = "project=" + project + " " + d
	}
	if st != nil {
		d += fmt.Sprintf(" entries=%d bytes=%d skipped=%d truncated=%v", st.Entries, st.Bytes, st.Skipped, st.Truncated)
	}
	return d
}
