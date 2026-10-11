package grpcapi

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/filerestore"
	"github.com/litevirt/litevirt/internal/filerestore/filerestoretest"
	"github.com/litevirt/litevirt/internal/pbsstore"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// fakeRestorer stands in for restore VMs: it serves the real agent protocol
// in-process (filerestore.InProcessSession) — a container archive parsed from
// the backup's own bytes, or for a VM disk a directory standing in for its
// mounted filesystem.
type fakeRestorer struct {
	mu           sync.Mutex
	preflight    error
	dir          string
	opens        int
	closes       int
	kind, format string
	// barriers / reduced: what the fake restore VM reports isolated it.
	barriers string
	reduced  bool
}

func (f *fakeRestorer) Preflight() error { return f.preflight }

func (f *fakeRestorer) Open(_ context.Context, dev filerestore.BlockDevice, kind, format string) (fileRestoreConn, error) {
	f.mu.Lock()
	f.opens++
	f.kind, f.format = kind, format
	f.mu.Unlock()
	s, err := filerestoretest.Open(dev, kind, f.dir)
	if err != nil {
		return nil, err
	}
	return &countingConn{Session: s, f: f}, nil
}

func (f *fakeRestorer) counts() (int, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.opens, f.closes
}

type countingConn struct {
	*filerestoretest.Session
	f    *fakeRestorer
	once sync.Once
}

func (c *countingConn) FileRestoreBarriers() (string, bool) {
	c.f.mu.Lock()
	defer c.f.mu.Unlock()
	return c.f.barriers, c.f.reduced
}

func (c *countingConn) Close() {
	c.once.Do(func() {
		c.Session.Close()
		c.f.mu.Lock()
		c.f.closes++
		c.f.mu.Unlock()
	})
}

func guestDir(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	if err := os.MkdirAll(filepath.Join(d, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "etc", "hostname"), []byte("web\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return d
}

// ctBackup pushes a container archive (the shape lxc's export writes) of
// container "box" in project "a" and returns the repo dir.
func ctBackup(t *testing.T, s *Server, ts string) string {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, e := range []struct{ name, body string }{
		{"box/config", "lxc.rootfs.path = /x\n"},
		{"box/rootfs/etc/hostname", "box\n"},
		{"box/rootfs/root/notes.txt", "remember the milk\n"},
	} {
		_ = tw.WriteHeader(&tar.Header{Name: e.name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(e.body)), ModTime: time.Unix(1700000000, 0)})
		_, _ = tw.Write([]byte(e.body))
	}
	_ = tw.Close()
	repoDir := filepath.Join(t.TempDir(), "ctrepo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(containerBackupSpec{Name: "box", Project: "a"})
	if _, err := pbsstore.PushDisk(context.Background(), repo, bytes.NewReader(b.Bytes()), pbsstore.PushOptions{
		VMName: "box", DiskName: containerBackupDisk, Timestamp: ts, ContainerSpecJSON: string(spec),
	}); err != nil {
		t.Fatal(err)
	}
	return repoDir
}

func extractTar(t *testing.T, chunks []*pb.RestoreBackupFilesChunk) (map[string]string, *pb.RestoreBackupFilesChunk) {
	t.Helper()
	var data bytes.Buffer
	var done *pb.RestoreBackupFilesChunk
	for _, c := range chunks {
		data.Write(c.Data)
		if c.Done {
			done = c
		}
	}
	out := map[string]string{}
	tr := tar.NewReader(&data)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("extracted archive: %v", err)
		}
		body, _ := io.ReadAll(tr)
		out[h.Name] = string(body)
	}
	return out, done
}

// A container backup browses and extracts end to end: one restore VM serves
// the listings, the extraction ends it, and the extraction is audited.
func TestFileRestore_ContainerBrowseAndExtract(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	const ts = "2026-10-10T01:00:00Z"
	repoDir := ctBackup(t, s, ts)
	s.SetBackupRepos(map[string]string{"r": repoDir})
	fr := &fakeRestorer{}
	s.setFileRestorer(fr, FileRestoreOptions{})
	ctx := adminCtx()

	root, err := s.ListBackupFiles(ctx, &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts})
	if err != nil {
		t.Fatalf("list /: %v", err)
	}
	if len(root.Entries) != 1 || root.Entries[0].Name != "rootfs" {
		t.Fatalf("volumes %v", root.Entries)
	}
	etc, err := s.ListBackupFiles(ctx, &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts, Path: "/rootfs/etc"})
	if err != nil || len(etc.Entries) != 1 || etc.Entries[0].Name != "hostname" {
		t.Fatalf("list /rootfs/etc: %v %v", etc, err)
	}
	if fr.kind != filerestore.KindArchive || fr.format != "raw" {
		t.Errorf("a container backup was opened as %s/%s, want archive/raw", fr.kind, fr.format)
	}
	if o, c := fr.counts(); o != 1 || c != 0 {
		t.Fatalf("after two listings: %d opens, %d closes; want one restore VM, still running", o, c)
	}

	st := &progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx}
	if err := s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
		RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts, Paths: []string{"/rootfs/root/notes.txt"},
	}, st); err != nil {
		t.Fatalf("RestoreBackupFiles: %v", err)
	}
	files, done := extractTar(t, st.Sent)
	if files["rootfs/root/notes.txt"] != "remember the milk\n" || len(files) != 1 {
		t.Fatalf("extracted %v", files)
	}
	if done == nil || done.Entries != 1 || done.Bytes != 18 {
		t.Fatalf("done frame %+v", done)
	}
	// m-3: the extraction ran on a restore VM of its own (never the browsing
	// one another caller may be using), killed on completion.
	if o, c := fr.counts(); o != 2 || c != 1 {
		t.Fatalf("after the extraction: %d opens, %d closes; want the browsing VM kept and the extraction's own VM ended", o, c)
	}
	a := lastAuditRow(t, s, "backup.file_restore")
	if !a.found || a.result != "ok" || a.target != "box" || !strings.Contains(a.detail, "paths=/rootfs/root/notes.txt") ||
		!strings.Contains(a.detail, "project=a") || !strings.Contains(a.detail, "entries=1") {
		t.Fatalf("audit row %+v", a)
	}
}

// File restore takes the same permission as a full restore of the backup's
// project; a refused extraction is audited as denied and boots nothing.
func TestFileRestore_RBAC(t *testing.T) {
	f := newRestoreFixture(t) // project a's VM "web" backed up; alice is Operator on /projects/a
	fr := &fakeRestorer{dir: guestDir(t)}
	f.s.setFileRestorer(fr, FileRestoreOptions{})

	// carol is Operator on another project.
	carol := grantUser(t, f.s, "carol", "/projects/b", "Operator")
	for name, ctx := range map[string]context.Context{"viewer": viewerCtx(), "other project": carol} {
		_, err := f.s.ListBackupFiles(ctx, &pb.ListBackupFilesRequest{RepoPath: "r", Name: "web", DiskName: "root", Timestamp: restoreTS})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: list got %v, want PermissionDenied", name, err)
		}
		err = f.s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
			RepoPath: "r", Name: "web", DiskName: "root", Timestamp: restoreTS, Paths: []string{"/vda1/etc"},
		}, &progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx})
		if status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: extract got %v, want PermissionDenied", name, err)
		}
		if a := lastAuditRow(t, f.s, "backup.file_restore"); a.result != "denied" {
			t.Errorf("%s: refused extraction audited as %+v, want denied", name, a)
		}
	}
	if o, _ := fr.counts(); o != 0 {
		t.Fatalf("a refused caller booted %d restore VMs", o)
	}

	// The project's own operator may.
	st := &progressStream[pb.RestoreBackupFilesChunk]{ctx: f.alice}
	if err := f.s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
		RepoPath: "r", Name: "web", DiskName: "root", Timestamp: restoreTS, Paths: []string{"/vda1/etc/hostname"},
	}, st); err != nil {
		t.Fatalf("project operator: %v", err)
	}
	if files, _ := extractTar(t, st.Sent); files["vda1/etc/hostname"] != "web\n" {
		t.Fatalf("extracted %v", files)
	}
	if a := lastAuditRow(t, f.s, "backup.file_restore"); a.result != "ok" || a.user != "alice" {
		t.Fatalf("audit %+v", a)
	}
	// The fixture's backup is a stopped VM's standalone qcow2 file.
	if fr.kind != filerestore.KindFS || fr.format != "qcow2" {
		t.Errorf("opened as %s/%s, want fs/qcow2", fr.kind, fr.format)
	}
}

// Without restore VM support, file restore is refused naming the cause.
func TestFileRestore_UnavailableNamesTheCause(t *testing.T) {
	f := newRestoreFixture(t)
	req := &pb.ListBackupFilesRequest{RepoPath: "r", Name: "web", DiskName: "root", Timestamp: restoreTS}
	_, err := f.s.ListBackupFiles(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "full restore still works") {
		t.Fatalf("no restorer configured: %v", err)
	}
	fr := &fakeRestorer{preflight: errors.New("file restore unavailable on this host: no usable KVM (/dev/kvm: no such file)")}
	f.s.setFileRestorer(fr, FileRestoreOptions{})
	_, err = f.s.ListBackupFiles(adminCtx(), req)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "/dev/kvm") {
		t.Fatalf("preflight failure: %v", err)
	}
	if o, _ := fr.counts(); o != 0 {
		t.Fatal("a VM was started after a failed preflight")
	}
}

// A disk-file backup is read by qemu as qcow2, so only a standalone image is
// handed to it: one naming a backing file, or an overlay's delta, is refused
// before any VM starts.
func TestFileRestore_DiskFileMustBeStandaloneQcow2(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repoDir := filepath.Join(t.TempDir(), "repo")
	repo, err := pbsstore.Init(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"r": repoDir})
	fr := &fakeRestorer{dir: guestDir(t)}
	s.setFileRestorer(fr, FileRestoreOptions{})
	dir := t.TempDir()
	base := filepath.Join(dir, "base.qcow2")
	over := filepath.Join(dir, "over.qcow2")
	plain := filepath.Join(dir, "raw.img")
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(over, base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plain, bytes.Repeat([]byte{0}, 1<<16), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm"})
	push := func(path, ts string, bi *pbsstore.BaseIdentity) {
		if _, err := pbsstore.PushFile(context.Background(), repo, path, pbsstore.PushOptions{
			VMName: "vm", DiskName: "root", Timestamp: ts, VMSpecJSON: string(spec),
			ContentFormat: pbsstore.ContentDiskFile, BaseIdentity: bi,
		}); err != nil {
			t.Fatal(err)
		}
	}
	push(over, "2026-10-10T01:00:00Z", nil)
	push(plain, "2026-10-10T02:00:00Z", nil)
	push(base, "2026-10-10T03:00:00Z", &pbsstore.BaseIdentity{Path: "/img/base", Size: 1, SHA256: "x"})
	push(base, "2026-10-10T04:00:00Z", nil)
	for ts, want := range map[string]string{
		"2026-10-10T01:00:00Z": "backing file",
		"2026-10-10T02:00:00Z": "not a qcow2",
		"2026-10-10T03:00:00Z": "overlay",
	} {
		_, err := s.ListBackupFiles(adminCtx(), &pb.ListBackupFilesRequest{RepoPath: "r", Name: "vm", DiskName: "root", Timestamp: ts})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want FailedPrecondition mentioning %q", ts, err, want)
		}
	}
	if o, _ := fr.counts(); o != 0 {
		t.Fatalf("%d VMs started for refused backups", o)
	}
	if _, err := s.ListBackupFiles(adminCtx(), &pb.ListBackupFilesRequest{RepoPath: "r", Name: "vm", DiskName: "root", Timestamp: "2026-10-10T04:00:00Z"}); err != nil {
		t.Fatalf("a standalone qcow2 backup: %v", err)
	}
	if fr.format != "qcow2" {
		t.Fatalf("format %q", fr.format)
	}
}

// A guest-content backup (read over NBD from a running VM) is raw.
func TestFileRestore_GuestContentIsRaw(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repoDir := filepath.Join(t.TempDir(), "repo")
	repo, _ := pbsstore.Init(repoDir)
	s.SetBackupRepos(map[string]string{"r": repoDir})
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm"})
	// Guest bytes that look like a qcow2 header must not change how it is read.
	head := make([]byte, 1<<16)
	copy(head, []byte{'Q', 'F', 'I', 0xfb})
	if _, err := pbsstore.PushDisk(context.Background(), repo, bytes.NewReader(head), pbsstore.PushOptions{
		VMName: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z", VMSpecJSON: string(spec),
		ContentFormat: pbsstore.ContentGuestRaw,
	}); err != nil {
		t.Fatal(err)
	}
	fr := &fakeRestorer{dir: guestDir(t)}
	s.setFileRestorer(fr, FileRestoreOptions{})
	if _, err := s.ListBackupFiles(adminCtx(), &pb.ListBackupFilesRequest{RepoPath: "r", Name: "vm", DiskName: "root", Timestamp: "2026-10-10T01:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if fr.kind != filerestore.KindFS || fr.format != "raw" {
		t.Fatalf("guest content opened as %s/%s, want fs/raw", fr.kind, fr.format)
	}
}

// An idle browsing session's restore VM is killed after the idle timeout,
// and the number of restore VMs on a host is capped.
func TestFileRestore_IdleTimeoutAndCap(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repoDir := ctBackup(t, s, "2026-10-10T01:00:00Z")
	// A second backup, a second session.
	repo, _ := pbsstore.Open(repoDir)
	m, _ := repo.GetManifest("box", "2026-10-10T01:00:00Z", containerBackupDisk)
	m2 := *m
	m2.Timestamp = "2026-10-10T02:00:00Z"
	if err := repo.PutManifest(&m2); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"r": repoDir})
	fr := &fakeRestorer{}
	s.setFileRestorer(fr, FileRestoreOptions{IdleTimeout: time.Minute, MaxSessions: 1})
	list := func(ts string) error {
		_, err := s.ListBackupFiles(adminCtx(), &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts})
		return err
	}
	if err := list("2026-10-10T01:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := list("2026-10-10T02:00:00Z"); status.Code(err) != codes.ResourceExhausted {
		t.Fatalf("a second session past max_sessions 1: %v, want ResourceExhausted", err)
	}
	s.reapFileRestoreOnce(time.Now().Add(30 * time.Second))
	if _, c := fr.counts(); c != 0 {
		t.Fatal("a session was reaped before its idle timeout")
	}
	s.reapFileRestoreOnce(time.Now().Add(2 * time.Minute))
	if _, c := fr.counts(); c != 1 {
		t.Fatal("an idle session outlived its idle timeout")
	}
	if err := list("2026-10-10T02:00:00Z"); err != nil {
		t.Fatalf("after the reap a new session fits: %v", err)
	}
}

// max_bytes can only lower the daemon's limit; hitting it is reported, and
// the archive is still whole.
func TestFileRestore_MaxBytes(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repoDir := ctBackup(t, s, "2026-10-10T01:00:00Z")
	s.SetBackupRepos(map[string]string{"r": repoDir})
	s.setFileRestorer(&fakeRestorer{}, FileRestoreOptions{MaxExtractBytes: 1 << 30})
	st := &progressStream[pb.RestoreBackupFilesChunk]{ctx: adminCtx()}
	if err := s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
		RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: "2026-10-10T01:00:00Z",
		Paths: []string{"/rootfs"}, MaxBytes: 3500, // the whole archive, headers included
	}, st); err != nil {
		t.Fatal(err)
	}
	files, done := extractTar(t, st.Sent)
	if done == nil || !done.Truncated || !strings.Contains(done.Status, "limit") {
		t.Fatalf("done %+v", done)
	}
	if files["rootfs/etc/hostname"] != "box\n" {
		t.Fatalf("files %v", files)
	}
	if _, ok := files["rootfs/root/notes.txt"]; ok {
		t.Fatal("a file past the limit was sent")
	}
}

func TestFileRestore_BadPaths(t *testing.T) {
	s := testServer(t)
	s.setFileRestorer(&fakeRestorer{}, FileRestoreOptions{})
	for _, p := range []string{"rootfs/etc", "/rootfs/../../etc"} {
		if _, err := s.ListBackupFiles(adminCtx(), &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", Timestamp: "x", Path: p}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("list %q: %v", p, err)
		}
	}
	for _, paths := range [][]string{nil, {"/"}, {"/a/../b"}} {
		err := s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{RepoPath: "r", Name: "box", Timestamp: "x", Paths: paths},
			&progressStream[pb.RestoreBackupFilesChunk]{ctx: adminCtx()})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("extract %v: %v", paths, err)
		}
	}
}

// The container side of the same rule: the backup's project decides.
func TestFileRestore_ContainerRBAC(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	const ts = "2026-10-10T01:00:00Z"
	s.SetBackupRepos(map[string]string{"r": ctBackup(t, s, ts)}) // container "box" in project a
	fr := &fakeRestorer{}
	s.setFileRestorer(fr, FileRestoreOptions{})
	alice := grantUser(t, s, "alice", "/projects/a", "Operator")
	carol := grantUser(t, s, "carol", "/projects/b", "Operator")
	req := func(ctx context.Context) error {
		_, err := s.ListBackupFiles(ctx, &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts, Path: "/rootfs"})
		return err
	}
	for name, ctx := range map[string]context.Context{"viewer": viewerCtx(), "other project": carol} {
		if err := req(ctx); status.Code(err) != codes.PermissionDenied {
			t.Errorf("%s: %v, want PermissionDenied", name, err)
		}
	}
	if o, _ := fr.counts(); o != 0 {
		t.Fatalf("a refused caller booted %d restore VMs", o)
	}
	if err := req(alice); err != nil {
		t.Fatalf("the container's project operator: %v", err)
	}
}

// stallConn's Tar blocks until the session is closed.
type stallConn struct {
	closed chan struct{}
	once   sync.Once
}

func (c *stallConn) List(string) ([]filerestore.Entry, bool, int, error) { return nil, false, 0, nil }
func (c *stallConn) Tar(io.Writer, []string, filerestore.TarLimits) (filerestore.TarStats, error) {
	<-c.closed
	return filerestore.TarStats{}, errors.New("connection closed")
}
func (c *stallConn) Broken() bool { return false }
func (c *stallConn) Close()       { c.once.Do(func() { close(c.closed) }) }

type stallRestorer struct{ conn *stallConn }

func (r *stallRestorer) Preflight() error { return nil }
func (r *stallRestorer) Open(context.Context, filerestore.BlockDevice, string, string) (fileRestoreConn, error) {
	return r.conn, nil
}

// A caller that goes away ends its extraction and kills the restore VM, even
// while the agent is stalling.
func TestFileRestore_CancelKillsTheVM(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.SetBackupRepos(map[string]string{"r": ctBackup(t, s, "2026-10-10T01:00:00Z")})
	conn := &stallConn{closed: make(chan struct{})}
	s.setFileRestorer(&stallRestorer{conn: conn}, FileRestoreOptions{})
	ctx, cancel := context.WithCancel(adminCtx())
	done := make(chan error, 1)
	go func() {
		done <- s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
			RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: "2026-10-10T01:00:00Z", Paths: []string{"/rootfs"},
		}, &progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx})
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a cancelled extraction reported success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a cancelled extraction kept waiting on a stalled restore VM")
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("the restore VM was not killed")
	}
}

// I-2: extractions per host are capped on their own, below the sessions.
func TestFileRestore_ExtractionCap(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.SetBackupRepos(map[string]string{"r": ctBackup(t, s, "2026-10-10T01:00:00Z")})
	conn := &stallConn{closed: make(chan struct{})}
	s.setFileRestorer(&stallRestorer{conn: conn}, FileRestoreOptions{MaxSessions: 5, MaxExtractions: 1})
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	go func() {
		_ = s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
			RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: "2026-10-10T01:00:00Z", Paths: []string{"/rootfs"},
		}, &progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		s.fileRestore.mu.Lock()
		n := s.fileRestore.extracting
		s.fileRestore.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the first extraction never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Bounded: an uncapped second extraction would block on the stalled VM.
	ctx2, cancel2 := context.WithTimeout(adminCtx(), 3*time.Second)
	defer cancel2()
	err := s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
		RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: "2026-10-10T01:00:00Z", Paths: []string{"/rootfs"},
	}, &progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx2})
	if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "max_extractions") {
		t.Fatalf("a second extraction past max_extractions 1: %v", err)
	}
}

// gatedRestorer's first Open blocks until released; later ones go through.
type gatedRestorer struct {
	fakeRestorer
	gate  chan struct{}
	first sync.Once
}

func (g *gatedRestorer) Open(ctx context.Context, dev filerestore.BlockDevice, kind, format string) (fileRestoreConn, error) {
	blocked := false
	g.first.Do(func() { blocked = true })
	if blocked {
		g.mu.Lock()
		g.opens++
		g.mu.Unlock()
		<-g.gate
		g.mu.Lock()
		g.opens--
		g.mu.Unlock()
	}
	return g.fakeRestorer.Open(ctx, dev, kind, format)
}

// m-4: one backup's slow boot does not hold up another backup's session,
// and concurrent callers for the same backup share one boot.
func TestFileRestore_BootsDoNotSerialize(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	repoDir := ctBackup(t, s, "2026-10-10T01:00:00Z")
	repo, _ := pbsstore.Open(repoDir)
	m, _ := repo.GetManifest("box", "2026-10-10T01:00:00Z", containerBackupDisk)
	m2 := *m
	m2.Timestamp = "2026-10-10T02:00:00Z"
	_ = repo.PutManifest(&m2)
	s.SetBackupRepos(map[string]string{"r": repoDir})
	g := &gatedRestorer{gate: make(chan struct{})}
	s.setFileRestorer(g, FileRestoreOptions{MaxSessions: 4})
	list := func(ts string) error {
		_, err := s.ListBackupFiles(adminCtx(), &pb.ListBackupFilesRequest{RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: ts})
		return err
	}
	slow := make(chan error, 2)
	go func() { slow <- list("2026-10-10T01:00:00Z") }()
	for i := 0; ; i++ {
		if o, _ := g.counts(); o == 1 {
			break
		}
		if i > 500 {
			t.Fatal("the slow boot never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// A second caller for the SAME backup waits for that boot, not another.
	go func() { slow <- list("2026-10-10T01:00:00Z") }()
	done := make(chan error, 1)
	go func() { done <- list("2026-10-10T02:00:00Z") }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("another backup's session waited for an unrelated boot")
	}
	close(g.gate)
	for i := 0; i < 2; i++ {
		if err := <-slow; err != nil {
			t.Fatal(err)
		}
	}
	if o, _ := g.counts(); o != 2 {
		t.Fatalf("%d boots for two backups (three callers), want 2", o)
	}
}

// m-13: an extraction has a wall clock as well as a progress deadline.
func TestFileRestore_ExtractionWallClock(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.SetBackupRepos(map[string]string{"r": ctBackup(t, s, "2026-10-10T01:00:00Z")})
	conn := &stallConn{closed: make(chan struct{})}
	s.setFileRestorer(&stallRestorer{conn: conn}, FileRestoreOptions{})
	extractWallClockOverride = 200 * time.Millisecond
	defer func() { extractWallClockOverride = 0 }()
	start := time.Now()
	// The caller's own context is far longer than the wall clock; only the
	// wall clock can end this in time.
	ctx, cancel := context.WithTimeout(adminCtx(), 5*time.Second)
	defer cancel()
	err := s.RestoreBackupFiles(&pb.RestoreBackupFilesRequest{
		RepoPath: "r", Name: "box", DiskName: "rootfs", Timestamp: "2026-10-10T01:00:00Z", Paths: []string{"/rootfs"},
	}, &progressStream[pb.RestoreBackupFilesChunk]{ctx: ctx})
	if status.Code(err) != codes.DeadlineExceeded || time.Since(start) > 4*time.Second {
		t.Fatalf("a stalled extraction past its wall clock: %v after %v", err, time.Since(start))
	}
	select {
	case <-conn.closed:
	default:
		t.Fatal("the restore VM outlived its extraction's wall clock")
	}
	if extractWallClock(16<<30) < 4*time.Hour || extractWallClock(1<<20) != 10*time.Minute {
		t.Fatalf("wall clock: %v / %v", extractWallClock(16<<30), extractWallClock(1<<20))
	}
}

// breakableConn is a session whose connection can be marked broken.
type breakableConn struct {
	stallConn
	broken atomic.Bool
}

func (b *breakableConn) Broken() bool { return b.broken.Load() }

type breakableRestorer struct {
	mu    sync.Mutex
	conns []*breakableConn
}

func (r *breakableRestorer) Preflight() error { return nil }
func (r *breakableRestorer) Open(context.Context, filerestore.BlockDevice, string, string) (fileRestoreConn, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := &breakableConn{stallConn: stallConn{closed: make(chan struct{})}}
	r.conns = append(r.conns, c)
	return c, nil
}

// Nit: a broken browsing session that a caller still holds keeps its slot
// until that caller lets go — max_sessions is never exceeded by a VM nobody
// counts — and is closed then.
func TestFileRestore_BrokenHeldSessionKeepsItsSlot(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.SetBackupRepos(map[string]string{"r": ctBackup(t, s, "2026-10-10T01:00:00Z")})
	r := &breakableRestorer{}
	s.setFileRestorer(r, FileRestoreOptions{MaxSessions: 2})
	tgt, err := s.resolveFileRestoreTarget(adminCtx(), "r", "box", "rootfs", "2026-10-10T01:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	_, release1, err := s.acquireBrowse(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	r.conns[0].broken.Store(true)
	_, release2, err := s.acquireBrowse(context.Background(), tgt)
	if err != nil {
		t.Fatal(err)
	}
	s.fileRestore.mu.Lock()
	used := s.fileRestore.used()
	s.fileRestore.mu.Unlock()
	if used != 2 {
		t.Fatalf("slots used %d with a held broken session and its replacement, want 2", used)
	}
	release1()
	select {
	case <-r.conns[0].closed:
	default:
		t.Fatal("the broken session was not closed when its holder let go")
	}
	s.fileRestore.mu.Lock()
	used = s.fileRestore.used()
	s.fileRestore.mu.Unlock()
	if used != 1 {
		t.Fatalf("slots used %d after the broken session's release, want 1", used)
	}
	release2()
}
