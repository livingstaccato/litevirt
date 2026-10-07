package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// NC-1. A reboot or a pool remount gives the pool a new device number (NFS,
// btrfs subvolumes, device-mapper): the record still knows its leftover.
func TestImportVM_ALeftoverIsKnownAcrossARemount(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	plantDeadLeftover(t, s, dst, "crashed", false)
	rec, ok := s.importPlacementOf(dst)
	if !ok {
		t.Fatal("no record")
	}
	rec.Dev++
	if err := s.writeImportPlacement(rec); err != nil {
		t.Fatal(err)
	}
	if err := importAs(s, t, "web"); err != nil {
		t.Fatalf("a re-import after the pool came back under a new device number: %v", err)
	}
	keptAside(t, dst, "crashed")
}

// NM-5. A rewrite at the same size with its modification time put back
// still moved its change time: not a leftover.
func TestImportVM_ARewriteWithItsTimePutBackIsNotALeftover(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	plantDeadLeftover(t, s, dst, "crashed!", false)
	was, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond) // the change time moves on
	f, err := os.OpenFile(dst, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("replica!"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := os.Chtimes(dst, was.ModTime(), was.ModTime()); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "web", dst, "replica!")
}

// NC-3. On a pool with neither link() nor RENAME_NOREPLACE the copy is
// written at a temp name recorded before its first byte, and the disk's name
// is never written in place: it only ever names the finished copy.
func TestImportVM_ACopyIsRecordedAtATempNameAndNeverWritesTheDisksName(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	s, dst := orphanFixture(t, "web")
	saved := placeCopy
	t.Cleanup(func() { placeCopy = saved })
	var temp string
	placeCopy = func(ctx context.Context, out, in *os.File, limit int64) error {
		temp = out.Name()
		fi, err := os.Lstat(temp)
		if err != nil {
			t.Fatal(err)
		}
		if rec, ok := s.importPlacementOf(temp); !ok || !rec.Scratch || !rec.matches(fi) || fi.Size() != 0 {
			t.Errorf("the copy at %s was not recorded before its first byte: %+v %v", temp, rec, ok)
		}
		if _, err := os.Lstat(dst); !os.IsNotExist(err) {
			t.Errorf("the disk's name was taken before the copy was done: %v", err)
		}
		return saved(ctx, out, in, limit)
	}
	if err := importAs(s, t, "web"); err != nil {
		t.Fatal(err)
	}
	if temp == "" || filepath.Dir(temp) != filepath.Dir(dst) || !strings.HasPrefix(filepath.Base(temp), ".web-root.qcow2.place-") {
		t.Fatalf("copied through %q", temp)
	}
	if _, err := os.Lstat(temp); !os.IsNotExist(err) {
		t.Fatalf("the copy's temp name is left: %v", err)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("the disk was not placed: %v", err)
	}
}

// A crash mid-copy leaves a partial at its temp name, recorded: a re-import
// removes it at once. A running import's partial is left alone.
func TestImportVM_ADeadImportsPartialCopyIsRemovedAtOnce(t *testing.T) {
	for _, live := range []bool{false, true} {
		t.Run(map[bool]string{false: "dead", true: "running"}[live], func(t *testing.T) {
			s, dst := orphanFixture(t, "web")
			partial := filepath.Join(filepath.Dir(dst), ".web-root.qcow2.place-abc")
			if live {
				if err := os.WriteFile(partial, []byte("half"), 0o600); err != nil {
					t.Fatal(err)
				}
				release, err := s.claimImportNameAs("web-other", "imp-live")
				if err != nil {
					t.Fatal(err)
				}
				defer release()
				fi, _ := os.Lstat(partial)
				if err := s.recordImportPlacement(partial, fi, "imp-live", true); err != nil {
					t.Fatal(err)
				}
			} else {
				plantDeadLeftover(t, s, partial, "half", true)
			}
			if err := importAs(s, t, "web"); err != nil {
				t.Fatal(err)
			}
			_, err := os.Lstat(partial)
			if live != (err == nil) {
				t.Fatalf("partial copy after a re-import's sweep: %v", err)
			}
		})
	}
}

// NI-1. A pool whose mount hangs holds no import up: the prune of stale
// records runs off the import's path, one pass per pool.
func TestImportVM_AHungPoolDoesNotHoldImportsUp(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	stuck := make(chan struct{})
	s.placementLstatOverride = func(string) (os.FileInfo, error) { <-stuck; return nil, os.ErrNotExist }
	t.Cleanup(func() { close(stuck) })
	for _, p := range []string{filepath.Join(filepath.Dir(dst), "old-root.qcow2"), filepath.Join(t.TempDir(), "nas-root.qcow2")} {
		plantDeadLeftover(t, s, p, "stale", false)
	}
	done := make(chan error, 2)
	for _, name := range []string{"web", "web-2"} {
		go func() { done <- importAs(s, t, name) }()
	}
	for range 2 {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("an import waited on a hung pool's record prune")
		}
	}
}

// One pool's hung mount stalls no other pool's prune.
func TestImportPlacements_APruneSkipsOtherPoolsRecords(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	other := filepath.Join(t.TempDir(), "nas-root.qcow2")
	plantDeadLeftover(t, s, other, "on a hung pool", false)
	gone := filepath.Join(filepath.Dir(dst), "gone-root.qcow2")
	plantDeadLeftover(t, s, gone, "removed", false)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	stuck := make(chan struct{})
	s.placementLstatOverride = func(p string) (os.FileInfo, error) {
		if p == other {
			<-stuck
		}
		return os.Lstat(p)
	}
	t.Cleanup(func() { close(stuck) })
	done := make(chan struct{})
	go func() { s.pruneImportPlacementsIn(filepath.Dir(dst), time.Now().Add(time.Minute)); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("a pool's prune waited on another pool's hung mount")
	}
	if _, ok := s.importPlacementOf(gone); ok {
		t.Fatal("the pool's own stale record was kept")
	}
}

// NM-2. The prune also drops what a crash cut short and records whose file
// was written since (they can never show it again).
func TestImportPlacements_ThePruneDropsTornAndOutlivedRecords(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	dir := filepath.Dir(dst)
	rewritten, kept := filepath.Join(dir, "a-root.qcow2"), filepath.Join(dir, "b-root.qcow2")
	plantDeadLeftover(t, s, rewritten, "left", false)
	plantDeadLeftover(t, s, kept, "left", false)
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(rewritten, later, later); err != nil {
		t.Fatal(err)
	}
	torn := filepath.Join(s.dataDir, importPlacementDirName, ".rec-123")
	if err := os.WriteFile(torn, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(torn, old, old); err != nil {
		t.Fatal(err)
	}
	s.pruneImportPlacementsIn(dir, time.Now().Add(time.Minute))
	if _, ok := s.importPlacementOf(rewritten); ok {
		t.Error("a record of a file written since was kept")
	}
	if _, ok := s.importPlacementOf(kept); !ok {
		t.Error("a record that still shows its file was dropped")
	}
	if _, err := os.Lstat(torn); !os.IsNotExist(err) {
		t.Errorf("a torn record write was kept: %v", err)
	}
}

// NM-3. An import placing a disk never takes the record another import
// running here holds for that name.
func TestImportWrites_APlacingNeverTakesARunningImportsRecord(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	if err := os.WriteFile(dst, []byte("a's"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := s.claimImportNameAs("web", "imp-a")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	fi, _ := os.Lstat(dst)
	if err := s.recordImportPlacement(dst, fi, "imp-a", false); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "b")
	if err := os.WriteFile(other, []byte("b's"), 0o600); err != nil {
		t.Fatal(err)
	}
	ofi, _ := os.Lstat(other)
	if err := s.recordImportPlacement(dst, ofi, "imp-b", false); err == nil {
		t.Fatal("took a running import's record")
	}
	if rec, ok := s.importPlacementOf(dst); !ok || rec.ImportID != "imp-a" {
		t.Fatalf("record now %+v", rec)
	}
}

// leftoverPeer is a host sharing the pool, as the asking host sees it.
type leftoverPeer struct {
	pb.LiteVirtClient
	dead  []string
	err   error
	asked func(*pb.ImportLeftoverStatusRequest)
}

func (p *leftoverPeer) ImportLeftoverStatus(_ context.Context, req *pb.ImportLeftoverStatusRequest, _ ...grpc.CallOption) (*pb.ImportLeftoverStatusResponse, error) {
	if p.asked != nil {
		p.asked(req)
	}
	if p.err != nil {
		return nil, p.err
	}
	return &pb.ImportLeftoverStatusResponse{Dead: p.dead}, nil
}

// sharedPoolFixture is a server with pool "shared" in poolDir, which
// other-host has too.
func sharedPoolFixture(t *testing.T, peer *leftoverPeer) (*Server, string) {
	t.Helper()
	s := concurrentImportServer(t, 10*oneDiskNeed())
	stubQemuImg(t)
	poolDir := t.TempDir()
	for _, h := range []string{s.hostName, "other-host"} {
		if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
			HostName: h, Name: "shared", Driver: "dir", Target: poolDir, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host != "other-host" {
			return nil, nil, errors.New("no such peer")
		}
		return peer, func() {}, nil
	}
	return s, filepath.Join(poolDir, "web-root.qcow2")
}

func importIntoShared(s *Server, t *testing.T, name string) error {
	f := smallImportFrame(t, name, false)
	f.TargetPool = "shared"
	return s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{f}})
}

// NC-2. A re-import on another host into a shared pool asks the hosts
// sharing it: the host whose import crashed there vouches for its leftovers,
// and the re-import goes ahead. No answer, or no yes, and it waits as before.
func TestImportVM_AnotherHostsDeadLeftoverInASharedPool(t *testing.T) {
	cases := []struct {
		name  string
		dead  []string
		err   error
		allow bool
	}{
		{name: "vouched", dead: []string{"web-root.qcow2", "web-data.qcow2"}, allow: true},
		{name: "unreachable", err: status.Error(codes.Unavailable, "down")},
		{name: "not theirs", dead: nil},
		{name: "only the sibling", dead: []string{"web-data.qcow2"}},
		{name: "an answer about another file", dead: []string{"web-other.qcow2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var asked *pb.ImportLeftoverStatusRequest
			peer := &leftoverPeer{dead: c.dead, err: c.err, asked: func(r *pb.ImportLeftoverStatusRequest) { asked = r }}
			s, dst := sharedPoolFixture(t, peer)
			if err := os.WriteFile(dst, []byte("crashed on other-host"), 0o600); err != nil {
				t.Fatal(err)
			}
			sib := filepath.Join(filepath.Dir(dst), "web-data.qcow2")
			if err := os.WriteFile(sib, []byte("its other disk"), 0o600); err != nil {
				t.Fatal(err)
			}
			err := importIntoShared(s, t, "web")
			if asked == nil || asked.Pool != "shared" || len(asked.Files) != 2 {
				t.Fatalf("asked %+v", asked)
			}
			fi, _ := os.Lstat(sib)
			_, ino, size, mtime, _ := fileState(fi)
			if f := asked.Files[1]; f.Name != "web-data.qcow2" || f.Ino != ino || f.Size != size || f.MtimeNs != mtime || f.CtimeNs != fileCtimeNs(fi) {
				t.Fatalf("asked about %+v", f)
			}
			if c.allow {
				if err != nil {
					t.Fatalf("a re-import over another host's vouched leftover: %v", err)
				}
				keptAside(t, dst, "crashed on other-host")
				return
			}
			if status.Code(err) != codes.FailedPrecondition {
				t.Fatalf("got %v, want a refusal", err)
			}
			if c.err != nil && !strings.Contains(err.Error(), "other-host") {
				t.Fatalf("the refusal does not name the host it could not ask: %v", err)
			}
			if b, _ := os.ReadFile(dst); string(b) != "crashed on other-host" {
				t.Fatalf("the file now holds %q", b)
			}
		})
	}
}

// NM-1. The file is judged, then moved: if it changed in between (a
// replica opened it), it is not moved.
func TestImportVM_AFileThatChangesWhileJudgedIsNotMoved(t *testing.T) {
	peer := &leftoverPeer{dead: []string{"web-data.qcow2"}}
	s, dst := sharedPoolFixture(t, peer)
	plantOld(t, dst, "old")
	if err := os.WriteFile(filepath.Join(filepath.Dir(dst), "web-data.qcow2"), []byte("theirs, dead"), 0o600); err != nil {
		t.Fatal(err)
	}
	peer.asked = func(*pb.ImportLeftoverStatusRequest) {
		f, err := os.OpenFile(dst, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString("new")
		f.Close()
	}
	err := importIntoShared(s, t, "web")
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "changed while") {
		t.Fatalf("got %v, want a refusal for a file that changed", err)
	}
	if aside, _ := filepath.Glob(dst + ".orphan-*"); len(aside) != 0 {
		t.Fatalf("moved aside: %v", aside)
	}
}

// The answering host answers from its record alone, and only a peer asks.
func TestImportLeftoverStatus_AnswersFromItsRecordOnly(t *testing.T) {
	s, dst := sharedPoolFixture(t, &leftoverPeer{})
	dir := filepath.Dir(dst)
	dead, live := filepath.Join(dir, "web-root.qcow2"), filepath.Join(dir, "db-root.qcow2")
	plantDeadLeftover(t, s, dead, "crashed", false)
	if err := os.WriteFile(live, []byte("running"), 0o600); err != nil {
		t.Fatal(err)
	}
	release, err := s.claimImportNameAs("db", "imp-db")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	lfi, _ := os.Lstat(live)
	if err := s.recordImportPlacement(live, lfi, "imp-db", false); err != nil {
		t.Fatal(err)
	}
	file := func(p string, bump int64) *pb.ImportLeftoverFile {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		_, ino, size, mtime, _ := fileState(fi)
		return &pb.ImportLeftoverFile{Name: filepath.Base(p), Ino: ino, Size: size, MtimeNs: mtime + bump, CtimeNs: fileCtimeNs(fi)}
	}
	req := &pb.ImportLeftoverStatusRequest{Pool: "shared", Files: []*pb.ImportLeftoverFile{file(dead, 0), file(live, 0)}}
	if _, err := s.ImportLeftoverStatus(adminCtx(), req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a user asked: %v, want PermissionDenied", err)
	}
	peer := peerCtxFor(t, s, "other-host")
	resp, err := s.ImportLeftoverStatus(peer, req)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Dead) != 1 || resp.Dead[0] != "web-root.qcow2" {
		t.Fatalf("answered %v, want only the dead import's file", resp.Dead)
	}
	moved := &pb.ImportLeftoverStatusRequest{Pool: "shared", Files: []*pb.ImportLeftoverFile{file(dead, 1)}}
	if resp, err := s.ImportLeftoverStatus(peer, moved); err != nil || len(resp.Dead) != 0 {
		t.Fatalf("a file in another state: %v %v", resp, err)
	}
	for _, bad := range []string{"../x", "a/b", "..", ".", ""} {
		r := &pb.ImportLeftoverStatusRequest{Pool: "shared", Files: []*pb.ImportLeftoverFile{{Name: bad}}}
		if _, err := s.ImportLeftoverStatus(peer, r); status.Code(err) != codes.InvalidArgument {
			t.Errorf("name %q: %v, want InvalidArgument", bad, err)
		}
	}
	if _, err := s.ImportLeftoverStatus(peer, &pb.ImportLeftoverStatusRequest{Files: req.Files}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("the default pool: %v, want InvalidArgument", err)
	}
	if _, err := s.ImportLeftoverStatus(peer, &pb.ImportLeftoverStatusRequest{Pool: "nope"}); status.Code(err) != codes.NotFound {
		t.Errorf("an unknown pool: %v, want NotFound", err)
	}
}
