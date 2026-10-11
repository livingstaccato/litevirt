package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// orderGate is a release-feature gate that records what it saw and when. A
// closed gate refuses the way the real one does before the latch; an open one
// "records the use" (noting whether repo.json existed yet) and then runs the
// write with a grant.
type orderGate struct {
	t        *testing.T
	open     bool
	repoJSON string

	used          int
	repoAtUse     bool // repo.json existed when the use was recorded
	featuresAsked []capabilities.Feature
}

func (g *orderGate) WithFeature(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
	g.featuresAsked = append(g.featuresAsked, f)
	if !g.open {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
	}
	g.used++
	_, err := os.Stat(g.repoJSON)
	g.repoAtUse = err == nil
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *orderGate) FeatureAvailable(capabilities.Feature) bool { return g.open }

func compressionServer(t *testing.T, g *orderGate) (*Server, string) {
	t.Helper()
	s := testServer(t)
	dir := filepath.Join(t.TempDir(), "repo")
	g.t = t
	g.repoJSON = filepath.Join(dir, "repo.json")
	s.SetReleaseFeatureGate(g)
	return s, dir
}

// Before the release token latches, a zstd repo is refused with the release
// text and nothing is created; after it, the use is recorded BEFORE repo.json
// is written and the repo is compressed (schema 2).
func TestSetBackupRepoCompression_Init_GatedAndUsedBeforeData(t *testing.T) {
	g := &orderGate{}
	s, dir := compressionServer(t, g)
	req := &pb.SetBackupRepoCompressionRequest{Repo: dir, Compression: "zstd", Init: true}

	_, err := s.SetBackupRepoCompression(adminCtx(), req)
	want := "the cluster upgrade must finish first (backup_zstd needs " + capabilities.ReleaseToken + ")"
	if status.Code(err) != codes.FailedPrecondition || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("before the latch: %v, want FailedPrecondition %q", err, want)
	}
	if _, serr := os.Stat(g.repoJSON); serr == nil {
		t.Fatal("a repository was created although the gate refused")
	}
	if g.used != 0 {
		t.Fatalf("a use was recorded by a refused write (%d)", g.used)
	}

	g.open = true
	resp, err := s.SetBackupRepoCompression(adminCtx(), req)
	if err != nil {
		t.Fatalf("after the latch: %v", err)
	}
	if resp.GetCompression() != "zstd" || resp.GetSchemaVersion() != 2 || resp.GetHost() != "test-host" {
		t.Fatalf("response = %+v, want zstd schema 2 on test-host", resp)
	}
	if g.used != 1 || g.repoAtUse {
		t.Fatalf("used=%d repoExistedAtUse=%v, want one use recorded before the repository existed", g.used, g.repoAtUse)
	}
	if len(g.featuresAsked) == 0 || g.featuresAsked[len(g.featuresAsked)-1] != capabilities.FeatureBackupZstd {
		t.Fatalf("gated on %v, want backup_zstd", g.featuresAsked)
	}
	r, err := pbsstore.Open(dir)
	if err != nil || r.Compression() != pbsstore.CompressionZstd || r.Meta().SchemaVersion != 2 {
		t.Fatalf("repo on disk: %v compression/schema wrong", err)
	}
}

// Converting an existing repo is gated the same way, and a refused conversion
// leaves the repo byte-identical.
func TestSetBackupRepoCompression_Convert_Gated(t *testing.T) {
	g := &orderGate{}
	s, dir := compressionServer(t, g)
	if _, err := pbsstore.Init(dir); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(g.repoJSON)
	req := &pb.SetBackupRepoCompressionRequest{Repo: dir, Compression: "zstd"}
	if _, err := s.SetBackupRepoCompression(adminCtx(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("convert before the latch: %v, want FailedPrecondition", err)
	}
	if after, _ := os.ReadFile(g.repoJSON); string(after) != string(before) {
		t.Fatal("a refused conversion changed repo.json")
	}
	g.open = true
	if _, err := s.SetBackupRepoCompression(adminCtx(), req); err != nil {
		t.Fatal(err)
	}
	if !g.repoAtUse || g.used != 1 {
		t.Fatalf("used=%d", g.used)
	}
	if r, err := pbsstore.Open(dir); err != nil || r.Compression() != "zstd" || r.Meta().SchemaVersion != 2 {
		t.Fatalf("converted repo: %v", err)
	}
}

// The daemon never creates its repository scaffolding inside its own state or
// PKI directories, for an admin too (as the restore-target create refuses),
// and nothing is recorded or created for it.
func TestSetBackupRepoCompression_RefusesDaemonState(t *testing.T) {
	g := &orderGate{open: true}
	s, _ := compressionServer(t, g)
	s.dataDir = t.TempDir()
	s.pkiDir = t.TempDir()
	for _, p := range []string{filepath.Join(s.dataDir, "images", "repo"), filepath.Join(s.pkiDir, "repo"), s.dataDir} {
		_, err := s.SetBackupRepoCompression(adminCtx(), &pb.SetBackupRepoCompressionRequest{Repo: p, Compression: "zstd", Init: true})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("%s: %v, want InvalidArgument", p, err)
		}
		if _, serr := os.Stat(filepath.Join(p, "repo.json")); serr == nil {
			t.Fatalf("%s: repo.json created", p)
		}
	}
	if g.used != 0 {
		t.Fatal("a refused path recorded a use")
	}
}

// Only zstd goes through the daemon; none is never gated, so it is refused
// here rather than silently accepted; no gate wired fails closed.
func TestSetBackupRepoCompression_Validation(t *testing.T) {
	g := &orderGate{open: true}
	s, dir := compressionServer(t, g)
	if _, err := s.SetBackupRepoCompression(adminCtx(), &pb.SetBackupRepoCompressionRequest{Repo: dir, Compression: "none", Init: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("none: %v, want InvalidArgument", err)
	}
	if _, err := s.SetBackupRepoCompression(adminCtx(), &pb.SetBackupRepoCompressionRequest{Repo: dir, Compression: "zstd", Encrypted: true}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("encrypted without init: %v, want InvalidArgument", err)
	}
	s.SetReleaseFeatureGate(nil)
	if _, err := s.SetBackupRepoCompression(adminCtx(), &pb.SetBackupRepoCompressionRequest{Repo: dir, Compression: "zstd", Init: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("no gate wired: %v, want FailedPrecondition", err)
	}
	if _, serr := os.Stat(g.repoJSON); serr == nil {
		t.Fatal("a repository was created with no gate")
	}
}

// A viewer cannot create or convert a repository.
func TestSetBackupRepoCompression_NeedsOperator(t *testing.T) {
	g := &orderGate{open: true}
	s, dir := compressionServer(t, g)
	ctx := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "v"), ctxKeyRole, "viewer")
	_, err := s.SetBackupRepoCompression(ctx, &pb.SetBackupRepoCompressionRequest{Repo: dir, Compression: "zstd", Init: true})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("viewer: %v, want PermissionDenied", err)
	}
	if g.used != 0 {
		t.Fatal("a denied caller recorded a use")
	}
}
