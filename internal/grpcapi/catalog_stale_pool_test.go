package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// catalogTestGate is a release-feature gate on which catalog_incarnation is
// available: its writes take a test grant.
type catalogTestGate struct{ t *testing.T }

func (g catalogTestGate) FeatureAvailable(capabilities.Feature) bool { return true }
func (g catalogTestGate) WithFeature(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

// stalePoolServer has pool p of project A born on host-a, and then host-a
// removed and re-admitted (incarnation 1): p is a stale-host pool. It returns
// contexts for an Admin of project A's pool and one of project B's.
func stalePoolServer(t *testing.T) (s *Server, alice, bob context.Context) {
	t.Helper()
	ctx := context.Background()
	s = newPoolTestServer(t)
	s.SetReleaseFeatureGate(catalogTestGate{t})
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "host-a", Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "p", Driver: "local", Target: t.TempDir(), Project: "A"}); err != nil {
		t.Fatalf("create A's pool: %v", err)
	}
	if b, err := corrosion.StoragePoolBirthOf(ctx, s.db, "host-a", "p"); err != nil || b.Project != "A" {
		t.Fatalf("A's pool not born: %+v %v", b, err)
	}
	if _, err := s.db.DB().Exec(`UPDATE hosts SET incarnation = 1 WHERE name = 'host-a'`); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := corrosion.GetStoragePool(ctx, s.db, "host-a", "p"); ok {
		t.Fatal("setup: the pool is not stale-host")
	}
	for _, u := range []struct{ name, project string }{{"alice", "A"}, {"bob", "B"}} {
		if err := corrosion.InsertUser(ctx, s.db, u.name, "operator", "x"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
			ID: u.name + "-p", Path: poolRBACPathFor(u.project, "p"), Role: "Admin",
			Principal: "user:" + u.name + "@local", Propagate: true,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	as := func(u string) context.Context {
		return context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, u), ctxKeyRole, "operator")
	}
	return s, as("alice"), as("bob")
}

// Review of e56d2d5d7: a stale-host pool reads as not found to the listings,
// but lv pool create's ownership check must still see its project, or project
// B re-creates the name into B and takes over the disks that name it.
//
// Mutation: CreateStoragePool reading the existing pool with GetStoragePool
// (stale pools hidden) — red at "takeover".
func TestStaleHostPool_CreateKeepsItsProject(t *testing.T) {
	s, alice, bob := stalePoolServer(t)
	ctx := context.Background()
	_, err := s.CreateStoragePool(bob, &pb.CreateStoragePoolRequest{Name: "p", Driver: "local", Project: "B"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("takeover: project B re-created A's stale-host pool into B: %v", err)
	}
	if _, err := s.CreateStoragePool(alice, &pb.CreateStoragePoolRequest{Name: "p", Driver: "local", Project: "A"}); err != nil {
		t.Fatalf("project A re-creating its stale-host pool: %v", err)
	}
	b, err := corrosion.StoragePoolBirthOf(ctx, s.db, "host-a", "p")
	if err != nil || b.Project != "A" || b.HostIncarnation != 1 {
		t.Fatalf("A's re-create: %+v %v, want A's pool born under host incarnation 1", b, err)
	}
}

// lv pool rm finds a stale-host pool, under its own project's authority, and
// tombstones it. lv pool ls and inspect show it as stale-host.
//
// Mutations: DeleteStoragePool reading with GetStoragePool — red at "rm";
// the listing leaving stale pools out — red at "ls".
func TestStaleHostPool_ListedAndRemovable(t *testing.T) {
	s, alice, bob := stalePoolServer(t)
	ctx := context.Background()
	ls, err := s.ListStoragePools(adminCtx(), &pb.ListStoragePoolsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var listed *pb.StoragePool
	for _, p := range ls.Pools {
		if p.Name == "p" {
			listed = p
		}
	}
	if listed == nil || listed.State != poolStateStaleHost {
		t.Fatalf("ls: the stale-host pool is listed as %+v, want state %s", listed, poolStateStaleHost)
	}
	if got, err := s.GetStoragePool(adminCtx(), &pb.GetStoragePoolRequest{Name: "p"}); err != nil || got.Pool.State != poolStateStaleHost {
		t.Fatalf("inspect: %+v %v, want state %s", got, err, poolStateStaleHost)
	}
	if _, err := s.DeleteStoragePool(bob, &pb.DeleteStoragePoolRequest{Name: "p"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("project B removing A's stale-host pool: %v, want PermissionDenied", err)
	}
	if _, err := s.DeleteStoragePool(alice, &pb.DeleteStoragePoolRequest{Name: "p"}); err != nil {
		t.Fatalf("rm: removing the stale-host pool: %v", err)
	}
	if _, ok, _, err := corrosion.GetStoragePoolAnyLifetime(ctx, s.db, "host-a", "p"); err != nil || ok {
		t.Fatalf("rm: the stale-host pool is still live: %v %v", ok, err)
	}
	var deleted string
	if err := s.db.DB().QueryRow(`SELECT COALESCE(deleted_at, '') FROM storage_pools WHERE name = 'p'`).Scan(&deleted); err != nil || deleted == "" {
		t.Fatalf("rm: no tombstone: %q %v", deleted, err)
	}
}
