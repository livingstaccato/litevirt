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
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 1, m1: a live disk row lifts a kept-disks.json entry's hold only
// when it is this host's, and only on the file it names. A row of another
// host at the same path is another file, and the files under a reattached
// top stay held.
//
// Red on 7c5073b41 (any host's row dropped the whole chain). Mutations: drop
// the host filter: "another host's row" red; skip the whole chain again:
// "this host's row" red.
func TestKeptRegistry_ALiveRowLiftsOnlyItsOwnFileOnThisHost(t *testing.T) {
	setup := func(t *testing.T, rowHost string) (*Server, string, string) {
		s, base, _ := debrisFixture(t)
		top := registryKeep(t, s, "gone", base)
		if rowHost == "" {
			rowHost = s.hostName
		}
		if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "user", HostName: rowHost, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: "user", DiskName: "root", HostName: rowHost, Path: top, StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
		return s, top, base
	}
	t.Run("another host's row", func(t *testing.T) {
		s, top, _ := setup(t, "elsewhere")
		if held, _ := s.keptHolds(adminCtx(), top); !held {
			t.Error("a row of another host at the same path lifted this host's kept disk's hold")
		}
	})
	t.Run("this host's row", func(t *testing.T) {
		s, top, base := setup(t, "")
		if held, why := s.keptHolds(adminCtx(), top); held {
			t.Errorf("the file this host's live row names is still held by the entry: %s", why)
		}
		if held, _ := s.keptHolds(adminCtx(), base); !held {
			t.Error("the file under a reattached kept top lost its hold")
		}
	})
}

// Re-review 1, m2: a kept disk's chain that ends at a missing backing file
// does not hold anything there, but a create (or import) that would write a
// disk at that path is refused, naming the overlay: the new disk would
// become the kept overlay's base.
//
// Red on 7c5073b41 (the create and the import go ahead). Mutation: drop the
// missing-base check (keptMissingBaseRefusal / the registry loop's): red.
func TestCreateVM_NeverWritesTheMissingBaseOfAKeptOverlay(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		base := s.images.DiskPath("web", "root")
		top := registryKeep(t, s, "web", base) // base missing: removed by hand
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}} // an empty disk at web-root.qcow2
		_, err := s.CreateVM(adminCtx(), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), base) {
			t.Fatalf("create web over a kept overlay's missing base = %v; want FailedPrecondition naming %s and %s", err, top, base)
		}
		if exists(base) {
			t.Fatal("a file was written at the kept overlay's missing base")
		}
	})
	t.Run("create with debris to clear", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		base := s.images.DiskPath("web", "root")
		swap := s.images.DiskPath("web", "swap")
		if err := os.MkdirAll(filepath.Dir(swap), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(swap, []byte("debris"), 0o600); err != nil {
			t.Fatal(err)
		}
		top := registryKeep(t, s, "web", base)
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}}
		if _, err := s.CreateVM(adminCtx(), req); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("create web over a kept overlay's missing base, with debris = %v; want FailedPrecondition naming %s", err, top)
		}
		if exists(base) {
			t.Fatal("a file was written at the kept overlay's missing base")
		}
	})
	t.Run("import", func(t *testing.T) {
		s, dst := orphanFixture(t, "imp-mb")
		top := registryKeep(t, s, "imp-mb", dst)
		err := s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, "imp-mb", false)}})
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("import at a kept overlay's missing base = %v; want FailedPrecondition naming %s", err, top)
		}
		if exists(dst) {
			t.Fatal("the import wrote the kept overlay's missing base")
		}
	})
}

// A create that clears nothing is refused while kept-disks.json, or a kept
// disk's chain, cannot be read: whether a kept overlay names a path it
// writes as its missing base is then unknown. keptMissingBaseRefusal let it
// go ahead, and the new disk could become a kept overlay's base.
//
// Mutation: return nil on a keptRegistryChains error in
// keptMissingBaseRefusal again: both subtests red (the base is written).
func TestCreateVM_RefusesWhileWhatAKeptOverlayBacksOnCannotBeRead(t *testing.T) {
	create := func(t *testing.T, s *Server, base, want string) {
		t.Helper()
		req := disklessCreateRequest("web")
		req.Spec.Disks = []*pb.DiskSpec{{Name: "root", Size: "1M"}} // an empty disk at web-root.qcow2
		_, err := s.CreateVM(adminCtx(), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
			t.Fatalf("create web = %v; want FailedPrecondition naming %q", err, want)
		}
		if exists(base) {
			t.Fatal("a refused create wrote a disk at the base path")
		}
	}
	t.Run("kept-disks.json unreadable", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		base := s.images.DiskPath("web", "root")
		if err := os.WriteFile(filepath.Join(s.dataDir, diskKeptFile), []byte("[not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		create(t, s, base, diskKeptFile)
	})
	t.Run("a kept chain unreadable", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		base := s.images.DiskPath("web", "root")
		top := registryKeep(t, s, "web", base)       // base missing
		if err := os.Truncate(top, 16); err != nil { // the magic, and no header to read
			t.Fatal(err)
		}
		create(t, s, base, "the backing chain of "+top)
	})
}

// Re-review 1, m3: replica pruning keeps a replica a kept-disks.json entry
// holds (a kept disk, or a file one backs on), as every other removal does.
//
// Red on 7c5073b41. Mutation: drop keptHolds from pruneRecordedReplicas, or
// from pruneTopLevelReplicas: the matching subtest red.
func TestPruneReplicas_KeepWhatAKeptDiskHolds(t *testing.T) {
	t.Run("recorded", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		dir := replicaPoolDir(t, s, "dr")
		ctx := context.Background()
		var mine []string
		for _, ts := range []string{"20260101-000000", "20260102-000000", "20260103-000000"} {
			rec := newReplicaRecord("", "vm1", "root", "vm1/dr", ts, "qcow2")
			p, err := publishRecordedReplica(ctx, dir, rec, func(tmp string) error { return os.WriteFile(tmp, []byte("x"), 0o600) })
			if err != nil {
				t.Fatal(err)
			}
			mine = append(mine, p)
		}
		registryKeep(t, s, "vm1", mine[0])
		got, err := s.pruneRecordedReplicas(ctx, "dr", "", "vm1", "root", "vm1/dr", 1)
		if err != nil || got != 1 {
			t.Fatalf("pruned %d (%v), want 1: the held one kept, the other pruned", got, err)
		}
		if !exists(mine[0]) {
			t.Error("a replica a kept disk backs on was pruned")
		}
		if exists(mine[1]) {
			t.Error("an unheld old replica survived: the prune did nothing, so this proves nothing")
		}
	})
	t.Run("top level", func(t *testing.T) {
		s := testServer(t)
		s.dataDir = t.TempDir()
		dir := t.TempDir()
		var names []string
		for _, n := range []string{"vm1-root-20260101-000000.qcow2", "vm1-root-20260102-000000.qcow2", "vm1-root-20260103-000000.qcow2"} {
			if err := os.WriteFile(filepath.Join(dir, n), []byte("x"), 0o644); err != nil {
				t.Fatal(err)
			}
			names = append(names, filepath.Join(dir, n))
		}
		registryKeep(t, s, "vm1", names[0])
		if got := s.pruneLocalReplicas(context.Background(), dir, replicaKey{VM: "vm1", Disk: "root"}, 1); got != 1 {
			t.Fatalf("pruned %d, want 1", got)
		}
		if !exists(names[0]) {
			t.Error("a replica a kept disk backs on was pruned")
		}
	})
}
