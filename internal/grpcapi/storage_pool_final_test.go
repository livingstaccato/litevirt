package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Final-review fixes for the storage-pool slice: C3 (replicas in the replica
// area are deleted through the content API, as top-level replicas were on
// main), C4 (a pool is deleted around the daemon's own directories), m1 (a
// relayed named promote is judged as the operator, not the relaying node).

// areaReplica publishes a recorded replica of (project, vm, disk) taken at
// taken into poolDir's replica area and returns its path.
func areaReplica(t *testing.T, poolDir, project, vm, disk, taken string) string {
	t.Helper()
	rec := newReplicaRecord(project, vm, disk, vm+"/dr", taken, "qcow2")
	p, err := publishRecordedReplica(context.Background(), poolDir, rec, func(tmp string) error {
		return os.WriteFile(tmp, []byte("replica of "+project+"/"+vm), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func listedReplicas(t *testing.T, s *Server, ctx context.Context, pool string) []string {
	t.Helper()
	resp, err := s.ListStoragePoolContents(ctx, &pb.ListStoragePoolContentsRequest{PoolName: pool})
	if err != nil {
		t.Fatalf("list %s: %v", pool, err)
	}
	var out []string
	for _, c := range resp.GetContents() {
		if c.GetReplicaVm() != "" {
			out = append(out, c.GetReplicaVm()+"/"+c.GetName())
		}
	}
	return out
}

func present(p string) bool { _, err := os.Lstat(p); return err == nil }

// C3: a replica the listing shows is deleted by the name it shows — the file
// and its record — where on this branch a delete returned OK and deleted
// nothing. Another project's replica of the same shape is not the caller's.
func TestFinalPools_ContentDeleteRemovesAListedAreaReplica(t *testing.T) {
	f := newPoolFixture(t)
	f.grantPoolWrite(t)
	mine := areaReplica(t, f.dr, "a", "web", "1", "20261007-120000")
	theirs := areaReplica(t, f.dr, "b", "web-1", "1", "20261007-110000")
	name := filepath.Base(mine)

	if got := listedReplicas(t, f.s, f.alice, "dr"); !slices.Contains(got, "web/"+name) {
		t.Fatalf("alice's listing = %v, want web/%s", got, name)
	}
	if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: name}); err != nil {
		t.Fatalf("deleting a listed replica: %v", err)
	}
	if present(mine) || present(mine+".json") {
		t.Fatalf("the replica (or its record) is still there after a delete that returned OK")
	}
	if got := listedReplicas(t, f.s, f.alice, "dr"); slices.Contains(got, "web/"+name) {
		t.Fatalf("the deleted replica is still listed: %v", got)
	}

	// Another project's replica: NotFound, by name and by VM, and untouched.
	for _, req := range []*pb.DeleteStoragePoolContentRequest{
		{PoolName: "dr", Filename: filepath.Base(theirs)},
		{PoolName: "dr", Filename: filepath.Base(theirs), ReplicaVm: "web-1"},
	} {
		if _, err := f.s.DeleteStoragePoolContent(f.alice, req); status.Code(err) != codes.NotFound {
			t.Errorf("alice deleting project b's replica %+v: got %v, want NotFound", req, err)
		}
	}
	if !present(theirs) || !present(theirs+".json") {
		t.Fatalf("project b's replica was deleted")
	}
	// A replica recorded for an earlier VM "web" of project b is not
	// alice's, though she reads project a's VM of that name now.
	stale := areaReplica(t, f.dr, "b", "web", "1", "20261007-100000")
	if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(stale), ReplicaVm: "web"}); status.Code(err) != codes.NotFound {
		t.Errorf("alice deleting a replica project b recorded for its own VM web: got %v, want NotFound", err)
	}
	if !present(stale) {
		t.Fatalf("project b's replica of its earlier VM web was deleted")
	}
	// An admin deletes any.
	if _, err := f.s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(theirs), ReplicaVm: "web-1"}); err != nil {
		t.Fatalf("an admin deleting a replica: %v", err)
	}
	if present(theirs) {
		t.Fatalf("the admin's delete left the replica")
	}
}

// C3: one fan-out run writes replicas of several VMs under one file name;
// the VM the listing shows beside it says which, and without it the delete
// refuses rather than guess.
func TestFinalPools_ContentDeleteOfASharedReplicaNameNeedsTheVM(t *testing.T) {
	f := newPoolFixture(t)
	f.grantPoolWrite(t)
	web := areaReplica(t, f.dr, "a", "web", "1", "20261007-120000")
	other := areaReplica(t, f.dr, "a", "a", "1", "20261007-120000")
	name := filepath.Base(web)
	if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: name}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an ambiguous name: got %v, want FailedPrecondition", err)
	}
	if !present(web) || !present(other) {
		t.Fatalf("an ambiguous delete removed a replica")
	}
	if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: name, ReplicaVm: "a"}); err != nil {
		t.Fatalf("delete naming the VM: %v", err)
	}
	if present(other) || !present(web) {
		t.Fatalf("delete naming vm a: a's replica present=%v, web's present=%v", present(other), present(web))
	}
}

// C3: a deleted VM's replicas stay listed to its project (its tombstone says
// whose) and are deleted the same way; nothing else could ever free them.
func TestFinalPools_ADeletedVMsReplicasAreListedAndDeleted(t *testing.T) {
	f := newPoolFixture(t)
	f.grantPoolWrite(t)
	p := areaReplica(t, f.dr, "a", "web", "1", "20261007-120000")
	if err := corrosion.DeleteVM(adminCtx(), f.s.db, "web"); err != nil {
		t.Fatal(err)
	}
	if got := listedReplicas(t, f.s, f.alice, "dr"); !slices.Contains(got, "web/"+filepath.Base(p)) {
		t.Fatalf("the deleted VM's replica is not listed to its project: %v", got)
	}
	if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(p)}); err != nil {
		t.Fatalf("deleting a deleted VM's replica: %v", err)
	}
	if present(p) {
		t.Fatalf("the deleted VM's replica is still there")
	}
}

// C3: never a replica a disk uses (a --no-localize promotion boots from it).
func TestFinalPools_ContentDeleteKeepsAnAreaReplicaADiskUses(t *testing.T) {
	f := newPoolFixture(t)
	f.grantPoolWrite(t)
	p := areaReplica(t, f.dr, "a", "web", "1", "20261007-120000")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web-dr", Project: "a", Cpu: 1, MemoryMib: 256})
	if err := corrosion.InsertVM(context.Background(), f.s.db,
		corrosion.VMRecord{Name: "web-dr", HostName: f.s.hostName, State: "stopped", Project: "a", Spec: string(spec)}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "1", HostName: f.s.hostName, Path: p, SizeBytes: 1 << 20, StorageType: "dir", StorageVolume: "dr"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DeleteStoragePoolContent(f.alice, &pb.DeleteStoragePoolContentRequest{PoolName: "dr", Filename: filepath.Base(p)}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("deleting a replica a disk uses: got %v, want FailedPrecondition", err)
	}
	if !present(p) || !present(p+".json") {
		t.Fatalf("a replica a disk uses was deleted")
	}
}

// ownPool creates local pool name in its own directory and returns it.
func ownPool(t *testing.T, s *Server, name string) string {
	t.Helper()
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: name, Driver: "local"}); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(s.dataDir, "pools", name)
}

func poolGone(t *testing.T, s *Server, name string) bool {
	t.Helper()
	_, ok, err := corrosion.GetStoragePool(adminCtx(), s.db, s.hostName, name)
	if err != nil {
		t.Fatal(err)
	}
	return !ok
}

// C4: a pool that was a replication target, whose replicas were pruned (or
// whose schedule is gone), and one that held uploads, are deleted: the
// daemon's own empty directories are not files someone left.
func TestFinalPools_PoolDeleteCleansTheDaemonsEmptyDirectories(t *testing.T) {
	s := newPoolTestServer(t)
	dir := ownPool(t, s, "dr")
	owner := replicaOwnerDir(dir, "acme", "web")
	if err := os.MkdirAll(owner, 0o700); err != nil {
		t.Fatal(err)
	}
	markers := filepath.Join(dir, uploadMarkerDir)
	if err := os.MkdirAll(markers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markers, "gone.iso"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "dr"}); err != nil {
		t.Fatalf("deleting a pool holding only the daemon's empty directories: %v", err)
	}
	if present(dir) || !poolGone(t, s, "dr") {
		t.Fatalf("pool directory present=%v, row gone=%v", present(dir), poolGone(t, s, "dr"))
	}
}

// C4: replicas still in the area refuse a plain delete (they are data) and
// go with --force — except one a disk uses, which is kept. --force always
// deletes the pool, as on main; files someone left stay, and so does the
// directory holding them.
func TestFinalPools_PoolDeleteForceAlwaysSucceeds(t *testing.T) {
	s := newPoolTestServer(t)
	dir := ownPool(t, s, "dr")
	rep := areaReplica(t, dir, "acme", "web", "root", "20261007-120000")
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "dr"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("deleting a pool holding replicas without --force: got %v, want FailedPrecondition", err)
	}
	if !present(rep) || poolGone(t, s, "dr") {
		t.Fatalf("a refused delete changed something")
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "dr", Force: true}); err != nil {
		t.Fatalf("--force: %v", err)
	}
	if present(rep) || present(dir) || !poolGone(t, s, "dr") {
		t.Fatalf("--force: replica present=%v, dir present=%v, row gone=%v", present(rep), present(dir), poolGone(t, s, "dr"))
	}

	// A file someone left, and a replica a disk uses: the pool is deleted,
	// both stay.
	dir = ownPool(t, s, "dr2")
	left := filepath.Join(dir, "notes.iso")
	if err := os.WriteFile(left, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	used := areaReplica(t, dir, "acme", "web", "root", "20261007-130000")
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "web-dr", HostName: s.hostName, State: "stopped", Project: "acme"}, nil,
		[]corrosion.DiskRecord{{VMName: "web-dr", DiskName: "root", HostName: s.hostName, Path: used, SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "dr2", Force: true}); err != nil {
		t.Fatalf("--force with files left: %v", err)
	}
	if !poolGone(t, s, "dr2") || !present(left) || !present(used) || !present(used+".json") {
		t.Fatalf("--force with files left: row gone=%v, left file=%v, used replica=%v, its record=%v",
			poolGone(t, s, "dr2"), present(left), present(used), present(used+".json"))
	}
}
