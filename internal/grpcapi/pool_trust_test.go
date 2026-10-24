package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// trustServer is newPoolTestServer judging its pool rows, as every real
// server does (NewServer).
func trustServer(t *testing.T) *Server {
	t.Helper()
	s := newPoolTestServer(t)
	s.pkiDir = t.TempDir()
	pt, err := pooltrust.Open(s.dataDir, s.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetPoolTrust(pt)
	return s
}

// forgeRow writes, as replication would apply it, a storage_pools row naming
// s's host that s never created.
func forgeRow(t *testing.T, s *Server, name, dir string) {
	t.Helper()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "dir", Target: dir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
}

func uploadTo(s *Server, pool, name string, data []byte) error {
	st := &fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: pool, Filename: name},
		{Chunk: data},
	}}
	return s.UploadStoragePoolContent(st)
}

// The attack (X1): a row naming this host, written by another member or
// injected into replication, names a directory outside this host's pool
// areas. Even once it is in the in-memory pool map — what the daemon's
// refresh tick did with every row — this host refuses it as a disk root (the
// migration receive's gate), for an upload, a content delete and a listing,
// and resolves no pool by its name. Confirming it with TrustStoragePool
// (`lv pool trust`) makes it this host's pool, audited.
//
// Mutations: drop the trust check from poolRefusal — the receive, upload,
// delete and list rows go red; drop it from lookupStoragePool — the lookup
// row goes red; drop it from resolvePoolErr's table fallback (with the map
// entry removed) — the resolve row goes red.
func TestPoolTrust_ForgedRowIsNoDiskRoot(t *testing.T) {
	s := trustServer(t)
	outside := filepath.Join(t.TempDir(), "srv-pwn")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(outside, "victim.iso")
	if err := os.WriteFile(victim, []byte("victim"), 0o644); err != nil {
		t.Fatal(err)
	}
	forgeRow(t, s, "forged", outside)
	s.SetStoragePoolsByName(map[string]StoragePoolRef{"forged": {Driver: "dir", Target: outside}})

	if s.withinDiskArtifactRoot(filepath.Join(outside, "x.qcow2")) {
		t.Error("receive: a forged row's directory is a disk-artifact root")
	}
	if err := uploadTo(s, "forged", "pwn.iso", []byte("attacker bytes")); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv pool trust") {
		t.Errorf("upload into a forged row's directory: %v, want FailedPrecondition naming lv pool trust", err)
	}
	if _, err := os.Lstat(filepath.Join(outside, "pwn.iso")); err == nil {
		t.Error("upload: a file was written into a forged row's directory")
	}
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "forged", Filename: "victim.iso"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("content delete in a forged row's directory: %v, want FailedPrecondition", err)
	}
	if b, err := os.ReadFile(victim); err != nil || string(b) != "victim" {
		t.Errorf("content delete removed or changed %s: %q %v", victim, b, err)
	}
	if _, err := s.ListStoragePoolContents(adminCtx(), &pb.ListStoragePoolContentsRequest{PoolName: "forged"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("listing a forged row's directory: %v, want FailedPrecondition", err)
	}
	if _, ok := s.lookupStoragePool("forged"); ok {
		t.Error("lookup: a forged row's pool resolves from the map")
	}
	s.removeStoragePoolRef("forged")
	if _, ok, err := s.resolvePoolErr(context.Background(), "forged"); ok || err != nil {
		t.Errorf("resolve: a forged row's pool resolves from the table (ok %t, err %v)", ok, err)
	}
	if rows, _ := s.ownPools(context.Background()); len(rows) != 0 {
		t.Errorf("ownPools lists the forged row: %+v", rows)
	}

	// `lv pool trust`: the operator checked it and confirms it.
	resp, err := s.TrustStoragePool(adminCtx(), &pb.TrustStoragePoolRequest{Name: "forged", Driver: "dir", Target: outside})
	if err != nil || resp.GetAlreadyTrusted() || resp.GetTrustedAs() != pooltrust.TrustLedger {
		t.Fatalf("TrustStoragePool = %+v, %v; want newly trusted through the ledger", resp, err)
	}
	if !s.withinDiskArtifactRoot(filepath.Join(outside, "x.qcow2")) {
		t.Error("a confirmed pool is not a disk-artifact root")
	}
	if err := uploadTo(s, "forged", "ok.iso", []byte("operator bytes")); err != nil {
		t.Errorf("upload into a confirmed pool: %v", err)
	}
	rows, err := s.db.Query(context.Background(), `SELECT target, detail FROM audit_log WHERE action = 'storage.pool.trust'`)
	if err != nil || len(rows) != 1 || rows[0].String("target") != "forged" || !strings.Contains(rows[0].String("detail"), outside) {
		t.Errorf("audit of the trust = %+v (%v), want one storage.pool.trust row naming the pool and its target", rows, err)
	}
	if e, ok := s.PoolTrust().Entry("forged"); !ok || e.How != pooltrust.HowTrust {
		t.Errorf("ledger entry = %+v %t, want how=trust", e, ok)
	}
}

// What the operator confirms is the row as they checked it: a row changed
// since is refused, and nothing is recorded. Confirming needs storage.hostpath
// at the root, as naming the path in a create does.
//
// Mutations: skip the binding comparison — the changed-row case goes red;
// skip authorizePoolHostPaths — the operator case goes red.
func TestPoolTrust_TrustBindsToTheCheckedRowAndNeedsHostPathAuthority(t *testing.T) {
	s := trustServer(t)
	dir := filepath.Join(t.TempDir(), "pool")
	forgeRow(t, s, "p", dir)
	_, err := s.TrustStoragePool(adminCtx(), &pb.TrustStoragePoolRequest{Name: "p", Driver: "dir", Target: filepath.Join(t.TempDir(), "what-i-saw")})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("trust of a row that changed since it was checked: %v, want FailedPrecondition", err)
	}
	if _, ok := s.PoolTrust().Entry("p"); ok {
		t.Fatal("a refused trust recorded the pool")
	}
	op := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "oscar"), ctxKeyRole, "operator")
	if _, err := s.TrustStoragePool(op, &pb.TrustStoragePoolRequest{Name: "p", Driver: "dir", Target: dir}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator confirming a host path: %v, want PermissionDenied", err)
	}
	if _, ok := s.PoolTrust().Entry("p"); ok {
		t.Fatal("a denied trust recorded the pool")
	}
}

// A pool created on this host is recorded in its ledger before its row is
// written, bound to its target: the row is trusted, a forged rewrite of it to
// another target is not, and a delete takes it out of the ledger.
//
// Mutations: drop the Record in CreateStoragePool — the created pool is
// refused, red; drop the Forget in DeleteStoragePool — the re-forged row is
// trusted, red.
func TestPoolTrust_CreateRecordsDeleteForgets(t *testing.T) {
	s := trustServer(t)
	dir := filepath.Join(t.TempDir(), "made")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "made", Driver: "dir", Target: dir}); err != nil {
		t.Fatalf("CreateStoragePool: %v", err)
	}
	if err := s.checkPoolForWrite(context.Background(), "made", StoragePoolRef{Driver: "dir", Target: dir}); err != nil {
		t.Fatalf("a pool this host created is refused: %v", err)
	}
	if e, ok := s.PoolTrust().Entry("made"); !ok || e.How != pooltrust.HowCreate {
		t.Fatalf("ledger entry = %+v %t, want how=create", e, ok)
	}
	if err := s.checkPoolForWrite(context.Background(), "made", StoragePoolRef{Driver: "dir", Target: "/var/lib/cloud/seed/nocloud"}); err == nil {
		t.Fatal("a forged rewrite of a created pool to another target is trusted")
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "made"}); err != nil {
		t.Fatalf("DeleteStoragePool: %v", err)
	}
	if _, ok := s.PoolTrust().Entry("made"); ok {
		t.Fatal("a deleted pool is still in the ledger")
	}
	forgeRow(t, s, "made", dir)
	if s.poolRowTrusted(corrosion.StoragePoolRecord{HostName: s.hostName, Name: "made", Driver: "dir", Target: dir}) {
		t.Fatal("a row brought back after a delete is trusted on the strength of the deleted pool")
	}
}

// A forged row's delete removes the row only: nothing at the place it names is
// torn down or removed.
//
// Mutation: drop the untrusted branch — the fake's pool destroy is called for
// the forged row, red.
func TestPoolTrust_DeleteOfAnUntrustedRowTouchesNothing(t *testing.T) {
	s := trustServer(t)
	fake := libvirtfake.New()
	destroyed := 0
	fake.FailPoolDestroy = func(string) error { destroyed++; return nil }
	s.virt = fake
	dir := filepath.Join(t.TempDir(), "forged")
	forgeRow(t, s, "forged", dir)
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "forged"}); err != nil {
		t.Fatalf("DeleteStoragePool: %v", err)
	}
	if destroyed != 0 {
		t.Error("deleting a forged row called the libvirt pool teardown")
	}
	if _, ok, _ := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, "forged"); ok {
		t.Error("the forged row was not deleted")
	}
}

// pool_row_untrusted names each untrusted row of this host with the command
// that confirms it, and resolves once there are none.
//
// Mutation: skip a trusted row's exclusion in UntrustedPools — the area pool
// is named, red; never resolve — red.
func TestPoolTrust_ConditionNamesUntrustedRows(t *testing.T) {
	s := trustServer(t)
	ctx := context.Background()
	forgeRow(t, s, "forged", filepath.Join(t.TempDir(), "x"))
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "inarea", Driver: "dir", Target: filepath.Join(s.dataDir, "pools", "inarea"), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	s.JudgePoolTrust(ctx)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, poolTrustEvaluator, condPoolRowUntrusted, "host", s.hostName)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition = %+v found=%t err=%v, want raised", row, found, err)
	}
	var ev struct {
		Pools  []untrustedPool `json:"pools"`
		Detail string          `json:"detail"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	if len(ev.Pools) != 1 || ev.Pools[0].Pool != "forged" || !strings.Contains(ev.Detail, "lv pool trust") {
		t.Fatalf("evidence = %+v, want only the forged pool and the confirming command", ev)
	}
	if _, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: "forged"}); err != nil {
		t.Fatal(err)
	}
	s.JudgePoolTrust(ctx)
	row, _, _ = corrosion.GetHealthCondition(ctx, s.db, poolTrustEvaluator, condPoolRowUntrusted, "host", s.hostName)
	if row.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("condition = %s after the forged row went, want resolved", row.Lifecycle)
	}
}

// An ISO library row this host did not make is not one of its libraries:
// `lv iso pull` fetches nothing into the directory it names, and `lv iso ls`
// does not read it. Confirmed, it is a library like any other.
//
// Mutations: drop checkPoolTrusted from PullISO — the pull copies the file
// into the forged directory, red; drop the trust filter in ListISOs — the
// forged directory's ISO is listed, red.
func TestPoolTrust_ForgedISOLibraryIsNotOne(t *testing.T) {
	s, _, _ := isoServer(t)
	pt, err := pooltrust.Open(s.dataDir, s.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetPoolTrust(pt)
	dir := projectLibrary(t, s, "acme-isos", "acme")
	writeLibFile(t, filepath.Join(dir, "planted.iso"), opticalImage("planted"))
	src := filepath.Join(t.TempDir(), "debian.iso")
	writeLibFile(t, src, opticalImage("debian"))

	if _, err := s.PullISO(adminCtx(), &pb.PullISORequest{Ref: "acme-isos/debian.iso", HostPath: src}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("pull into a forged library: %v, want FailedPrecondition", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "debian.iso")); err == nil {
		t.Error("pull wrote into a forged library's directory")
	}
	ls, err := s.ListISOs(adminCtx(), &pb.ListISOsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ls.GetIsos() {
		if e.GetPool() == "acme-isos" {
			t.Errorf("lv iso ls lists %s from a forged library", e.GetRef())
		}
	}
	if _, err := s.TrustStoragePool(adminCtx(), &pb.TrustStoragePoolRequest{Name: "acme-isos", Driver: "dir", Target: dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PullISO(adminCtx(), &pb.PullISORequest{Ref: "acme-isos/debian.iso", HostPath: src}); err != nil {
		t.Errorf("pull into the confirmed library: %v", err)
	}
}

// A forged nfs row naming this host is not mounted by the mount reconcile:
// a forged export laid over a directory of the attacker's choosing is the
// same write as a forged directory pool. Confirmed, it is mounted.
//
// Mutation: list every row in ReconcileNFSMounts (ownPools → the raw list) —
// the forged export is mounted, red.
func TestPoolTrust_ForgedNFSRowIsNotMounted(t *testing.T) {
	s, _ := provableCreateServer(t)
	pt, err := pooltrust.Open(s.dataDir, s.pkiDir)
	if err != nil {
		t.Fatal(err)
	}
	s.SetPoolTrust(pt)
	m := installHostMounts(t)
	target := filepath.Join(t.TempDir(), "seed")
	dir := nfsPoolRowAt(t, s, "forged", "evil.example:/x", target)
	s.ReconcileNFSMounts(context.Background())
	if m.count() != 0 || m.mounted(dir) {
		t.Fatalf("the mount reconcile mounted a forged row's export at %s", dir)
	}
	if err := pt.Record("forged", pooltrust.Binding{Driver: "nfs", Source: "evil.example:/x", Target: target}, pooltrust.HowTrust); err != nil {
		t.Fatal(err)
	}
	s.ReconcileNFSMounts(context.Background())
	if !m.mounted(dir) {
		t.Fatal("a confirmed nfs pool was not mounted")
	}
}

// The startup sweep removes stale staging temps only from this host's
// trusted pool directories: a forged row cannot aim its deletes.
//
// Mutation: list every row in SweepStaleStaging — the forged directory's
// file is removed, red.
func TestPoolTrust_StagingSweepSkipsAForgedRow(t *testing.T) {
	s := trustServer(t)
	dir := filepath.Join(t.TempDir(), "forged")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	forgeRow(t, s, "forged", dir)
	p := filepath.Join(dir, ".web-1-root-20260920T010000Z.qcow2.partial")
	if err := os.WriteFile(p, []byte("someone's file"), 0o600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatal(err)
	}
	s.SweepStaleStaging(context.Background())
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("the sweep removed a file in a forged row's directory: %v", err)
	}
	if err := s.PoolTrust().Record("forged", pooltrust.Binding{Driver: "dir", Target: dir}, pooltrust.HowTrust); err != nil {
		t.Fatal(err)
	}
	s.SweepStaleStaging(context.Background())
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("the positive control: a confirmed pool's stale temp was not swept (%v)", err)
	}
}

// Every real server judges its pool rows: NewServer installs the store.
//
// Mutation: drop the store from NewServer — red.
func TestNewServer_JudgesPoolRows(t *testing.T) {
	s := NewServer("h1", t.TempDir(), t.TempDir(), nil, nil, nil)
	if s.PoolTrust() == nil {
		t.Fatal("NewServer installs no pool trust store: every replicated row naming the host would be acted on")
	}
}
