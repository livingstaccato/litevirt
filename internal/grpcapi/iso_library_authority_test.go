package grpcapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The review of the library round (restore-iso-review.md): a reference must be
// authorized wherever it is resolved, the global library is not any row named
// "isos", nothing that worked before is newly refused, a library write never
// replaces a file, and mode switches reconcile the records.

// repointPool changes which project owns a pool row on the test host, standing
// for the same-named pool of another project on the host a VM moved to.
func repointPool(t *testing.T, s *Server, name, project string) {
	t.Helper()
	rec, ok, err := corrosion.GetStoragePool(context.Background(), s.db, s.hostName, name)
	if err != nil || !ok {
		t.Fatalf("pool %s: %v", name, err)
	}
	rec.Project = project
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, rec); err != nil {
		t.Fatal(err)
	}
}

func stopVM(t *testing.T, s *Server, name string) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = ?`, name); err != nil {
		t.Fatal(err)
	}
}

// C1, start: on a host where the referenced pool belongs to another project,
// the VM does not start — whatever was true where it was created.
func TestISOAuthority_StartRefusesAnotherProjectsSameNamedPool(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	lib := projectLibrary(t, s, "b-lib", "acme")
	writeLibFile(t, filepath.Join(lib, "win-unattend.iso"), isoBody)
	if _, err := s.CreateVM(pat, isoCreate("a-vm", "b-lib/win-unattend.iso", "acme")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, "a-vm")
	// The VM was created on another host: its recorded file is that host's,
	// and here b-lib is project other's.
	spec := vmSpecFor(vmRecord(t, s, "a-vm"))
	if spec.GetIsoIdentity() == nil {
		t.Fatal("create recorded no iso_identity")
	}
	spec.IsoIdentity.Host = "creation-host"
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'a-vm'`, string(b)); err != nil {
		t.Fatal(err)
	}
	repointPool(t, s, "b-lib", "other")

	_, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "a-vm"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "other") {
		t.Fatalf("start where b-lib is project other's: got %v, want FailedPrecondition naming the owner", err)
	}
}

// C1, migration target: the target judges the reference against its own pool
// row, with the VM's project, and refuses a pool it lacks.
func TestISOAuthority_MigrationTargetJudgesItsOwnPool(t *testing.T) {
	mk := func(t *testing.T) (*Server, string) {
		s, _ := stubTarget(t)
		s.pkiDir = filepath.Join(t.TempDir(), "pki")
		spec, _ := json.Marshal(&pb.VMSpec{Name: "mig", Iso: "b-lib/win-unattend.iso", Project: "acme"})
		if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, project = 'acme' WHERE name = 'mig'`, string(spec)); err != nil {
			t.Fatal(err)
		}
		return s, ""
	}
	t.Run("another project's same-named pool", func(t *testing.T) {
		s, _ := mk(t)
		lib := projectLibrary(t, s, "b-lib", "other")
		writeLibFile(t, filepath.Join(lib, "win-unattend.iso"), isoBody)
		if _, err := ensure(s, "mig"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("target whose b-lib is project other's: got %v, want FailedPrecondition", err)
		}
	})
	t.Run("no such pool", func(t *testing.T) {
		s, _ := mk(t)
		if _, err := ensure(s, "mig"); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("target with no b-lib: got %v, want FailedPrecondition", err)
		}
	})
}

// I1: the global library row is admin-made. A root-bound Operator holds
// storage.pool.write everywhere, and still cannot create, replace or delete it.
func TestISOAuthority_GlobalLibraryRowNeedsHostPath(t *testing.T) {
	s, _, _ := isoServer(t)
	rob := isoEngineCtx(t, s, "rob", "Operator", "/")
	other := t.TempDir()
	if _, err := s.CreateStoragePool(rob, &pb.CreateStoragePoolRequest{Name: "isos", Driver: "dir", Target: other}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("root Operator creating the global library row: got %v, want PermissionDenied", err)
	}
	globalLibrary(t, s)
	if _, err := s.CreateStoragePool(rob, &pb.CreateStoragePoolRequest{Name: "isos", Driver: "dir", Target: other}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("root Operator retargeting the global library: got %v, want PermissionDenied", err)
	}
	if _, err := s.DeleteStoragePool(rob, &pb.DeleteStoragePoolRequest{Name: "isos"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("root Operator deleting the global library: got %v, want PermissionDenied", err)
	}
}

// I1: no exemption for the library row in the overlap check — an isos row on a
// directory another pool maps is refused, to an Admin too.
func TestISOAuthority_GlobalLibraryRowCannotShareADirectory(t *testing.T) {
	s, _, _ := isoServer(t)
	dir := projectLibrary(t, s, "acme-pool", "acme")
	if err := corrosion.InsertProject(context.Background(), s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "isos", Driver: "dir", Target: dir})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an isos row over a project pool's directory: got %v, want InvalidArgument", err)
	}
}

// I2: a cluster that already had an isos pool keeps using its files as they
// are — an Admin's absolute path into it starts, with no library record and
// no mode ever set.
func TestISOAuthority_AnExistingIsosPoolKeepsWorking(t *testing.T) {
	s, fake, _ := isoServer(t)
	nas := t.TempDir() // an NFS mount, say: not the daemon's pools/isos
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "isos", Driver: "dir", Target: nas, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	iso := filepath.Join(nas, "debian.iso")
	writeLibFile(t, iso, isoBody)
	if _, err := s.CreateVM(adminCtx(), isoCreate("old", iso, "")); err != nil {
		t.Fatalf("admin create with a path into the existing isos pool: %v", err)
	}
	if !strings.Contains(fake.DefinedXML("old"), iso) {
		t.Fatal("not attached")
	}
	stopVM(t, s, "old")
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "old")); err != nil {
		t.Fatalf("start: %v", err)
	}
	// With no mode set, a cluster that had an isos pool is in shared mode:
	// that pool is the global library, listed for every project.
	resp, err := s.ListISOs(adminCtx(), &pb.ListISOsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	listed := false
	for _, e := range resp.GetIsos() {
		listed = listed || (e.GetRef() == "isos/debian.iso" && e.GetGlobal())
	}
	if !listed {
		t.Fatalf("the existing isos pool is not the global library: %v", resp.GetIsos())
	}
	// Uploads to it keep working before failover_scope_v1 latches.
	s.db.SetClusterPolicyGate(func() bool { return false })
	if err := s.UploadStoragePoolContent(&fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "isos", Filename: "new.iso"}, {Chunk: []byte(isoBody)},
	}}); err != nil {
		t.Fatalf("admin upload to an existing isos pool: %v", err)
	}
}

// I2: an Admin's absolute host path is never gated by the library mode, even
// when it points into the global library.
func TestISOAuthority_AdminPathIsNotGatedByTheMode(t *testing.T) {
	s, _, _ := isoServer(t)
	libraryMode(t, s, corrosion.ISOLibrarySync)
	lib := globalLibrary(t, s)
	iso := filepath.Join(mustEval(t, lib), "unrecorded.iso")
	writeLibFile(t, iso, isoBody)
	if _, err := s.CreateVM(adminCtx(), isoCreate("adm", iso, "")); err != nil {
		t.Fatalf("admin path into the sync-mode library with no record: %v", err)
	}
}

// I3: a pull or an upload into a library never replaces a file already there.
func TestISOAuthority_LibraryWritesNeverReplace(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	dir := projectLibrary(t, s, "acme-isos", "acme")
	victim := filepath.Join(dir, "build.iso")
	writeLibFile(t, victim, isoBody)
	fetched := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fetched++; io.WriteString(w, "trojan") }))
	defer srv.Close()

	if _, err := s.PullISO(pat, &pb.PullISORequest{Ref: "acme-isos/build.iso", Url: srv.URL}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("pull over an existing library file: got %v, want FailedPrecondition", err)
	}
	if fetched != 0 {
		t.Fatalf("a pull over a taken name downloaded first (%d requests); it is refused up front", fetched)
	}
	st := &fakeUploadStream{ctx: pat, msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "acme-isos", Filename: "build.iso"}, {Chunk: []byte("trojan")},
	}}
	if err := s.UploadStoragePoolContent(st); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("upload over an existing library file: got %v, want FailedPrecondition", err)
	}
	if st.idx != 1 {
		t.Fatalf("an upload over a taken name read %d frames; it is refused after the header", st.idx)
	}
	if b, _ := os.ReadFile(victim); string(b) != isoBody {
		t.Fatalf("the library file was replaced: %q", b)
	}
}

// I3: a project library on a directory another project's pool also maps lists
// nothing from it.
func TestISOAuthority_ListingExcludesAnotherProjectsDirectory(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	shared := t.TempDir()
	for _, row := range []corrosion.StoragePoolRecord{
		{HostName: s.hostName, Name: "a-lib", Driver: "dir", Target: shared, Project: "acme", Options: map[string]string{"content": "iso"}, State: "active"},
		{HostName: s.hostName, Name: "b-pool", Driver: "dir", Target: shared, Project: "other", State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(context.Background(), s.db, row); err != nil {
			t.Fatal(err)
		}
	}
	writeLibFile(t, filepath.Join(shared, "secret-build.iso"), isoBody)
	resp, err := s.ListISOs(pat, &pb.ListISOsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range resp.GetIsos() {
		if e.GetName() == "secret-build.iso" {
			t.Fatalf("another project's file was listed through a-lib: %+v", e)
		}
	}
}

// I5: a tombstone from an earlier sync period does not delete a file put in
// the library after a switch through shared mode.
func TestISOAuthority_ModeSwitchReconcilesRecords(t *testing.T) {
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	lib := globalLibrary(t, s)
	if _, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "sync"}); err != nil {
		t.Fatal(err)
	}
	up := func(name string) {
		t.Helper()
		if err := s.UploadStoragePoolContent(&fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
			{PoolName: "isos", Filename: name}, {Chunk: []byte(isoBody)},
		}}); err != nil {
			t.Fatalf("upload %s: %v", name, err)
		}
	}
	up("debian.iso")
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "isos", Filename: "debian.iso"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "shared"}); err != nil {
		t.Fatal(err)
	}
	writeLibFile(t, filepath.Join(lib, "debian.iso"), isoBody+" v2")
	if _, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "sync"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncISOLibrary(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(lib, "debian.iso")); err != nil || string(b) != isoBody+" v2" {
		t.Fatalf("the re-added file was removed by a stale tombstone: %q %v", b, err)
	}
}

// ── tests of the fix-round API (they do not compile on 54e58ed9) ──

func libraryVM(t *testing.T, s *Server, name, project string) (lib, path string) {
	t.Helper()
	lib = projectLibrary(t, s, "acme-isos", project)
	writeLibFile(t, filepath.Join(lib, "install.iso"), isoBody)
	spec, _ := json.Marshal(&pb.VMSpec{Name: name, Iso: "acme-isos/install.iso", IsoScope: isoScopeProject, Project: project})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, project = ? WHERE name = ?`, string(spec), project, name); err != nil {
		t.Fatal(err)
	}
	return lib, filepath.Join(mustEval(t, lib), "install.iso")
}

// C1, live migration: libvirt hands qemu on the target the source's path, so
// the target's resolution must be that very file; a stopped (cold) move is
// pointed at the target's file when it starts instead.
func TestISOAuthority_RuntimeMigrationNeedsTheSamePath(t *testing.T) {
	s, _ := stubTarget(t)
	_, here := libraryVM(t, s, "mig", "acme")
	run := func(paths []string, runtime bool) error {
		_, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
			InstallerIsoListed: true, InstallerIsoPaths: paths, InstallerIsoRuntime: runtime})
		return err
	}
	if err := run([]string{here}, true); err != nil {
		t.Fatalf("live migration, same library path: %v", err)
	}
	if err := run([]string{"/srv/source-host/isos/install.iso"}, true); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("live migration, the source's path differs: got %v, want FailedPrecondition", err)
	}
	if err := run([]string{"/srv/source-host/isos/install.iso"}, false); err != nil {
		t.Fatalf("stopped move, different path (repointed at start): %v", err)
	}
	if err := run(nil, true); err != nil {
		t.Fatalf("a domain that carries no installer CD-ROM: %v", err)
	}
}

// C1, live migration: a target lacking the pool refuses, rather than letting
// qemu open whatever the source's path names here.
func TestISOAuthority_RuntimeMigrationTargetWithoutThePoolRefuses(t *testing.T) {
	s, disks := stubTarget(t)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mig", Iso: "a-lib/foo.iso", IsoScope: isoScopeProject, Project: "acme"})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, project = 'acme' WHERE name = 'mig'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(disks, "foo.iso") // another project's upload on this host
	writeLibFile(t, theirs, "B's file")
	_, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
		InstallerIsoListed: true, InstallerIsoPaths: []string{theirs}, InstallerIsoRuntime: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("live migration to a host without a-lib: got %v, want FailedPrecondition", err)
	}
}

// An Admin's host path on a migration target is judged as itself and must be
// there.
func TestISOAuthority_MigrationTargetJudgesAnAdminPath(t *testing.T) {
	s, _ := stubTarget(t)
	p := filepath.Join(t.TempDir(), "virtio-win.iso")
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mig", Iso: p, IsoScope: isoScopeHostPath})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'mig'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	req := &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true, InstallerIsoPaths: []string{p}, InstallerIsoRuntime: true}
	if _, err := s.EnsureDisks(adminCtx(), req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("admin path missing on the target: got %v, want FailedPrecondition", err)
	}
	writeLibFile(t, p, isoBody)
	if _, err := s.EnsureDisks(adminCtx(), req); err != nil {
		t.Fatalf("admin path present on the target: %v", err)
	}
}

// The kind of pool is recorded at create, and a host where the reference
// resolves to another kind refuses: in sync mode an "isos" row that is not the
// daemon's pools/isos is not the global library.
func TestISOAuthority_TheRecordedKindIsHeldEverywhere(t *testing.T) {
	s, _, _ := isoServer(t)
	libraryMode(t, s, corrosion.ISOLibraryShared)
	lib := globalLibrary(t, s)
	writeLibFile(t, filepath.Join(lib, "debian.iso"), isoBody)
	pat := acmeOperator(t, s)
	if _, err := s.CreateVM(pat, isoCreate("g", "isos/debian.iso", "acme")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if got := vmSpecFor(vmRecord(t, s, "g")).GetIsoScope(); got != isoScopeGlobal {
		t.Fatalf("recorded iso_scope = %q, want global", got)
	}
	stopVM(t, s, "g")
	libraryMode(t, s, corrosion.ISOLibrarySync)
	other := t.TempDir()
	writeLibFile(t, filepath.Join(other, "debian.iso"), isoBody)
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "isos", Driver: "dir", Target: other, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	_, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "g"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "created with a global one") {
		t.Fatalf("start where isos is not the global library: got %v, want FailedPrecondition naming the kinds", err)
	}
}

// iso_scope is server-owned: a client's is dropped, and a forwarded leg keeps
// the entry's classification rather than its own peer (admin) authority.
func TestISOAuthority_ScopeIsServerOwned(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	p := filepath.Join(t.TempDir(), "x.iso")
	writeLibFile(t, p, isoBody)
	req := isoCreate("c", p, "acme")
	req.Spec.IsoScope = isoScopeHostPath
	if _, err := s.CreateVM(pat, req); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator claiming iso_scope hostpath: got %v, want PermissionDenied", err)
	}

	dir := projectLibrary(t, s, "acme-isos", "acme")
	iso := filepath.Join(dir, "in-pool.iso")
	writeLibFile(t, iso, isoBody)
	ref := isoCreate("r", "acme-isos/in-pool.iso", "acme")
	ref.Spec.IsoScope = isoScopeHostPath // a client's claim is dropped, not judged
	if _, err := s.CreateVM(pat, ref); err != nil {
		t.Fatalf("a reference with a client-supplied iso_scope: %v", err)
	}
	peer := peerCtxFor(t, s, "entry-node")
	peer = context.WithValue(peer, ctxKeyUsername, "entry-node")
	peer = context.WithValue(peer, ctxKeyRole, "admin")
	fwd := isoCreate("f", iso, "acme")
	fwd.Spec.IsoScope = isoScopeProject
	if _, err := s.CreateVM(peer, fwd); err != nil {
		t.Fatalf("forwarded create: %v", err)
	}
	if got := vmSpecFor(vmRecord(t, s, "f")).GetIsoScope(); got != isoScopeProject {
		t.Fatalf("the owner recorded %q for an entry-classified project pool path, want project", got)
	}
}

// I4: the file is opened without following a link at the last moment before
// it is handed to qemu, so a swap after the name was judged is refused.
func TestISOAuthority_OpenTimeSwapIsRefused(t *testing.T) {
	s, _, key := isoServer(t)
	_, iso := libraryVMStopped(t, s, "race")
	t.Cleanup(func() { isoBeforeOpen = nil })
	isoBeforeOpen = func(p string) {
		if p == iso || strings.HasSuffix(p, "/install.iso") {
			_ = os.Remove(p)
			_ = os.Symlink(key, p)
		}
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "race")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the ISO swapped for a link between the check and the open: got %v, want FailedPrecondition", err)
	}
}

// I5: a tombstone is collected once every library host has applied it, not
// before; a re-added file clears it.
func TestISOAuthority_TombstonesAreCollectedOnceApplied(t *testing.T) {
	ctx := context.Background()
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	globalLibrary(t, s)
	other := t.TempDir()
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: "host-b", Name: "isos", Driver: "dir", Target: filepath.Join(other, "pools", "isos"), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "sync"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UploadStoragePoolContent(&fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "isos", Filename: "gone.iso"}, {Chunk: []byte(isoBody)},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "isos", Filename: "gone.iso"}); err != nil {
		t.Fatal(err)
	}
	tomb := func() (corrosion.ISOCatalogEntry, bool) {
		all, _ := corrosion.ListISOCatalog(ctx, s.db)
		for _, e := range all {
			if e.Name == "gone.iso" {
				return e, true
			}
		}
		return corrosion.ISOCatalogEntry{}, false
	}
	if err := s.SyncISOLibrary(ctx); err != nil {
		t.Fatal(err)
	}
	if e, _ := tomb(); !e.Deleted {
		t.Fatalf("the tombstone was collected while host-b had not applied it: %+v", e)
	}
	mode, _ := corrosion.GetISOLibraryMode(ctx, s.db)
	if err := corrosion.PutISOLibraryHostAck(ctx, s.db, corrosion.ISOLibraryHostAck{Host: "host-b", Gen: mode.UpdatedAt, AppliedThrough: s.db.NowTS()}); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncISOLibrary(ctx); err != nil {
		t.Fatal(err)
	}
	if e, _ := tomb(); !e.Collected() {
		t.Fatalf("the tombstone every host applied was not collected: %+v", e)
	}
	// Re-added: a positive record again.
	if err := s.UploadStoragePoolContent(&fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "isos", Filename: "gone.iso"}, {Chunk: []byte(isoBody)},
	}}); err != nil {
		t.Fatal(err)
	}
	if e, ok, _ := corrosion.GetISOCatalogEntry(ctx, s.db, "gone.iso"); !ok || e.Deleted || e.SHA256 != sha(isoBody) {
		t.Fatalf("a re-added file is not recorded: %+v %v", e, ok)
	}
}

// hookedUploadStream runs before(i) before handing out frame i.
type hookedUploadStream struct {
	fakeUploadStream
	before func(i int)
}

func (h *hookedUploadStream) Recv() (*pb.UploadStoragePoolContentRequest, error) {
	if h.before != nil {
		h.before(h.idx)
	}
	return h.fakeUploadStream.Recv()
}

// I3: the publish itself is no-replace — a name taken while the bytes were
// being written (after the up-front check) is not replaced either.
func TestISOAuthority_ANameTakenDuringAWriteIsNotReplaced(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	dir := projectLibrary(t, s, "acme-isos", "acme")
	victim := filepath.Join(dir, "build.iso")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeLibFile(t, victim, isoBody) // B uploads it while A's pull streams
		io.WriteString(w, "trojan")
	}))
	defer srv.Close()
	if _, err := s.PullISO(pat, &pb.PullISORequest{Ref: "acme-isos/build.iso", Url: srv.URL}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("pull racing another write of the name: got %v, want FailedPrecondition", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != isoBody {
		t.Fatalf("the library file was replaced by a pull: %q", b)
	}

	other := filepath.Join(dir, "other.iso")
	st := &hookedUploadStream{
		fakeUploadStream: fakeUploadStream{ctx: pat, msgs: []*pb.UploadStoragePoolContentRequest{
			{PoolName: "acme-isos", Filename: "other.iso"}, {Chunk: []byte("trojan")},
		}},
		before: func(i int) {
			if i == 1 {
				writeLibFile(t, other, isoBody)
			}
		},
	}
	if err := s.UploadStoragePoolContent(st); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("upload racing another write of the name: got %v, want FailedPrecondition", err)
	}
	if b, _ := os.ReadFile(other); string(b) != isoBody {
		t.Fatalf("the library file was replaced by an upload: %q", b)
	}
}
