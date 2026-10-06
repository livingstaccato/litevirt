package grpcapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ISO libraries: a VM names its ISO as <pool>/<file>.iso, and the host resolves
// that to a plain file directly in the pool's directory, at create and at every
// start. These tests prove the workflows that were taken away work again —
// installer media for every project from one global library, a project's own
// library, virtio-win pulled in from /usr/share — and that every attack the
// restrictions closed is still refused.

const isoBody = "CD001 installer"

func sha(b string) string {
	h := sha256.Sum256([]byte(b))
	return hex.EncodeToString(h[:])
}

// globalLibrary registers the built-in global library on the test host and
// returns its directory.
func globalLibrary(t *testing.T, s *Server) string {
	t.Helper()
	dir := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: globalISOLibrary, Driver: "dir", Target: dir,
		Options: GlobalISOLibraryOptions(), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// projectLibrary registers a project's ISO library (content=iso).
func projectLibrary(t *testing.T, s *Server, name, project string) string {
	t.Helper()
	dir := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "dir", Target: dir, Project: project,
		Options: map[string]string{"content": "iso"}, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func libraryMode(t *testing.T, s *Server, mode string) {
	t.Helper()
	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetISOLibraryMode(context.Background(), s.db, mode, "test"); err != nil {
		t.Fatal(err)
	}
}

func writeLibFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func storedISO(t *testing.T, s *Server, name string) string {
	t.Helper()
	rec := vmRecord(t, s, name)
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(rec.Spec), &spec); err != nil {
		t.Fatal(err)
	}
	return spec.Iso
}

func acmeOperator(t *testing.T, s *Server) context.Context {
	t.Helper()
	for _, p := range []string{"acme", "other"} {
		if err := corrosion.InsertProject(context.Background(), s.db, corrosion.ProjectRecord{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	return isoEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
}

// ── the workflows ──

// A project operator boots from the global library by reference. The spec keeps
// the reference; the domain carries the file it resolved to on the host.
func TestISOLibrary_ProjectOperatorUsesTheGlobalLibrary(t *testing.T) {
	s, fake, _ := isoServer(t)
	pat := acmeOperator(t, s)
	libraryMode(t, s, corrosion.ISOLibraryShared)
	dir := globalLibrary(t, s)
	writeLibFile(t, filepath.Join(dir, "debian-12.iso"), isoBody)

	if _, err := s.CreateVM(pat, isoCreate("inst", "isos/debian-12.iso", "acme")); err != nil {
		t.Fatalf("a project operator naming a global-library ISO: %v", err)
	}
	if got := storedISO(t, s, "inst"); got != "isos/debian-12.iso" {
		t.Fatalf("stored iso = %q, want the reference", got)
	}
	want := filepath.Join(mustEval(t, dir), "debian-12.iso")
	if !strings.Contains(fake.DefinedXML("inst"), want) {
		t.Fatalf("the domain does not carry %s:\n%s", want, fake.DefinedXML("inst"))
	}
}

func mustEval(t *testing.T, p string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// A project's own library works for its operators and no one else's VMs.
func TestISOLibrary_ProjectLibraryIsTheProjects(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	mine := projectLibrary(t, s, "acme-isos", "acme")
	theirs := projectLibrary(t, s, "other-isos", "other")
	writeLibFile(t, filepath.Join(mine, "win11.iso"), isoBody)
	writeLibFile(t, filepath.Join(theirs, "secret-build.iso"), isoBody)

	if _, err := s.CreateVM(pat, isoCreate("mine", "acme-isos/win11.iso", "acme")); err != nil {
		t.Fatalf("own project library: %v", err)
	}
	_, err := s.CreateVM(pat, isoCreate("theirs", "other-isos/secret-build.iso", "acme"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("another project's library: got %v, want PermissionDenied", err)
	}
}

// What earlier specs stored — an absolute path to a .iso directly in a pool
// directory — still works for a non-admin, and is kept as that pool's reference.
func TestISOLibrary_AnEarlierPoolPathBecomesItsReference(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	dir := projectLibrary(t, s, "acme-isos", "acme")
	iso := filepath.Join(dir, "old.iso")
	writeLibFile(t, iso, isoBody)

	if _, err := s.CreateVM(pat, isoCreate("old", iso, "acme")); err != nil {
		t.Fatalf("a non-admin re-creating from a stored pool path: %v", err)
	}
	if got := storedISO(t, s, "old"); got != "acme-isos/old.iso" {
		t.Fatalf("stored iso = %q, want acme-isos/old.iso", got)
	}
}

// An Admin may still name any host path that is not refused (unchanged).
func TestISOLibrary_AdminHostPathStillWorks(t *testing.T) {
	s, fake, _ := isoServer(t)
	p := filepath.Join(t.TempDir(), "virtio-win.iso")
	writeLibFile(t, p, isoBody)
	if _, err := s.CreateVM(adminCtx(), isoCreate("adm", p, "")); err != nil {
		t.Fatalf("admin host path: %v", err)
	}
	if got := storedISO(t, s, "adm"); got != p {
		t.Fatalf("an admin's host path was rewritten to %q", got)
	}
	if !strings.Contains(fake.DefinedXML("adm"), p) {
		t.Fatal("the admin's ISO was not attached")
	}
}

// virtio-win installs to /usr/share as a link to a versioned file. An Admin
// pulls it into the global library by host path: a copy, never a link, and
// every project can then boot it by reference.
func TestISOLibrary_AdminPullsAHostFileIntoTheLibrary(t *testing.T) {
	s, _, _ := isoServer(t)
	libraryMode(t, s, corrosion.ISOLibrarySync)
	dir := globalLibrary(t, s)
	src := t.TempDir()
	real := filepath.Join(src, "virtio-win-0.1.240.iso")
	writeLibFile(t, real, isoBody)
	link := filepath.Join(src, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}

	resp, err := s.PullISO(adminCtx(), &pb.PullISORequest{Ref: "isos/virtio-win.iso", HostPath: link})
	if err != nil {
		t.Fatalf("admin pull from a host path: %v", err)
	}
	if resp.GetSha256() != sha(isoBody) {
		t.Fatalf("sha256 = %s", resp.GetSha256())
	}
	dest := filepath.Join(dir, "virtio-win.iso")
	fi, err := os.Lstat(dest)
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("library file is not a plain file: %v %v", fi, err)
	}
	if n, _ := linkCount(fi); n != 1 {
		t.Fatalf("library file has %d links; a pull must copy", n)
	}
	if e, ok, _ := corrosion.GetISOCatalogEntry(context.Background(), s.db, "virtio-win.iso"); !ok || e.SHA256 != sha(isoBody) {
		t.Fatalf("sync mode: the library record is %+v (found %v)", e, ok)
	}
	pat := acmeOperator(t, s)
	if _, err := s.CreateVM(pat, isoCreate("win", "isos/virtio-win.iso", "acme")); err != nil {
		t.Fatalf("a project operator booting the pulled ISO: %v", err)
	}
}

// A project operator pulls a URL into its own library, under the image-pull
// limits.
func TestISOLibrary_OperatorPullsAURLIntoItsLibrary(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	dir := projectLibrary(t, s, "acme-isos", "acme")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, isoBody) }))
	defer srv.Close()

	if _, err := s.PullISO(pat, &pb.PullISORequest{Ref: "acme-isos/net.iso", Url: srv.URL + "/net.iso", Checksum: sha(isoBody)}); err != nil {
		t.Fatalf("operator URL pull into its library: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "net.iso")); string(b) != isoBody {
		t.Fatalf("pulled content = %q", b)
	}
	_, err := s.PullISO(pat, &pb.PullISORequest{Ref: "acme-isos/bad.iso", Url: srv.URL + "/x", Checksum: sha("other")})
	if err == nil {
		t.Fatal("a pull whose checksum does not match was accepted")
	}
	if _, serr := os.Stat(filepath.Join(dir, "bad.iso")); !os.IsNotExist(serr) {
		t.Fatal("a mismatched pull left a file in the library")
	}
	if _, err := s.PullISO(pat, &pb.PullISORequest{Ref: "acme-isos/f.iso", Url: "file:///etc/passwd"}); err == nil {
		t.Fatal("a file:// pull was accepted")
	}
}

// Listing shows the caller's project libraries, then the global library, and
// nothing a VM could not boot.
func TestISOLibrary_ListShowsProjectLibrariesThenTheGlobalOne(t *testing.T) {
	s, _, key := isoServer(t)
	pat := acmeOperator(t, s)
	libraryMode(t, s, corrosion.ISOLibraryShared)
	g := globalLibrary(t, s)
	mine := projectLibrary(t, s, "acme-isos", "acme")
	theirs := projectLibrary(t, s, "other-isos", "other")
	writeLibFile(t, filepath.Join(g, "debian-12.iso"), isoBody)
	writeLibFile(t, filepath.Join(mine, "win11.iso"), isoBody)
	writeLibFile(t, filepath.Join(mine, "notes.txt"), "x")
	writeLibFile(t, filepath.Join(theirs, "theirs.iso"), isoBody)
	if err := os.Symlink(key, filepath.Join(mine, "key.iso")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(mine, "win11.iso"), filepath.Join(mine, "twin.iso")); err != nil {
		t.Fatal(err)
	}

	resp, err := s.ListISOs(pat, &pb.ListISOsRequest{})
	if err != nil {
		t.Fatalf("ListISOs: %v", err)
	}
	var refs []string
	for _, e := range resp.GetIsos() {
		refs = append(refs, e.GetRef())
	}
	if got, want := strings.Join(refs, ","), "isos/debian-12.iso"; !strings.HasSuffix(got, want) || len(refs) != 1 {
		// win11.iso has a second link (twin.iso) now, so neither is bootable.
		t.Fatalf("listing = %v, want only %s (the hard-linked pair, the link, the .txt and another project's library are not listed)", refs, want)
	}
	if err := os.Remove(filepath.Join(mine, "twin.iso")); err != nil {
		t.Fatal(err)
	}
	resp, _ = s.ListISOs(pat, &pb.ListISOsRequest{})
	refs = refs[:0]
	for _, e := range resp.GetIsos() {
		refs = append(refs, e.GetRef())
	}
	if got := strings.Join(refs, ","); got != "acme-isos/win11.iso,isos/debian-12.iso" {
		t.Fatalf("listing = %s, want the project library first, then the global one", got)
	}
}

// ── the attacks, still refused ──

// Everything a library reference could be twisted into.
func TestISOLibrary_AttacksThroughAReference(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server, lib string) string{
		"a symlink to the host key": func(t *testing.T, s *Server, lib string) string {
			if err := os.Symlink(filepath.Join(s.pkiDir, "host.key"), filepath.Join(lib, "key.iso")); err != nil {
				t.Fatal(err)
			}
			return "acme-isos/key.iso"
		},
		"a symlink to an unlisted host file": func(t *testing.T, s *Server, lib string) string {
			out := filepath.Join(t.TempDir(), "host-only.iso")
			writeLibFile(t, out, "not for the guest")
			if err := os.Symlink(out, filepath.Join(lib, "out.iso")); err != nil {
				t.Fatal(err)
			}
			return "acme-isos/out.iso"
		},
		"a hard link to another file": func(t *testing.T, s *Server, lib string) string {
			other := filepath.Join(lib, "other.bin")
			writeLibFile(t, other, "another file")
			if err := os.Link(other, filepath.Join(lib, "twin.iso")); err != nil {
				t.Fatal(err)
			}
			return "acme-isos/twin.iso"
		},
		"traversal in the reference": func(t *testing.T, s *Server, lib string) string { return "acme-isos/../../etc/shadow" },
		"a non-.iso file":            func(t *testing.T, s *Server, lib string) string { return "acme-isos/root.qcow2" },
		"a dot file":                 func(t *testing.T, s *Server, lib string) string { return "acme-isos/.hidden.iso" },
		"a nested path":              func(t *testing.T, s *Server, lib string) string { return "acme-isos/sub/x.iso" },
		"another project's library": func(t *testing.T, s *Server, lib string) string {
			d := projectLibrary(t, s, "other-isos", "other")
			writeLibFile(t, filepath.Join(d, "x.iso"), isoBody)
			return "other-isos/x.iso"
		},
		"a pool that is not on the host": func(t *testing.T, s *Server, lib string) string { return "nowhere/x.iso" },
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			s, fake, _ := isoServer(t)
			pat := acmeOperator(t, s)
			lib := projectLibrary(t, s, "acme-isos", "acme")
			ref := mk(t, s, lib)
			_, err := s.CreateVM(pat, isoCreate("v", ref, "acme"))
			if err == nil {
				t.Fatalf("%s: create accepted %q", name, ref)
			}
			if strings.Contains(fake.DefinedXML("v"), "cdrom") {
				t.Fatalf("%s: a CD-ROM was defined", name)
			}
		})
	}
}

// A non-admin still cannot name a host path outside a pool, and nobody — an
// Admin included — can name a protected file.
func TestISOLibrary_HostPathsStayAdminOnly(t *testing.T) {
	s, _, key := isoServer(t)
	pat := acmeOperator(t, s)
	p := filepath.Join(t.TempDir(), "shadow.iso")
	writeLibFile(t, p, isoBody)
	if _, err := s.CreateVM(pat, isoCreate("v1", p, "acme")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator host path: got %v, want PermissionDenied", err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("v2", key, "")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin naming the host key: got %v, want InvalidArgument", err)
	}
}

// Only an Admin writes the global library; an operator writes its project's.
func TestISOLibrary_GlobalLibraryIsAdminWritten(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	libraryMode(t, s, corrosion.ISOLibraryShared)
	g := globalLibrary(t, s)
	projectLibrary(t, s, "acme-isos", "acme")

	up := func(ctx context.Context, pool, file string) error {
		return s.UploadStoragePoolContent(&fakeUploadStream{ctx: ctx, msgs: []*pb.UploadStoragePoolContentRequest{
			{PoolName: pool, Filename: file}, {Chunk: []byte(isoBody)},
		}})
	}
	if err := up(pat, globalISOLibrary, "trojan.iso"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator upload to the global library: got %v, want PermissionDenied", err)
	}
	if _, err := os.Stat(filepath.Join(g, "trojan.iso")); !os.IsNotExist(err) {
		t.Fatal("a refused upload wrote into the global library")
	}
	if _, err := s.PullISO(pat, &pb.PullISORequest{Ref: "isos/x.iso", Url: "http://127.0.0.1:1/x.iso"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator pull into the global library: got %v, want PermissionDenied", err)
	}
	writeLibFile(t, filepath.Join(g, "keep.iso"), isoBody)
	if _, err := s.DeleteStoragePoolContent(pat, &pb.DeleteStoragePoolContentRequest{PoolName: globalISOLibrary, Filename: "keep.iso"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator delete from the global library: got %v, want PermissionDenied", err)
	}
	if err := up(pat, "acme-isos", "mine.iso"); err != nil {
		t.Fatalf("operator upload to its project library: %v", err)
	}
	if err := up(pat, "acme-isos", "payload.qcow2"); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("a non-.iso upload into a library: got %v, want InvalidArgument", err)
	}
	if err := up(adminCtx(), globalISOLibrary, "debian.iso"); err != nil {
		t.Fatalf("admin upload to the global library: %v", err)
	}
}

// Copying a host file in reads it, so a host-path pull is Admin-only and
// refuses protected files.
func TestISOLibrary_HostPathPullIsAdminOnly(t *testing.T) {
	s, _, key := isoServer(t)
	pat := acmeOperator(t, s)
	projectLibrary(t, s, "acme-isos", "acme")
	src := filepath.Join(t.TempDir(), "x.iso")
	writeLibFile(t, src, isoBody)
	if _, err := s.PullISO(pat, &pb.PullISORequest{Ref: "acme-isos/x.iso", HostPath: src}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator host-path pull: got %v, want PermissionDenied", err)
	}
	if _, err := s.PullISO(adminCtx(), &pb.PullISORequest{Ref: "acme-isos/k.iso", HostPath: key}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin pulling the host key into a library: got %v, want InvalidArgument", err)
	}
}

// A pool cannot be created over the global library's directory: its writers
// would be writing the library.
func TestISOLibrary_NoPoolOverTheGlobalLibrary(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	g := globalLibrary(t, s)
	for _, target := range []string{g, filepath.Dir(g)} {
		_, err := s.CreateStoragePool(pat, &pb.CreateStoragePoolRequest{Name: "sneaky", Driver: "dir", Target: target, Project: "acme"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("pool at %s over the global library: got %v, want InvalidArgument", target, err)
		}
	}
}

// ── every start ──

func libraryVMStopped(t *testing.T, s *Server, name string) (lib, iso string) {
	t.Helper()
	libraryMode(t, s, corrosion.ISOLibraryShared)
	lib = globalLibrary(t, s)
	iso = filepath.Join(lib, "install.iso")
	writeLibFile(t, iso, isoBody)
	if _, err := s.CreateVM(adminCtx(), isoCreate(name, "isos/install.iso", "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = ?`, name); err != nil {
		t.Fatal(err)
	}
	return lib, iso
}

func TestISOLibrary_StartRefusesALibraryFileSwappedForALink(t *testing.T) {
	s, _, key := isoServer(t)
	_, iso := libraryVMStopped(t, s, "swap")
	swapForSymlink(t, iso, key)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "swap")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start after the library file became a link: got %v, want FailedPrecondition", err)
	}
}

func TestISOLibrary_StartRefusesALibraryFileSwappedForAHardLink(t *testing.T) {
	s, _, _ := isoServer(t)
	lib, iso := libraryVMStopped(t, s, "hard")
	other := filepath.Join(lib, "other.bin")
	writeLibFile(t, other, "another file")
	if err := os.Remove(iso); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(other, iso); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "hard")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start after the library file became a hard link: got %v, want FailedPrecondition", err)
	}
}

func TestISOLibrary_StartWithTheLibraryFileIntact(t *testing.T) {
	s, _, _ := isoServer(t)
	libraryVMStopped(t, s, "ok")
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "ok")); err != nil {
		t.Fatalf("start: %v", err)
	}
}

// A domain defined on a host whose library lives elsewhere (a cold migration)
// is pointed at this host's file at start.
func TestISOLibrary_StartRepointsTheDomainAtThisHostsFile(t *testing.T) {
	s, fake, _ := isoServer(t)
	lib, _ := libraryVMStopped(t, s, "moved")
	here := filepath.Join(mustEval(t, lib), "install.iso")
	elsewhere := "/srv/other-host/isos/install.iso"
	if err := fake.DefineDomain(strings.ReplaceAll(fake.DefinedXML("moved"), here, elsewhere)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "moved")); err != nil {
		t.Fatalf("start: %v", err)
	}
	xml := fake.DefinedXML("moved")
	if strings.Contains(xml, elsewhere) || !strings.Contains(xml, here) {
		t.Fatalf("the domain was not pointed at %s:\n%s", here, xml)
	}
}

// Sync mode: a VM starts only where its ISO's copy matches the library record.
func TestISOLibrary_SyncModeStartsOnlyOnAMatchingCopy(t *testing.T) {
	s, _, _ := isoServer(t)
	lib, iso := libraryVMStopped(t, s, "synced")
	libraryMode(t, s, corrosion.ISOLibrarySync)
	start := func() error {
		_, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "synced"))
		return err
	}
	if err := start(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("sync mode, no library record: got %v, want FailedPrecondition", err)
	}
	if err := corrosion.PutISOCatalogEntry(context.Background(), s.db, corrosion.ISOCatalogEntry{
		Name: "install.iso", SHA256: sha(isoBody), Size: int64(len(isoBody)),
	}, "test"); err != nil {
		t.Fatal(err)
	}
	if err := start(); err != nil {
		t.Fatalf("sync mode, matching copy: %v", err)
	}
	// A different file under the same name (rename, so the inode changes).
	tmp := filepath.Join(lib, "new.tmp")
	writeLibFile(t, tmp, "tampered "+isoBody)
	if err := os.Rename(tmp, iso); err != nil {
		t.Fatal(err)
	}
	if err := start(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("sync mode, mismatched copy: got %v, want FailedPrecondition", err)
	}
}

// ── sync between hosts ──

// fetchStream is the server half of FetchISOLibraryFile in a test: it collects
// what the serving host sends.
type fetchStream struct {
	grpc.ServerStream
	ctx    context.Context
	chunks [][]byte
}

func (f *fetchStream) Context() context.Context { return f.ctx }
func (f *fetchStream) Send(c *pb.FetchISOLibraryFileChunk) error {
	f.chunks = append(f.chunks, append([]byte(nil), c.GetChunk()...))
	return nil
}
func (f *fetchStream) SetHeader(metadata.MD) error  { return nil }
func (f *fetchStream) SendHeader(metadata.MD) error { return nil }
func (f *fetchStream) SetTrailer(metadata.MD)       {}

// fetchClient is the client half: it serves the collected chunks.
type fetchClient struct {
	grpc.ClientStream
	chunks [][]byte
}

func (f *fetchClient) Recv() (*pb.FetchISOLibraryFileChunk, error) {
	if len(f.chunks) == 0 {
		return nil, io.EOF
	}
	c := f.chunks[0]
	f.chunks = f.chunks[1:]
	return &pb.FetchISOLibraryFileChunk{Chunk: c}, nil
}

// peerLibrary is a LiteVirtClient whose FetchISOLibraryFile is answered by
// another in-process server, as that host.
type peerLibrary struct {
	pb.LiteVirtClient
	t    *testing.T
	from *Server
	ctx  context.Context
}

func (p *peerLibrary) FetchISOLibraryFile(_ context.Context, in *pb.FetchISOLibraryFileRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.FetchISOLibraryFileChunk], error) {
	st := &fetchStream{ctx: p.ctx}
	if err := p.from.FetchISOLibraryFile(in, st); err != nil {
		return nil, err
	}
	return &fetchClient{chunks: st.chunks}, nil
}

// Two hosts on one replicated state: an upload on one reaches the other,
// verified; a tampered source is not copied; a removal removes everywhere.
func TestISOLibrary_SyncCopiesVerifiesAndRemoves(t *testing.T) {
	a, _, _ := isoServer(t)
	libraryMode(t, a, corrosion.ISOLibrarySync)
	b := &Server{hostName: "host-b", dataDir: t.TempDir(), pkiDir: a.pkiDir, db: a.db}
	// host-b is a live cluster host, and what it presents to A is its peer cert.
	asPeer := peerCtxFor(t, a, "host-b")
	libA := globalLibrary(t, a)
	libB := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), a.db, corrosion.StoragePoolRecord{
		HostName: "host-b", Name: globalISOLibrary, Driver: "dir", Target: libB, Options: GlobalISOLibraryOptions(), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	b.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host != a.hostName {
			return nil, nil, status.Errorf(codes.Unavailable, "no route to %s", host)
		}
		return &peerLibrary{t: t, from: a, ctx: asPeer}, func() {}, nil
	}

	if err := a.UploadStoragePoolContent(&fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: globalISOLibrary, Filename: "debian.iso"}, {Chunk: []byte(isoBody)},
	}}); err != nil {
		t.Fatalf("admin upload on host A: %v", err)
	}
	if err := b.SyncISOLibrary(context.Background()); err != nil {
		t.Fatalf("sync on host B: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(libB, "debian.iso")); string(got) != isoBody {
		t.Fatalf("host B's copy = %q", got)
	}

	// A's copy is replaced behind the library's back: B must not take it.
	tmp := filepath.Join(libA, "x.tmp")
	writeLibFile(t, tmp, isoBody+" with a payload")
	if err := os.Rename(tmp, filepath.Join(libA, "debian.iso")); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(libB, "debian.iso")); err != nil {
		t.Fatal(err)
	}
	if err := b.SyncISOLibrary(context.Background()); err == nil {
		t.Fatal("sync took a copy that does not match the library record")
	}
	if _, err := os.Stat(filepath.Join(libB, "debian.iso")); !os.IsNotExist(err) {
		t.Fatal("a mismatched copy landed on host B")
	}

	// Removal is recorded and followed.
	writeLibFile(t, filepath.Join(libB, "debian.iso"), isoBody)
	if _, err := a.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: globalISOLibrary, Filename: "debian.iso"}); err != nil {
		t.Fatalf("admin delete: %v", err)
	}
	if err := b.SyncISOLibrary(context.Background()); err != nil {
		t.Fatalf("sync after delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(libB, "debian.iso")); !os.IsNotExist(err) {
		t.Fatal("a removed library file stayed on host B")
	}
}

// Only an Admin changes the mode; switching to sync records the files this
// host's library already holds.
func TestISOLibrary_ModeIsAdminSetAndAdoptsExistingFiles(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetISOLibraryMode(context.Background(), s.db, corrosion.ISOLibraryShared, "test"); err != nil {
		t.Fatal(err)
	}
	g := globalLibrary(t, s)
	writeLibFile(t, filepath.Join(g, "already.iso"), isoBody)
	if _, err := s.SetISOLibraryMode(pat, &pb.SetISOLibraryModeRequest{Mode: "sync"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator setting the mode: got %v, want PermissionDenied", err)
	}
	if _, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "bogus"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown mode: got %v", err)
	}
	st, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "sync"})
	if err != nil || st.GetMode() != "sync" {
		t.Fatalf("admin setting sync: %v %v", st, err)
	}
	if e, ok, _ := corrosion.GetISOCatalogEntry(context.Background(), s.db, "already.iso"); !ok || e.SHA256 != sha(isoBody) {
		t.Fatalf("an existing library file was not recorded on switching to sync: %+v %v", e, ok)
	}
}
