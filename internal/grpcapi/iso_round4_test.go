package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 3 of the library round (restore-iso-rereview-3.md), fix round 4.
// The binding rule: a security fix secures a feature, it never removes it or
// newly refuses a workflow that worked on main 3e4ba50b.

// opticalImage is a file that carries an ISO 9660 volume descriptor where a
// CD-ROM image has it (sector 16, "CD001" at offset 0x8001), then body.
func opticalImage(body string) string {
	b := make([]byte, 0x8800)
	copy(b[0x8000:], "\x01CD001\x01")
	return string(b) + body
}

// hostTarget is a migration target (stubTarget) with a PKI directory holding
// a host key, so a test can aim a link at it.
func hostTarget(t *testing.T) (*Server, string) {
	t.Helper()
	s, _ := stubTarget(t)
	s.pkiDir = filepath.Join(t.TempDir(), "pki")
	if err := os.MkdirAll(s.pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(s.pkiDir, "host.key")
	if err := os.WriteFile(key, []byte("-----BEGIN PRIVATE KEY-----\nsecret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s, key
}

func setMigSpec(t *testing.T, s *Server, spec *pb.VMSpec) {
	t.Helper()
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, project = ? WHERE name = 'mig'`, string(b), spec.GetProject()); err != nil {
		t.Fatal(err)
	}
}

// N-C1: a running VM whose host-path ISO is a link (virtio-win.iso → a
// versioned file) moves live to a host where the link names another version.
// The domain carries the source's resolved file, which this host does not
// have; this host resolves the VM's ISO itself and the move goes ahead.
func TestISORound4_ALiveMoveOfALinkedHostPathISO(t *testing.T) {
	s, _ := hostTarget(t)
	dir := t.TempDir()
	here := filepath.Join(dir, "virtio-win-0.1.248.iso")
	writeLibFile(t, here, isoBody)
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(here, link); err != nil {
		t.Fatal(err)
	}
	setMigSpec(t, s, &pb.VMSpec{Name: "mig", Iso: link, IsoScope: isoScopeHostPath})
	srcPath := filepath.Join(dir, "virtio-win-0.1.240.iso") // the source's version: not on this host
	r, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
		InstallerIsoListed: true, InstallerIsoPaths: []string{srcPath}, InstallerIsoRuntime: true})
	if err != nil {
		t.Fatalf("live move of a VM whose ISO link names another version here: %v", err)
	}
	if got := r.GetInstallerIsoResolved()[srcPath]; got != mustEval(t, here) {
		t.Fatalf("the target resolved %s to %q, want this host's %s", srcPath, got, mustEval(t, here))
	}
}

// N-C1, red: where the link on this host names a refused file, the live move
// is refused.
func TestISORound4_ALiveMoveToALinkAtTheHostKeyIsRefused(t *testing.T) {
	s, key := hostTarget(t)
	dir := t.TempDir()
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	setMigSpec(t, s, &pb.VMSpec{Name: "mig", Iso: link, IsoScope: isoScopeHostPath})
	_, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
		InstallerIsoListed: true, InstallerIsoPaths: []string{filepath.Join(dir, "virtio-win-0.1.240.iso")}, InstallerIsoRuntime: true})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("live move where the ISO link names the host key: got %v, want FailedPrecondition", err)
	}
}

// N-C1: a running VM's library ISO moves live to a host where the library is
// in another directory; this host's file is what the domain lands on.
func TestISORound4_ALiveMoveOfALibraryISOInAnotherDirectory(t *testing.T) {
	s, _ := stubTarget(t)
	_, here := libraryVM(t, s, "mig", "acme")
	r, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
		InstallerIsoListed: true, InstallerIsoPaths: []string{"/srv/source-host/isos/install.iso"}, InstallerIsoRuntime: true})
	if err != nil {
		t.Fatalf("live move of a library ISO whose directory differs here: %v", err)
	}
	if got := r.GetInstallerIsoResolved()["/srv/source-host/isos/install.iso"]; got != here {
		t.Fatalf("the target resolved the source's path to %q, want %s", got, here)
	}
}

// homeTestDir makes a directory under the real /home of the user running the
// tests, or skips: ISOs under /home worked on main, and the test proves it on
// the real deny-list, not on a stand-in.
func homeTestDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil || !strings.HasPrefix(home, "/home/") {
		t.Skip("the test user's home is not under /home")
	}
	d, err := os.MkdirTemp(home, "lv-iso-test-")
	if err != nil {
		t.Skipf("cannot write in %s: %v", home, err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	r, err := filepath.EvalSymlinks(d)
	if err != nil || !strings.HasPrefix(r, "/home/") {
		t.Skip("the test user's home does not resolve under /home")
	}
	return r
}

// N-C2: an Admin names an ISO in a home directory, and a VM made on main with
// one keeps starting.
func TestISORound4_AnISOUnderHomeWorks(t *testing.T) {
	s, fake, _ := isoServer(t)
	d := homeTestDir(t)
	if err := os.MkdirAll(filepath.Join(d, "isos"), 0o755); err != nil {
		t.Fatal(err)
	}
	iso := filepath.Join(d, "isos", "virtio-win.iso")
	writeLibFile(t, iso, opticalImage("virtio"))
	if _, err := s.CreateVM(adminCtx(), isoCreate("adm", iso, "")); err != nil {
		t.Fatalf("admin create with an ISO under /home: %v", err)
	}
	legacyVM(t, s, fake, "old", iso)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "old")); err != nil {
		t.Fatalf("start of a main-era VM whose ISO is under /home: %v", err)
	}
}

// N-C2, red: under /home only an optical image is a file a guest may be given,
// and not through a link into a dot-directory the path does not name; an ISO
// in a dot-directory the Admin names (libvirt's session pool) works.
func TestISORound4_HomeIsStillNotReadable(t *testing.T) {
	s, _, _ := isoServer(t)
	d := homeTestDir(t)
	for _, sub := range []string{".ssh", ".cache", "isos", ".local/share/libvirt/images"} {
		if err := os.MkdirAll(filepath.Join(d, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(d, ".ssh", "id_rsa")
	writeLibFile(t, key, "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n")
	keyISO := filepath.Join(d, "isos", "id_rsa.iso")
	writeLibFile(t, keyISO, "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n")
	dotISO := filepath.Join(d, ".cache", "x.iso")
	writeLibFile(t, dotISO, opticalImage("cached"))
	link := filepath.Join(d, "isos", "key.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	dotLink := filepath.Join(d, "isos", "cached.iso")
	if err := os.Symlink(dotISO, dotLink); err != nil {
		t.Fatal(err)
	}
	for i, p := range []string{key, keyISO, link, dotLink} {
		name := "bad" + string(rune('a'+i))
		if _, err := s.CreateVM(adminCtx(), isoCreate(name, p, "")); status.Code(err) != codes.InvalidArgument {
			t.Errorf("admin create with %s: got %v, want InvalidArgument", p, err)
		}
	}
	session := filepath.Join(d, ".local", "share", "libvirt", "images", "x.iso")
	writeLibFile(t, session, opticalImage("session"))
	for i, p := range []string{session, dotISO} {
		if _, err := s.CreateVM(adminCtx(), isoCreate("ok"+string(rune('a'+i)), p, "")); err != nil {
			t.Errorf("admin create with %s (a dot-directory the Admin names): %v", p, err)
		}
	}
}

// I-a: a directory that does not answer is probed once at a time, and its
// failure is answered from the cache until that probe returns.
func TestISORound4_OneProbeInFlightPerDirectory(t *testing.T) {
	block := make(chan struct{})
	var calls atomic.Int32
	orig, origT := isoDirProbe, isoDirProbeTimeout
	t.Cleanup(func() { close(block); isoDirProbe, isoDirProbeTimeout = orig, origT })
	isoDirProbeTimeout = 100 * time.Millisecond
	dead := filepath.Join(t.TempDir(), "dead")
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if p == dead {
			calls.Add(1)
			<-block
		}
		return orig(p)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := probeDir(dead); err == nil {
				t.Error("a probe of an unanswering directory answered")
			}
		}()
	}
	wg.Wait()
	start := time.Now()
	for i := 0; i < 100; i++ {
		if _, err := probeDir(dead); err == nil {
			t.Fatal("a probe of an unanswering directory answered")
		}
	}
	if d := time.Since(start); d > isoDirProbeTimeout {
		t.Errorf("100 later probes took %s: the failure was not answered from the cache", d)
	}
	if n := calls.Load(); n != 1 {
		t.Fatalf("%d probes of the one unanswering directory are blocked; want 1", n)
	}
}

// I-b: lv iso ls and the UI picker do not hang on a library whose directory
// does not answer — neither resolving it nor listing it — and say so.
func TestISORound4_TheListingDoesNotHang(t *testing.T) {
	s, _, _ := isoServer(t)
	listed := projectLibrary(t, s, "slow-lib", "acme")
	block := make(chan struct{})
	origP, origL, origT := isoDirProbe, isoBeforeList, isoDirProbeTimeout
	t.Cleanup(func() { close(block); isoDirProbe, isoBeforeList, isoDirProbeTimeout = origP, origL, origT })
	isoDirProbeTimeout = 200 * time.Millisecond
	list := func() map[string]bool {
		t.Helper()
		done := make(chan *pb.ListISOsResponse, 1)
		go func() {
			r, err := s.ListISOs(adminCtx(), &pb.ListISOsRequest{})
			if err != nil {
				t.Errorf("ListISOs: %v", err)
			}
			done <- r
		}()
		select {
		case r := <-done:
			unavailable := map[string]bool{}
			for _, e := range r.GetIsos() {
				if e.GetSyncState() == "unavailable" {
					unavailable[e.GetPool()] = true
				}
			}
			return unavailable
		case <-time.After(10 * time.Second):
			t.Fatal("ListISOs hung on a library whose directory does not answer")
		}
		return nil
	}
	// Its directory resolves, but reading it does not answer.
	isoBeforeList = func(dir string) {
		if dir == mustEval(t, listed) {
			<-block
		}
	}
	if got := list(); !got["slow-lib"] {
		t.Fatalf("unavailable libraries = %v; want slow-lib, whose listing does not answer", got)
	}
	// Its directory does not even resolve.
	lib := projectLibrary(t, s, "dead-lib", "acme")
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if p == lib {
			<-block
		}
		return origP(p)
	}
	if got := list(); !got["dead-lib"] {
		t.Fatalf("unavailable libraries = %v; want dead-lib, whose directory does not answer", got)
	}
}

// m-4: a probe that fails with an error other than "no such directory" says
// nothing about which directory it is, so the question fails closed.
func TestISORound4_AnErroredProbeFailsClosed(t *testing.T) {
	s, _, _ := isoServer(t)
	libraryVMStopped(t, s, "v")
	broken := t.TempDir()
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-broken", Driver: "dir", Target: broken, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	orig := isoDirProbe
	t.Cleanup(func() { isoDirProbe = orig })
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if p == broken {
			return "", nil, &os.PathError{Op: "stat", Path: p, Err: syscall.ESTALE}
		}
		return orig(p)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "v")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with another project's pool directory erroring: got %v, want FailedPrecondition", err)
	}
}

// m-1: no pool may map the host-local identity store.
func TestISORound4_NoPoolOverTheIdentityStore(t *testing.T) {
	s, _, _ := isoServer(t)
	store := filepath.Join(s.dataDir, "iso-identity")
	if err := os.MkdirAll(filepath.Join(store, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{store, filepath.Join(store, "sub")} {
		_, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "forge", Driver: "dir", Target: target})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("pool at %s: got %v, want InvalidArgument", target, err)
		}
	}
}

func identityFiles(t *testing.T, s *Server) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(s.dataDir, "iso-identity"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// m-2: a record is written through a temp file of its own (not one fixed
// name another writer, or a leftover, can hold).
func TestISORound4_ARecordIsWrittenThroughItsOwnTempFile(t *testing.T) {
	s, _, _ := isoServer(t)
	_, _ = libraryVMStopped(t, s, "v")
	key := isoIdentityKey("v", vmSpecFor(vmRecord(t, s, "v")))
	s.forgetISOIdentity(key)
	if err := os.MkdirAll(s.isoIdentityPath(key)+".tmp", 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "v")); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.readISOIdentity(key); !ok {
		t.Fatal("the start recorded no identity")
	}
}

// Identity records go with their VM: on delete, and on a create that failed.
// A create records nothing under the VM's name (m-3).
func TestISORound4_RecordsGoWithTheirVM(t *testing.T) {
	s, fake, _ := isoServer(t)
	_, _ = libraryVMStopped(t, s, "v")
	if got := identityFiles(t, s); len(got) != 1 || !strings.HasPrefix(got[0], "uuid-") {
		t.Fatalf("records after a create = %v, want the one uuid record", got)
	}
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "v"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if got := identityFiles(t, s); len(got) != 0 {
		t.Fatalf("records after the VM was deleted = %v, want none", got)
	}
	fake.FailStartDomain = func(string) error { return errors.New("no boot") }
	if _, err := s.CreateVM(adminCtx(), isoCreate("w", "isos/install.iso", "")); err == nil {
		t.Fatal("the create was meant to fail")
	}
	if got := identityFiles(t, s); len(got) != 0 {
		t.Fatalf("records after a failed create = %v, want none", got)
	}
}

// m-5: a path with characters XML escapes is pointed at, both from and to.
func TestISORound4_AnEscapedPathIsRepointed(t *testing.T) {
	s, fake, _ := isoServer(t)
	dir := filepath.Join(t.TempDir(), "r&d's")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(dir, "virtio-win-0.1.240.iso")
	writeLibFile(t, real, isoBody)
	linkDir := filepath.Join(t.TempDir(), "a&b")
	if err := os.MkdirAll(linkDir, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(linkDir, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	legacyVM(t, s, fake, "esc", filepath.Join(t.TempDir(), "placeholder.iso"))
	// The domain carries the link, escaped as libvirt writes it.
	x := fake.DefinedXML("esc")
	from := s.domainInstallerISOs("esc", x)
	if len(from) != 1 {
		t.Fatalf("test setup: CD-ROMs %v", from)
	}
	x = strings.ReplaceAll(x, from[0], strings.ReplaceAll(link, "&", "&amp;"))
	if err := fake.DefineDomain(x); err != nil {
		t.Fatal(err)
	}
	spec := vmSpecFor(vmRecord(t, s, "esc"))
	spec.Iso = link
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'esc'`, string(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "esc")); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := s.domainInstallerISOs("esc", fake.DefinedXML("esc")); len(got) != 1 || got[0] != mustEval(t, real) {
		t.Fatalf("the domain's CD-ROM is %v, want %s", got, mustEval(t, real))
	}
}

// m-11: only the spec's CD-ROM follows the spec's ISO; another CD-ROM is
// judged as itself and keeps its file.
func TestISORound4_AnotherCDROMKeepsItsFile(t *testing.T) {
	s, fake, _ := isoServer(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "virtio-win-0.1.240.iso")
	writeLibFile(t, real, isoBody)
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	drivers := filepath.Join(dir, "drivers.iso")
	writeLibFile(t, drivers, isoBody+" drivers")
	legacyVM(t, s, fake, "two", link)
	x := fake.DefinedXML("two")
	second := `<disk type="file" device="cdrom"><driver name="qemu" type="raw"/><source file="` + drivers +
		`"/><target dev="sdz" bus="sata"/><readonly/></disk></devices>`
	if err := fake.DefineDomain(strings.Replace(x, "</devices>", second, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "two")); err != nil {
		t.Fatalf("start: %v", err)
	}
	got := s.domainInstallerISOs("two", fake.DefinedXML("two"))
	want := []string{mustEval(t, real), mustEval(t, drivers)}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("CD-ROMs after the start = %v, want %v", got, want)
	}
}

// m-7: a library file this host holds with no record is recorded on the next
// pass, not only once per generation.
func TestISORound4_ALocalFileIsAdoptedOnAnyPass(t *testing.T) {
	ctx := context.Background()
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	lib := globalLibrary(t, s)
	if _, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "sync"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncISOLibrary(ctx); err != nil {
		t.Fatal(err)
	}
	writeLibFile(t, filepath.Join(lib, "late.iso"), isoBody)
	if err := s.SyncISOLibrary(ctx); err != nil {
		t.Fatal(err)
	}
	if e, ok, _ := corrosion.GetISOCatalogEntry(ctx, s.db, "late.iso"); !ok || e.SHA256 != sha(isoBody) {
		t.Fatalf("a local library file was not recorded on a later pass: %+v %v", e, ok)
	}
}

// m-6: pinning the implicit mode keeps the records it was holding.
func TestISORound4_ThePinKeepsTheRecords(t *testing.T) {
	ctx := context.Background()
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	globalLibrary(t, s)
	if err := s.UploadStoragePoolContent(&fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
		{PoolName: "isos", Filename: "kept.iso"}, {Chunk: []byte(isoBody)},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := corrosion.GetISOCatalogEntry(ctx, s.db, "kept.iso"); !ok {
		t.Fatal("test setup: the upload was not recorded")
	}
	s.pinImplicitISOLibraryMode(adminCtx())
	if m, _ := corrosion.GetISOLibraryMode(ctx, s.db); m.Implicit {
		t.Fatal("test setup: the mode was not pinned")
	}
	if _, ok, _ := corrosion.GetISOCatalogEntry(ctx, s.db, "kept.iso"); !ok {
		t.Fatal("the pin dropped the library's records; every sync-library start is refused until the next pass")
	}
}
