package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
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
)

// Re-review 2 of the library round (restore-iso-rereview-2.md). The binding
// rule: nothing that worked on main 3e4ba50b is newly refused.

// legacyVM stores what a VM created on main looks like: no iso_scope, the ISO
// path as the user named it, and a domain carrying that path.
func legacyVM(t *testing.T, s *Server, fake *libvirtfake.Fake, name, iso string) {
	t.Helper()
	ok := filepath.Join(t.TempDir(), "plain.iso")
	writeLibFile(t, ok, isoBody)
	if _, err := s.CreateVM(adminCtx(), isoCreate(name, ok, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, name)
	spec := vmSpecFor(vmRecord(t, s, name))
	spec.Iso, spec.IsoScope = iso, ""
	b, _ := json.Marshal(spec)
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = ?`, string(b), name); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(strings.ReplaceAll(fake.DefinedXML(name), ok, iso)); err != nil {
		t.Fatal(err)
	}
}

// C-2: virtio-win ships virtio-win.iso as a link to a versioned file. A VM
// made on main with that path keeps starting: the link is resolved once, the
// file it names judged, and the domain pointed at it.
func TestISORound3_AMainEraSymlinkedISOKeepsStarting(t *testing.T) {
	s, fake, _ := isoServer(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "virtio-win-0.1.240.iso")
	writeLibFile(t, real, isoBody)
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	legacyVM(t, s, fake, "win", link)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "win")); err != nil {
		t.Fatalf("start of a main-era VM whose ISO is a symlink: %v", err)
	}
	if x := fake.DefinedXML("win"); !strings.Contains(x, mustEval(t, real)) {
		t.Fatalf("the domain was not pointed at the resolved file:\n%s", x)
	}
}

// C-2: the same under a symlinked directory (/var/lib/libvirt/images → /data).
func TestISORound3_AnISOUnderASymlinkedDirectoryKeepsStarting(t *testing.T) {
	s, fake, _ := isoServer(t)
	data := t.TempDir()
	writeLibFile(t, filepath.Join(data, "debian.iso"), isoBody)
	images := filepath.Join(t.TempDir(), "images")
	if err := os.Symlink(data, images); err != nil {
		t.Fatal(err)
	}
	legacyVM(t, s, fake, "deb", filepath.Join(images, "debian.iso"))
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "deb")); err != nil {
		t.Fatalf("start of a VM whose ISO is under a symlinked directory: %v", err)
	}
}

// C-2: an Admin naming a symlinked host path at create works, and the domain
// carries the resolved file.
func TestISORound3_AdminCreateWithASymlinkedPath(t *testing.T) {
	s, fake, key := isoServer(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "virtio-win-0.1.240.iso")
	writeLibFile(t, real, isoBody)
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("adm", link, "")); err != nil {
		t.Fatalf("admin create with a symlinked host path: %v", err)
	}
	if x := fake.DefinedXML("adm"); !strings.Contains(x, mustEval(t, real)) {
		t.Fatalf("the domain does not carry the resolved file:\n%s", x)
	}
	if got := vmSpecFor(vmRecord(t, s, "adm")).GetIso(); got != link {
		t.Fatalf("the spec keeps %q, want the path the Admin named", got)
	}
	// A link to a refused file is still refused, to an Admin too.
	bad := filepath.Join(dir, "evil.iso")
	if err := os.Symlink(key, bad); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("bad", bad, "")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin create with a link to the host key: got %v, want InvalidArgument", err)
	}
}

// C-2: a main-era VM whose ISO link now names the host key does not start.
func TestISORound3_AMainEraLinkToTheHostKeyIsRefused(t *testing.T) {
	s, fake, key := isoServer(t)
	link := filepath.Join(t.TempDir(), "x.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	legacyVM(t, s, fake, "leak", link)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "leak")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start of a VM whose ISO links to the host key: got %v, want FailedPrecondition", err)
	}
}

// C-2: hard links are allowed where the kernel stops a user linking a file
// they do not own (fs.protected_hardlinks=1, the default).
func TestISORound3_AHardLinkedHostPathWithProtectedHardlinks(t *testing.T) {
	b, err := os.ReadFile("/proc/sys/fs/protected_hardlinks")
	if err != nil || strings.TrimSpace(string(b)) != "1" {
		t.Skip("fs.protected_hardlinks is not 1 here")
	}
	s, _, _ := isoServer(t)
	dir := t.TempDir()
	orig := filepath.Join(dir, "a.iso")
	writeLibFile(t, orig, isoBody)
	twin := filepath.Join(dir, "b.iso")
	if err := os.Link(orig, twin); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("twin", twin, "")); err != nil {
		t.Fatalf("admin create with a hard-linked host path under protected_hardlinks: %v", err)
	}
}

// C-1: a VM keeps starting on a host it arrived at, after another project's
// pool comes to share its library's directory there.
func TestISORound3_AnArrivedVMKeepsStarting(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	lib := projectLibrary(t, s, "b-lib", "acme")
	writeLibFile(t, filepath.Join(lib, "debian.iso"), isoBody)
	if _, err := s.CreateVM(pat, isoCreate("b-vm", "b-lib/debian.iso", "acme")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, "b-vm")
	arrive(t, s, "b-vm")
	// The first start here passes the full rule.
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "b-vm")); err != nil {
		t.Fatalf("first start on the host it arrived at: %v", err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "b-vm")); err != nil {
		t.Fatalf("start after another project's pool joined the directory: %v", err)
	}
}

// m-b: a stopped move to a host where the named pool is another project's is
// refused even when the file is absent there.
func TestISORound3_AStoppedMoveToAnotherProjectsPoolIsRefusedFileOrNot(t *testing.T) {
	s, _ := stubTarget(t)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mig", Iso: "b-lib/x.iso", IsoScope: isoScopeProject, Project: "acme"})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, project = 'acme' WHERE name = 'mig'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	projectLibrary(t, s, "b-lib", "other")
	_, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
		InstallerIsoListed: true, InstallerIsoPaths: []string{"/srv/source/b-lib/x.iso"}, InstallerIsoRuntime: false})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stopped move to a host whose b-lib is another project's (file absent): got %v, want FailedPrecondition", err)
	}
}

// m-g: an older source sends EnsureDisks only for a runtime move (main's only
// caller is the storage-copy runtime path), so listed=false with the ISO absent
// is refused — qemu here would open the source's path.
func TestISORound3_AnOlderSourcesMoveIsRuntime(t *testing.T) {
	s, _ := stubTarget(t)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mig", Iso: "a-lib/foo.iso", IsoScope: isoScopeProject, Project: "acme"})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, project = 'acme' WHERE name = 'mig'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an older source's move with the ISO absent here: got %v, want FailedPrecondition", err)
	}
}

// m2: a runtime move reads the RUNNING domain's CD-ROMs, and a read failure
// aborts rather than reading as "no CD-ROM".
func TestISORound3_ARuntimeMoveReadsTheLiveDomain(t *testing.T) {
	s, fake, _ := isoServer(t)
	_, iso := libraryVMStopped(t, s, "live")
	// The persistent definition has lost the CD-ROM; the running domain has it.
	live := fake.DefinedXML("live")
	if !strings.Contains(live, iso) && !strings.Contains(live, "install.iso") {
		t.Fatalf("test setup: no CD-ROM in\n%s", live)
	}
	fake.SetActiveXML("live", live)
	if err := fake.DefineDomain(strings.Replace(live, `device="cdrom"`, `device="disk"`, 1)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.ensureDisksOnTarget(context.Background(), "nowhere", "live", nil, false, true); err == nil {
		t.Fatal("a runtime move whose running domain carries an installer CD-ROM skipped the target's judgement")
	}
	fake.FailDumpXML = func(string) error { return errors.New("dump failed") }
	_, _, err := s.ensureDisksOnTarget(context.Background(), "nowhere", "live", nil, false, true)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "running domain") {
		t.Fatalf("a runtime move whose live domain cannot be read: got %v, want FailedPrecondition naming the running domain", err)
	}
}

// m5: the first time an Admin creates a global isos pool with no mode set, the
// mode in force is written, so the new pool does not silently flip it.
func TestISORound3_TheModeIsPinnedWhenAnIsosPoolIsCreated(t *testing.T) {
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "isos", Driver: "dir", Target: t.TempDir()}); err != nil {
		t.Fatalf("admin creating an isos pool: %v", err)
	}
	m, err := corrosion.GetISOLibraryMode(context.Background(), s.db)
	if err != nil || m.Implicit || m.Value != corrosion.ISOLibrarySync {
		t.Fatalf("mode after the first isos pool: %+v %v, want an explicit sync row", m, err)
	}
}

// m7: a non-admin naming a sync-mode global-library file by absolute path is
// held to the library record like a reference is.
func TestISORound3_AnAbsoluteLibraryPathIsHeldToTheRecord(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	libraryMode(t, s, corrosion.ISOLibrarySync)
	lib := globalLibrary(t, s)
	iso := filepath.Join(lib, "unrecorded.iso")
	writeLibFile(t, iso, isoBody)
	if _, err := s.CreateVM(pat, isoCreate("u", iso, "acme")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("operator naming an unrecorded sync-mode library file by path: got %v, want FailedPrecondition", err)
	}
}

// arrive makes this host one the VM came to: it forgets the file it judged
// for the VM at create.
func arrive(t *testing.T, s *Server, name string) {
	t.Helper()
	spec := vmSpecFor(vmRecord(t, s, name))
	s.forgetISOIdentity(isoIdentityKey(name, spec))
	s.forgetISOIdentity("name-" + name)
	if _, ok := s.readISOIdentity(isoIdentityKey(name, spec)); ok {
		t.Fatal("test setup: the identity record is still there")
	}
}

// ── tests of the round-3 API (they do not compile on 7e37acad) ──

// C-1: the device number is not part of a file's identity — a ZFS, btrfs,
// NFS or LVM mount can renumber it across a reboot.
func TestISORound3_ARenumberedDeviceIsTheSameFile(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	lib := projectLibrary(t, s, "b-lib", "acme")
	writeLibFile(t, filepath.Join(lib, "debian.iso"), isoBody)
	if _, err := s.CreateVM(pat, isoCreate("b-vm", "b-lib/debian.iso", "acme")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, "b-vm")
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	key := isoIdentityKey("b-vm", vmSpecFor(vmRecord(t, s, "b-vm")))
	rec, ok := s.readISOIdentity(key)
	if !ok {
		t.Fatal("create recorded no identity on this host")
	}
	rec.Dev += 1000 // the mount came back with another device number
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(s.isoIdentityPath(key), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "b-vm")); err != nil {
		t.Fatalf("start after the device was renumbered: %v", err)
	}
}

// I-1: another pool's directory that does not answer (an NFS server gone, on a
// hard mount) never hangs a start: the question fails closed within the
// deadline. The daemon's own NFS mount directories are never stat'ed.
func TestISORound3_AnUnansweringPoolDirectoryFailsClosedQuickly(t *testing.T) {
	s, _, _ := isoServer(t)
	_, _ = libraryVMStopped(t, s, "v")
	hung := filepath.Join(t.TempDir(), "nfs-target")
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "dead-nfs", Driver: "nfs", Source: "nas:/gone", Target: hung, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	t.Cleanup(func() { close(block) })
	orig, origT := isoDirProbe, isoDirProbeTimeout
	t.Cleanup(func() { isoDirProbe, isoDirProbeTimeout = orig, origT })
	isoDirProbeTimeout = 200 * time.Millisecond
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if strings.Contains(p, "mounts") {
			t.Errorf("the daemon's own NFS mount directory %s was stat'ed", p)
		}
		if p == hung {
			<-block
		}
		return orig(p)
	}
	start := time.Now()
	_, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "v"))
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("the start waited %s on an unanswering directory", d)
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("start with another pool's directory not answering: got %v, want a refusal saying which did not answer", err)
	}
}

// I-2: a directory reached by another path (a bind mount) is the same
// directory: compared by identity, not by path.
func TestISORound3_ABindMountedDirectoryIsTheSameDirectory(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	theirs := projectLibrary(t, s, "b-lib", "other")
	writeLibFile(t, filepath.Join(theirs, "x.iso"), isoBody)
	alias := t.TempDir() // stands for a bind mount of theirs
	writeLibFile(t, filepath.Join(alias, "x.iso"), isoBody)
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "a-lib", Driver: "dir", Target: alias, Project: "acme",
		Options: map[string]string{"content": "iso"}, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	orig := isoDirProbe
	t.Cleanup(func() { isoDirProbe = orig })
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		r, fi, err := orig(p)
		if err == nil && r == mustEval(t, alias) {
			fi, err = os.Stat(theirs) // the kernel's answer for a bind mount
		}
		return r, fi, err
	}
	if _, err := s.CreateVM(pat, isoCreate("a-vm", "a-lib/x.iso", "acme")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("booting through a bind mount of another project's directory: got %v, want PermissionDenied", err)
	}
}

// C-2: with fs.protected_hardlinks=0 a hard-linked host path stays refused,
// and the refusal says why.
func TestISORound3_AHardLinkWithoutProtectedHardlinksIsRefused(t *testing.T) {
	s, _, _ := isoServer(t)
	orig := protectedHardlinks
	t.Cleanup(func() { protectedHardlinks = orig })
	protectedHardlinks = func() bool { return false }
	dir := t.TempDir()
	writeLibFile(t, filepath.Join(dir, "a.iso"), isoBody)
	if err := os.Link(filepath.Join(dir, "a.iso"), filepath.Join(dir, "b.iso")); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateVM(adminCtx(), isoCreate("twin", filepath.Join(dir, "b.iso"), ""))
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "protected_hardlinks") {
		t.Fatalf("hard-linked host path with protected_hardlinks=0: got %v, want InvalidArgument naming it", err)
	}
}

// C-2: a host path's resolved file swapped for a link after the check is
// refused at the open.
func TestISORound3_AHostPathSwappedAfterTheCheckIsRefused(t *testing.T) {
	s, fake, key := isoServer(t)
	dir := t.TempDir()
	real := filepath.Join(dir, "virtio-win-0.1.240.iso")
	writeLibFile(t, real, isoBody)
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	legacyVM(t, s, fake, "win", link)
	t.Cleanup(func() { isoBeforeOpen = nil })
	isoBeforeOpen = func(p string) {
		if p == mustEval(t, real) {
			_ = os.Remove(p)
			_ = os.Symlink(key, p)
		}
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "win")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the resolved file swapped for a link after the check: got %v, want FailedPrecondition", err)
	}
}

// m4: a file added again while its tombstone is being collected keeps its new
// record.
func TestISORound3_AReAddDuringCollectionIsKept(t *testing.T) {
	ctx := context.Background()
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	globalLibrary(t, s)
	if _, err := s.SetISOLibraryMode(adminCtx(), &pb.SetISOLibraryModeRequest{Mode: "sync"}); err != nil {
		t.Fatal(err)
	}
	up := func() {
		if err := s.UploadStoragePoolContent(&fakeUploadStream{ctx: adminCtx(), msgs: []*pb.UploadStoragePoolContentRequest{
			{PoolName: "isos", Filename: "gone.iso"}, {Chunk: []byte(isoBody)},
		}}); err != nil {
			t.Fatal(err)
		}
	}
	up()
	if _, err := s.DeleteStoragePoolContent(adminCtx(), &pb.DeleteStoragePoolContentRequest{PoolName: "isos", Filename: "gone.iso"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { isoBeforeCollect = nil })
	isoBeforeCollect = func(name string) {
		if name == "gone.iso" {
			isoBeforeCollect = nil
			up()
		}
	}
	if err := s.SyncISOLibrary(ctx); err != nil {
		t.Fatal(err)
	}
	if e, ok, _ := corrosion.GetISOCatalogEntry(ctx, s.db, "gone.iso"); !ok || e.Deleted || e.SHA256 != sha(isoBody) {
		t.Fatalf("the re-added file lost its record to the collection: %+v %v", e, ok)
	}
}

// I-1: the daemon's own NFS mount directory (an nfs pool with no target) is
// never read to tell whether it shares an ISO's directory.
func TestISORound3_TheDaemonsNFSMountsAreNeverRead(t *testing.T) {
	s, _, _ := isoServer(t)
	_, _ = libraryVMStopped(t, s, "v")
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "daemon-nfs", Driver: "nfs", Source: "nas:/other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	orig := isoDirProbe
	t.Cleanup(func() { isoDirProbe = orig })
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if strings.Contains(p, "/mounts/") {
			t.Errorf("the daemon's own NFS mount directory %s was read", p)
		}
		return orig(p)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "v")); err != nil {
		t.Fatalf("start: %v", err)
	}
}

// C-2: an Admin's link is resolved again at every start from the path named,
// so a package update that moves the versioned file keeps working.
func TestISORound3_AnUpdatedLinkIsFollowedAtTheNextStart(t *testing.T) {
	s, fake, _ := isoServer(t)
	dir := t.TempDir()
	v1 := filepath.Join(dir, "virtio-win-0.1.240.iso")
	writeLibFile(t, v1, isoBody)
	link := filepath.Join(dir, "virtio-win.iso")
	if err := os.Symlink(v1, link); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("win", link, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, "win")
	v2 := filepath.Join(dir, "virtio-win-0.1.262.iso")
	writeLibFile(t, v2, isoBody+" new")
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(v2, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(v1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "win")); err != nil {
		t.Fatalf("start after the package moved the versioned file: %v", err)
	}
	if x := fake.DefinedXML("win"); !strings.Contains(x, mustEval(t, v2)) {
		t.Fatalf("the domain was not pointed at the new file:\n%s", x)
	}
}

// C-2: a host path is judged as named too — a link inside a refused place is
// refused even when it points somewhere harmless.
func TestISORound3_ALinkInARefusedPlaceIsRefused(t *testing.T) {
	s, _, _ := isoServer(t)
	plain := filepath.Join(t.TempDir(), "x.iso")
	writeLibFile(t, plain, isoBody)
	inPKI := filepath.Join(s.pkiDir, "x.iso")
	if err := os.Symlink(plain, inPKI); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("p", inPKI, "")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("admin naming a link inside the PKI directory: got %v, want InvalidArgument", err)
	}
}

// ...and at a start of a main-era VM, which no create-time check saw.
func TestISORound3_AMainEraLinkInARefusedPlaceIsRefused(t *testing.T) {
	s, fake, _ := isoServer(t)
	plain := filepath.Join(t.TempDir(), "x.iso")
	writeLibFile(t, plain, isoBody)
	inPKI := filepath.Join(s.pkiDir, "x.iso")
	if err := os.Symlink(plain, inPKI); err != nil {
		t.Fatal(err)
	}
	legacyVM(t, s, fake, "p", inPKI)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "p")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start of a VM whose ISO is a link inside the PKI directory: got %v, want FailedPrecondition", err)
	}
}
