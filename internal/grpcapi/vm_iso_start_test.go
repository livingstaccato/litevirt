package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// An installer ISO is checked when the VM is created, but qemu opens the file
// again on every start. Whoever controls the pool directory can swap the ISO
// for a link after the check, so the file is judged again at every start, on
// the host that starts it.

// isoVMStopped creates a VM whose ISO is a pool file, then stops it, and
// returns the stored ISO path and a file standing for any host file the
// caller must not read.
func isoVMStopped(t *testing.T, s *Server, name string) (iso, hostFile string) {
	t.Helper()
	dir := isoPool(t, s, "isos-"+name, "")
	iso = filepath.Join(dir, "install.iso")
	writeISO(t, iso)
	// Named by reference: a pool's file is judged strictly (no link, one
	// link) at every start, unlike an Admin's host path (resolveHostISO).
	if _, err := s.CreateVM(adminCtx(), isoCreate(name, "isos-"+name+"/install.iso", "")); err != nil {
		t.Fatalf("CreateVM %s: %v", name, err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = ?`, name); err != nil {
		t.Fatal(err)
	}
	hostFile = filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(hostFile, []byte("not for the guest"), 0o600); err != nil {
		t.Fatal(err)
	}
	return iso, hostFile
}

func swapForSymlink(t *testing.T, iso, to string) {
	t.Helper()
	if err := os.Remove(iso); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(to, iso); err != nil {
		t.Fatal(err)
	}
}

func swapForHardLink(t *testing.T, iso, to string) {
	t.Helper()
	if err := os.Remove(iso); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(to, iso); err != nil {
		t.Skipf("hard link across directories not possible here: %v", err)
	}
}

func vmRecord(t *testing.T, s *Server, name string) *corrosion.VMRecord {
	t.Helper()
	rec, err := corrosion.GetVM(context.Background(), s.db, name)
	if err != nil || rec == nil {
		t.Fatalf("GetVM %s: %v", name, err)
	}
	return rec
}

// The start preflight every start path shares (StartVM, the restart policy,
// the health-check restart, the reconciler) refuses a swapped ISO.
func TestVMISOStart_PreflightRefusesASymlinkSwappedInAfterCreate(t *testing.T) {
	s, _, key := isoServer(t)
	iso, _ := isoVMStopped(t, s, "swap-key")
	swapForSymlink(t, iso, key)

	_, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "swap-key"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the ISO swapped for a link to the host key: got %v, want FailedPrecondition", err)
	}
}

// A link to a file that is on no deny-list is refused too: the pool's owner
// chose an ISO, not whatever the link now names.
func TestVMISOStart_PreflightRefusesAnySymlink(t *testing.T) {
	s, _, _ := isoServer(t)
	iso, hostFile := isoVMStopped(t, s, "swap-any")
	swapForSymlink(t, iso, hostFile)

	_, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "swap-any"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the ISO swapped for a link to an unlisted file: got %v, want FailedPrecondition", err)
	}
}

func TestVMISOStart_PreflightRefusesAHardLink(t *testing.T) {
	s, _, _ := isoServer(t)
	iso, hostFile := isoVMStopped(t, s, "swap-hard")
	swapForHardLink(t, iso, hostFile)

	_, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "swap-hard"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the ISO swapped for a hard link: got %v, want FailedPrecondition", err)
	}
}

func TestVMISOStart_PreflightAllowsTheUnchangedISO(t *testing.T) {
	s, _, _ := isoServer(t)
	isoVMStopped(t, s, "intact")

	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "intact")); err != nil {
		t.Fatalf("start with the ISO as created: %v", err)
	}
}

// Reverting a snapshot can start the domain; it re-checks the ISO first.
func TestVMISOStart_SnapshotRestoreRefusesASwappedISO(t *testing.T) {
	s, _, key := isoServer(t)
	iso, _ := isoVMStopped(t, s, "revert")
	swapForSymlink(t, iso, key)

	_, err := s.RestoreSnapshot(adminCtx(), &pb.RestoreSnapshotRequest{VmName: "revert", SnapshotName: "any"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("snapshot restore with a swapped ISO: got %v, want FailedPrecondition", err)
	}
}

// A migration target opens the ISO from its own filesystem: EnsureDisks, the
// target's preparation call, judges it there.
func TestVMISOStart_MigrationTargetRefusesASwappedISO(t *testing.T) {
	s, _ := stubTarget(t)
	s.pkiDir = filepath.Join(t.TempDir(), "pki")
	if err := os.MkdirAll(s.pkiDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(s.pkiDir, "host.key")
	if err := os.WriteFile(key, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "install.iso")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mig", Iso: link})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ? WHERE name = 'mig'`, string(spec)); err != nil {
		t.Fatal(err)
	}

	if _, err := ensure(s, "mig"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("migration target with the ISO a link to its host key: got %v, want FailedPrecondition", err)
	}
}

// Several pool rows can share one directory (target-less local pools). An ISO
// found through it must pass the caller's checks on every row, not the first.
func TestVMISO_SharedPoolDirectoryNeedsEveryRow(t *testing.T) {
	s, _, _ := isoServer(t)
	ctx := context.Background()
	for _, p := range []string{"acme", "other"} {
		if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: p}); err != nil {
			t.Fatal(err)
		}
	}
	pat := isoEngineCtx(t, s, "pat", "Operator", projectRBACBase("acme"))
	dir := t.TempDir()
	for _, row := range []corrosion.StoragePoolRecord{
		{HostName: s.hostName, Name: "acme-isos", Driver: "dir", Target: dir, Project: "acme", State: "active"},
		{HostName: s.hostName, Name: "other-isos", Driver: "dir", Target: dir, Project: "other", State: "active"},
	} {
		if err := corrosion.UpsertStoragePool(ctx, s.db, row); err != nil {
			t.Fatal(err)
		}
	}
	iso := filepath.Join(dir, "other-team.iso")
	writeISO(t, iso)

	_, err := s.CreateVM(pat, isoCreate("shared", iso, "acme"))
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ISO in a directory another project's pool also maps: got %v, want PermissionDenied", err)
	}
}

// An Admin's host path is resolved again at every start from the path the VM
// was given (resolveHostISO): a directory above it swapped for a link to
// somewhere else is followed, the file there judged in full, and the domain
// pointed at it — as /var/lib/libvirt/images → /data/images worked on main.
// A swap that lands in a refused place is refused.
func TestVMISOStart_AHostPathsParentDirectoryIsResolvedAgain(t *testing.T) {
	s, fake, key := isoServer(t)
	root := t.TempDir()
	dir := filepath.Join(root, "media")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	iso := filepath.Join(dir, "install.iso")
	writeISO(t, iso)
	if _, err := s.CreateVM(adminCtx(), isoCreate("parent", iso, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if err := s.db.Execute(context.Background(), `UPDATE vms SET state = 'stopped' WHERE name = 'parent'`); err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.Mkdir(elsewhere, 0o755); err != nil {
		t.Fatal(err)
	}
	writeISO(t, filepath.Join(elsewhere, "install.iso"))
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, dir); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "parent")); err != nil {
		t.Fatalf("start with the directory above the ISO now a link: %v", err)
	}
	if x := fake.DefinedXML("parent"); !strings.Contains(x, filepath.Join(elsewhere, "install.iso")) {
		t.Fatalf("the domain was not pointed at the resolved file:\n%s", x)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(key), dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(key, filepath.Join(filepath.Dir(key), "install.iso")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "parent")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the directory swapped for a link into the PKI directory: got %v, want FailedPrecondition", err)
	}
}

// The start judges the CD-ROM the domain actually carries, not spec.Iso: a
// domain regenerated without the installer CD-ROM (reconciler, failover,
// UpdateVM) starts even when that ISO is long gone from this host.
func TestVMISOStart_DomainWithoutTheCDROMStartsEvenIfTheISOIsGone(t *testing.T) {
	s, fake, _ := isoServer(t)
	iso, _ := isoVMStopped(t, s, "noiso")
	xml := fake.DefinedXML("noiso")
	stripped := regexp.MustCompile(`(?s)<disk[^>]*device="cdrom"[^>]*>.*?`+regexp.QuoteMeta(iso)+`.*?</disk>`).ReplaceAllString(xml, "")
	if stripped == xml {
		t.Fatalf("test setup: no installer CD-ROM found in the domain XML:\n%s", xml)
	}
	if err := fake.DefineDomain(stripped); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(iso); err != nil {
		t.Fatal(err)
	}

	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "noiso")); err != nil {
		t.Fatalf("start of a domain that no longer carries the ISO: %v", err)
	}
}

// A caller without snapshot.restore learns nothing about the ISO: the check
// runs after authorization (and on the owner, after any forward).
func TestVMISOStart_SnapshotRestoreChecksAuthorityFirst(t *testing.T) {
	s, _, key := isoServer(t)
	iso, _ := isoVMStopped(t, s, "revert-auth")
	swapForSymlink(t, iso, key)
	viewer := isoEngineCtx(t, s, "vic", "Viewer", "/")

	_, err := s.RestoreSnapshot(viewer, &pb.RestoreSnapshotRequest{VmName: "revert-auth", SnapshotName: "any"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("restore by a viewer: got %v, want PermissionDenied before any ISO check", err)
	}
}
