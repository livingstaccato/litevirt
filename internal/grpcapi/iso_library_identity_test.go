package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 1 of the library round (restore-iso-rereview-1.md).

// I-A: a pool aimed through a link at another project's directory is that
// directory: its files are neither listed nor bootable through the link.
func TestISOIdentity_ALinkedPoolTargetIsTheDirectoryItNames(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	theirs := projectLibrary(t, s, "b-lib", "other")
	writeLibFile(t, filepath.Join(theirs, "win-unattend.iso"), isoBody)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(theirs, alias); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "a-lib", Driver: "dir", Target: alias, Project: "acme",
		Options: map[string]string{"content": "iso"}, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListISOs(pat, &pb.ListISOsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range resp.GetIsos() {
		if e.GetName() == "win-unattend.iso" {
			t.Fatalf("another project's file was listed through a linked pool: %+v", e)
		}
	}
	if _, err := s.CreateVM(pat, isoCreate("a-vm", "a-lib/win-unattend.iso", "acme")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("booting another project's file through a linked pool: got %v, want PermissionDenied", err)
	}
}

// I-B: a VM keeps starting when another project later creates a pool on its
// library's directory, as long as its ISO is the file it was created with; a
// file put there since is judged by the full rule.
func TestISOIdentity_AnotherProjectsLaterPoolDoesNotStopAVM(t *testing.T) {
	s, _, _ := isoServer(t)
	pat := acmeOperator(t, s)
	lib := projectLibrary(t, s, "b-lib", "acme")
	iso := filepath.Join(lib, "debian.iso")
	writeLibFile(t, iso, isoBody)
	if _, err := s.CreateVM(pat, isoCreate("b-vm", "b-lib/debian.iso", "acme")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	stopVM(t, s, "b-vm")
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "a-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "b-vm")); err != nil {
		t.Fatalf("start after another project's pool joined the directory, ISO unchanged: %v", err)
	}
	tmp := filepath.Join(lib, ".swap")
	writeLibFile(t, tmp, "planted by the other project")
	if err := os.Rename(tmp, iso); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "b-vm")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with a new file under the name in a shared directory: got %v, want FailedPrecondition", err)
	}
}

// m6: a stopped VM moves to a host that lacks its ISO or library; the start
// there re-judges it. A running VM's live move stays strict.
func TestISOIdentity_AStoppedMoveToAHostWithoutTheISOIsAllowed(t *testing.T) {
	s, _ := stubTarget(t)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "mig", Iso: "a-lib/foo.iso", IsoScope: isoScopeProject, Project: "acme"})
	if err := s.db.Execute(context.Background(), `UPDATE vms SET spec = ?, project = 'acme' WHERE name = 'mig'`, string(spec)); err != nil {
		t.Fatal(err)
	}
	src := []string{"/srv/source/a-lib/foo.iso"}
	if _, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
		InstallerIsoListed: true, InstallerIsoPaths: src, InstallerIsoRuntime: false}); err != nil {
		t.Fatalf("stopped move to a host without a-lib: %v", err)
	}
	if _, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "mig",
		InstallerIsoListed: true, InstallerIsoPaths: src, InstallerIsoRuntime: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("live move to a host without a-lib: got %v, want FailedPrecondition", err)
	}
}
