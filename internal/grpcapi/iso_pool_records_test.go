package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The ISO ownership rule reads the pools' per-file ownership: a file the
// reference's own pool records as its upload is that pool's, whatever other
// project's pool maps the same directory. Such a file is admitted where this
// host has no record of having judged it for the VM (isoIdentityHolds) and
// no source hash vouches for it.

// A VM's first arrival, with no hash from the source.
func TestISOOwnership_AFirstArrivalOfAPoolRecordedFileIsAdmitted(t *testing.T) {
	ctx := context.Background()
	s, _ := stubTarget(t)
	lib, here := libraryVM(t, s, "mig", "acme")
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	src := "/srv/source/acme-isos/install.iso"
	move := func() error {
		_, err := s.EnsureDisks(isoSourcePeer(t, s, "mig"), &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true,
			InstallerIsoPaths: []string{src}, InstallerIsoRuntime: true})
		return err
	}
	if err := move(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("first arrival of a file no record gives the library: got %v, want FailedPrecondition", err)
	}
	// Another pool's upload record does not make it the library's.
	if err := s.recordPoolUpload(ctx, "o-disks", "other", "bob@local", here); err != nil {
		t.Fatal(err)
	}
	if err := move(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("first arrival of another project's upload: got %v, want FailedPrecondition", err)
	}
	if err := s.forgetPoolUpload(ctx, here); err != nil {
		t.Fatal(err)
	}
	if err := s.recordPoolUpload(ctx, "acme-isos", "acme", "pat@local", here); err != nil {
		t.Fatal(err)
	}
	if err := move(); err != nil {
		t.Fatalf("first arrival of the library's recorded upload: %v", err)
	}
}

// A restore: the VM's records went with it when it was deleted, and another
// project's pool has joined the directory since. Its next start admits the
// library's recorded upload.
func TestISOOwnership_ARestoredVMStartsOnAPoolRecordedFile(t *testing.T) {
	ctx := context.Background()
	s, _, _ := isoServer(t)
	_ = acmeOperator(t, s)
	lib := projectLibrary(t, s, "acme-isos", "acme")
	here := mustEval(t, lib) + "/install.iso"
	writeLibFile(t, here, isoBody)
	if _, err := s.CreateVM(adminCtx(), isoCreate("vm1", "acme-isos/install.iso", "acme")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	spec := vmSpecFor(vmRecord(t, s, "vm1"))
	if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.resolveSpecISO(ctx, "vm1", "acme", spec); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("restored VM's start on a file no record gives the library: got %v, want FailedPrecondition", err)
	}
	if err := s.recordPoolUpload(ctx, "acme-isos", "acme", "pat@local", here); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.resolveSpecISO(ctx, "vm1", "acme", spec); err != nil {
		t.Fatalf("restored VM's start on the library's recorded upload: %v", err)
	}
}
