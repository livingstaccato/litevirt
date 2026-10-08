package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// disksDefaultPool gives the server an older cluster's built-in default pool:
// global, on <data_dir>/disks itself.
func disksDefaultPool(t *testing.T, s *Server) string {
	t.Helper()
	disks := filepath.Join(s.dataDir, "disks")
	if err := os.MkdirAll(disks, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "default", Driver: "local", Target: disks, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	return disks
}

// On main an ISO uploaded into an older cluster's default pool on
// <data_dir>/disks was bootable. Its upload lands in disks/uploads now, out of
// the VM disks' namespace; named as the pool's ISO (default/<file>), it is
// that pool's file by its upload record, and the VM is created and starts.
func TestISODisksPool_AnUploadIntoTheDefaultPoolBoots(t *testing.T) {
	s, _, _ := isoServer(t)
	_ = acmeOperator(t, s)
	disks := disksDefaultPool(t, s)
	if err := uploadAs(adminCtx(), s, "default", "installer.iso", isoBody); err != nil {
		t.Fatalf("upload into the default pool: %v", err)
	}
	if _, err := os.Stat(filepath.Join(disks, poolUploadsSubdir, "installer.iso")); err != nil {
		t.Fatalf("the upload is not in disks/uploads: %v", err)
	}
	if _, err := s.CreateVM(adminCtx(), isoCreate("inst", "default/installer.iso", "acme")); err != nil {
		t.Fatalf("CreateVM with the default pool's uploaded ISO: %v", err)
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "inst")); err != nil {
		t.Fatalf("start with the default pool's uploaded ISO: %v", err)
	}
}

// A file in disks/uploads that is not the referenced pool's upload — another
// project's pool's upload, or no upload at all — is not that pool's ISO.
func TestISODisksPool_AnotherProjectsUploadIsRefused(t *testing.T) {
	s, fake, _ := isoServer(t)
	_ = acmeOperator(t, s)
	disks := disksDefaultPool(t, s)
	up := filepath.Join(disks, poolUploadsSubdir)
	if err := os.MkdirAll(up, 0o755); err != nil {
		t.Fatal(err)
	}
	theirs := filepath.Join(up, "theirs.iso")
	writeISO(t, theirs)
	if err := s.recordPoolUpload(context.Background(), "pb", "bravo", "bob@local", theirs); err != nil {
		t.Fatal(err)
	}
	writeISO(t, filepath.Join(up, "stray.iso"))
	for _, f := range []string{"theirs.iso", "stray.iso"} {
		name := "v-" + f[:len(f)-4]
		_, err := s.CreateVM(adminCtx(), isoCreate(name, "default/"+f, "acme"))
		if code := status.Code(err); code != codes.FailedPrecondition && code != codes.PermissionDenied {
			t.Errorf("an ISO %s not the default pool's upload: got %v, want a refusal", f, err)
		}
		assertNoISODomain(t, s, fake, name, f)
	}
}
