package grpcapi

import (
	"context"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A pool the host refuses — here a directory pool on the directory that
// contains the daemon's data directory — lists, reads and writes nothing, so
// it offers no installer ISO either, even to an admin who passes every
// permission check on it and names the ISO as that pool's reference. The ISO
// itself is a file the read check alone would allow.
func TestVMISO_ARefusedPoolOffersNoISO(t *testing.T) {
	s, fake, _ := isoServer(t)
	ctx := context.Background()
	dir := filepath.Dir(s.dataDir)
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "refused", Driver: "dir", Target: dir, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	iso := filepath.Join(dir, "debian-12.iso")
	writeISO(t, iso)

	_, err := s.CreateVM(adminCtx(), isoCreate("refused", "refused/debian-12.iso", ""))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an ISO in a refused pool: got %v, want FailedPrecondition", err)
	}
	assertNoISODomain(t, s, fake, "refused", iso)
}
