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

// A pool the host refuses — here two rows on one directory — lists, reads and
// writes nothing, so it offers no installer ISO either, even to an admin who
// passes every permission check on it.
func TestVMISO_ARefusedPoolOffersNoISO(t *testing.T) {
	s, fake, _ := isoServer(t)
	ctx := context.Background()
	dir := filepath.Join(s.dataDir, "pools", "shared")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"isos-a", "isos-b"} {
		if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
			HostName: s.hostName, Name: name, Driver: "dir", Target: dir, State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	iso := filepath.Join(dir, "debian-12.iso")
	writeISO(t, iso)

	_, err := s.CreateVM(adminCtx(), isoCreate("refused", iso, ""))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an ISO in a refused pool: got %v, want FailedPrecondition", err)
	}
	assertNoISODomain(t, s, fake, "refused", iso)
}
