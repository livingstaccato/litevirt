package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// (re-review rr4 1) An operator can remove a forged row whose name is
// invalid, and the delete touches nothing on the host.
//
// Mutation: refuse an invalid name in DeleteStoragePool — red.
func TestRR4Probe_ForgedInvalidNameRowCleanup(t *testing.T) {
	s := trustServer(t)
	ctx := context.Background()
	victim := filepath.Join(filepath.Dir(s.dataDir), "victim")
	if err := os.MkdirAll(filepath.Join(victim, "keep"), 0o755); err != nil {
		t.Fatal(err)
	}
	name := "x/../../../victim"
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: name, Driver: "local", Target: filepath.Join(s.dataDir, "pools", name), State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	u, _ := s.UntrustedPools(ctx)
	t.Logf("untrusted before: %+v", u)
	_, err := s.DeleteStoragePool(adminCtx(), &pb.DeleteStoragePoolRequest{Name: name, Force: true})
	_, still, _ := corrosion.GetStoragePool(ctx, s.db, s.hostName, name)
	u, _ = s.UntrustedPools(ctx)
	_, verr := os.Stat(filepath.Join(victim, "keep"))
	t.Logf("delete err=%v; row still present=%v; untrusted after=%d; victim intact=%v", err, still, len(u), verr == nil)
	if verr != nil {
		t.Errorf("victim touched")
	}
	if still {
		t.Errorf("the forged row cannot be deleted; pool_row_untrusted keeps naming it")
	}
}
