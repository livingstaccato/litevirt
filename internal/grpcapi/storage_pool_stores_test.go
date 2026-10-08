package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// The import's placement records (<data_dir>/import-placements) and this
// host's record of the installer ISOs it judged (<data_dir>/iso-identity) are
// the daemon's own state: a pool there could forge or remove them. Neither is
// ever a pool's directory — not the store itself, not a directory inside it,
// not a link to it — whether the pool is being created or is already there.
func TestPoolTarget_TheImportAndISORecordStoresAreNeverAPool(t *testing.T) {
	s := newPoolTestServer(t)
	for _, store := range []string{importPlacementDirName, isoIdentityDir} {
		dir := filepath.Join(s.dataDir, store)
		inside := filepath.Join(dir, "inner")
		if err := os.MkdirAll(inside, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(t.TempDir(), "to-"+store)
		if err := os.Symlink(dir, link); err != nil {
			t.Fatal(err)
		}
		for _, target := range []string{dir, inside, link} {
			if err := storage.CheckWriteRoot(target, s.dataDir, ""); err == nil {
				t.Errorf("%s is a pool write root", target)
			}
			if _, err := s.CreateStoragePool(adminCtx(), &pb.CreateStoragePoolRequest{Name: "p", Driver: "dir", Target: target}); err == nil {
				t.Errorf("an admin created a pool at %s", target)
			}
			ref := StoragePoolRef{Driver: "dir", Target: target}
			if err := corrosion.UpsertStoragePool(adminCtx(), s.db, corrosion.StoragePoolRecord{
				HostName: s.hostName, Name: "legacy", Driver: "dir", Target: target, State: "active",
			}); err != nil {
				t.Fatal(err)
			}
			if err := s.checkPoolForWrite(adminCtx(), "legacy", ref); err == nil {
				t.Errorf("an existing pool at %s is used", target)
			}
		}
	}
}
