package fleet

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A replicated storage_pools row has no origin check: any member can write one
// naming the TARGET host. A foreign pool directory outside the target's own
// disks/, pools/ and mounts/ areas is therefore refused even when a row of the
// target's own names the same directory, so such a row can never widen a
// cold-move receive (re-review X1; the refresh-tick path of
// withinDiskArtifactRoot is a separate, older issue).
//
// Mutation: accept a foreign directory because a pool row of the target's names
// it (the own-pool branch of foreignPoolDirAcceptable, as in 39e6d402e) - both
// rows go red.
func TestFleet_ColdMigrationRefusesAForeignPoolDirectoryEvenWhenAForgedRowNamesTheTarget(t *testing.T) {
	for _, mk := range []bool{false, true} {
		name := "dir-absent"
		if mk {
			name = "dir-present"
		}
		t.Run(name, func(t *testing.T) {
			var outside string
			fp := newForeignPoolScenario(t,
				func(pool, _ string) string {
					outside = filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(pool))), "srv-pwn")
					return filepath.Join(outside, "x.qcow2")
				},
				func(pool, _ string) string {
					return filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(pool))), "srv-pwn")
				})
			// The forged row: written through the source's database, naming the target.
			if err := corrosion.UpsertStoragePool(context.Background(), fp.src.DB, corrosion.StoragePoolRecord{
				HostName: fp.dst.Name, Name: "forged", Driver: "dir", Target: outside, State: "active"}); err != nil {
				t.Fatal(err)
			}
			if mk {
				if err := os.MkdirAll(fp.targetFile(outside), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := fp.probeReceive(t); err == nil || !strings.Contains(err.Error(), "not in a disk-artifact root") {
				t.Fatalf("a forged row naming the target made it answer %v for %s, want the refusal", err, fp.disk)
			}
			if merr := fp.migrate(); merr == nil {
				t.Errorf("migrate --cold succeeded into %s", outside)
			}
			if _, serr := os.Lstat(fp.targetFile(fp.disk)); serr == nil {
				t.Errorf("%s was written on the target", fp.disk)
			}
		})
	}
}
