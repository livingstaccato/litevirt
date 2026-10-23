package fleet

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/grpcapi"
)

// The source reads the file at a disk's recorded path and removes it after the
// commit, so it holds the path to its OWN disk places too: a path the target
// would accept (a pool of its own) but that is none of the source's is refused
// before anything is read, sent or removed (review I1).
//
// Mutation: drop the coldSourcePathCheck in copyColdDisksToTarget - the move
// goes through, the file is sent and the source copy removed, and this is red.
func TestFleet_ColdMigrationSourceRefusesAPathOutsideItsOwnDiskPlaces(t *testing.T) {
	var dir string
	fp := newForeignPoolScenario(t,
		func(pool, _ string) string {
			dir = filepath.Join(filepath.Dir(filepath.Dir(pool)), "dstonly")
			return filepath.Join(dir, "fp1-root.qcow2")
		},
		func(pool, _ string) string { return pool })
	if err := os.MkdirAll(fp.targetFile(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	fp.dst.Server.SetStoragePoolsByName(map[string]grpcapi.StoragePoolRef{"dstonly": {Driver: "dir", Target: dir}})
	err := fp.migrate()
	if err == nil || !strings.Contains(err.Error(), "nothing was copied or changed") {
		t.Fatalf("migrate with a disk outside the source's disk places = %v, want the source's refusal", err)
	}
	if _, serr := os.Lstat(filepath.Join(fp.c.tmpRoot, "fs-"+fp.src.Name, fp.disk)); serr != nil {
		t.Errorf("the source's file is gone: %v", serr)
	}
	if _, serr := os.Lstat(fp.targetFile(fp.disk)); serr == nil {
		t.Errorf("the file reached the target")
	}
}
