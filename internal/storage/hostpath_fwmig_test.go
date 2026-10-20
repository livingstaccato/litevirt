package storage_test

import (
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/storage"
)

// Every live firmware move record directory is the daemon's own: the data
// directory guard cannot see fwmig's joins (they take the directory as a
// variable), so this iterates fwmig.Dirs(), which fwmig pins to its *Dir
// constants (D2-13 re-review 2 m-5). An external test package: fwmig imports
// libvirt, which imports storage.
//
// Mutation: drop one fwmig directory from dataDirOwned — red.
func TestDataDirOwned_CoversEveryFirmwareMoveRecordDir(t *testing.T) {
	owned := storage.DataDirOwned()
	for _, d := range fwmig.Dirs() {
		if !slices.Contains(owned, d) {
			t.Errorf("fwmig record directory %q is not in dataDirOwned", d)
		}
	}
}
