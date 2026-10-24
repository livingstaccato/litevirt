package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// supersededCopyFixture is a .superseded- copy beside the disk of VM old at a
// path of its own (outside every directory keptScanDirs lists), backing on
// the path a create of web writes, which is missing. It returns the server,
// that path and the copy.
func supersededCopyFixture(t *testing.T) (*Server, string, string) {
	t.Helper()
	s, _ := provableCreateServer(t)
	base := s.images.DiskPath("web", "root")
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(t.TempDir(), "old-root.qcow2")
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "old", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "old", DiskName: "root", HostName: s.hostName, Path: disk, StorageType: "local", DeleteWithVM: true}}); err != nil {
		t.Fatal(err)
	}
	copyAt := disk + ".superseded-20260901T000000.000000000Z"
	if err := qcow2.CreateWithBackingFormat(copyAt, base, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(base); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return s, base, copyAt
}

func failSupersededListing(t *testing.T) {
	t.Helper()
	old := listSupersededDisks
	listSupersededDisks = func(context.Context, *corrosion.Client, string) ([]health.SupersededCopy, error) {
		return nil, errors.New("injected: read the recorded stranded disks: database is locked")
	}
	t.Cleanup(func() { listSupersededDisks = old })
}

// Review B-1 (relkept-on70 round 1): a set-aside copy listing that cannot be
// read leaves the disk scan incomplete, so a create is refused: the scan
// reads the same listings, and a copy beside a disk at a path of its own is
// in no directory it walks. With the listing readable the copy's own
// missing-base finding refuses.
//
// Red on 915cec62c ("listing unreadable": the create goes ahead with a
// warning). Mutation: drop the listings from keptCollisionScan: red.
func TestKeptCollisionScan_ReadsTheSetAsideListings(t *testing.T) {
	t.Run("listing readable", func(t *testing.T) {
		s, base, copyAt := supersededCopyFixture(t)
		err := s.keptMissingBaseRefusal(adminCtx(), keptWritesOf(true, base))
		if err == nil || !strings.Contains(err.Error(), copyAt) {
			t.Fatalf("keptMissingBaseRefusal = %v; want a refusal naming %s", err, copyAt)
		}
	})
	t.Run("listing unreadable", func(t *testing.T) {
		s, base, copyAt := supersededCopyFixture(t)
		failSupersededListing(t)
		err := s.keptMissingBaseRefusal(adminCtx(), keptWritesOf(true, base))
		var unknown *keptChainsUnknownError
		if !errors.As(err, &unknown) || !strings.Contains(err.Error(), ".superseded- disk copies cannot be listed") {
			t.Fatalf("keptMissingBaseRefusal with the listing unreadable = %v; want the unknown-state refusal (%s backs on %s)", err, copyAt, base)
		}
	})
}

// Review NB-3: an unreadable note-side source names what failed, for the
// warning of a create that goes ahead: here the set-aside listing.
//
// Mutation: leave keptNoteChainsError.source unset for a listing: red.
func TestKeptNoteChains_AnErrorNamesItsSource(t *testing.T) {
	s, _, _ := supersededCopyFixture(t)
	failSupersededListing(t)
	_, err := s.keptNoteChains(adminCtx())
	var ne *keptNoteChainsError
	if !errors.As(err, &ne) || !strings.Contains(ne.source, "set-aside .superseded- disk copies") {
		t.Fatalf("keptNoteChains = %v; want a keptNoteChainsError whose source is the .superseded- listing", err)
	}
}

// Review NB-1: a readable kept-disks.json chain refuses on its own finding
// while another entry's chain cannot be read, a write on shared storage
// elsewhere included (that one is not judged by the disk scan).
//
// Red on 915cec62c ("another entry unreadable": the write goes ahead).
// Mutation: return nil chains on an entry's error in keptRegistryChains:
// red.
func TestKeptRegistryChains_AReadableEntryRefusesWhileAnotherDoesNot(t *testing.T) {
	for _, other := range []bool{false, true} {
		name := "alone"
		if other {
			name = "another entry unreadable"
		}
		t.Run(name, func(t *testing.T) {
			s, _ := provableCreateServer(t)
			target := filepath.Join(t.TempDir(), "nfs-web-root.qcow2") // missing
			top := registryKeep(t, s, "old", target)
			if other {
				bad := registryKeep(t, s, "other", filepath.Join(t.TempDir(), "gone.raw"))
				if err := os.Truncate(bad, 16); err != nil { // the magic, and no header to read
					t.Fatal(err)
				}
				if _, err := s.keptRegistryChains(adminCtx()); err == nil {
					t.Fatal("the fixture needs an entry whose chain cannot be read")
				}
			}
			err := s.keptMissingBaseRefusal(adminCtx(), keptWritesOf(false, target))
			if err == nil || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), "backs on although it is missing") {
				t.Fatalf("a write on shared storage at %s's missing base = %v; want the missing-base refusal naming it", top, err)
			}
		})
	}
}
