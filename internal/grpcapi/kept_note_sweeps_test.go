package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// keptNoteFixture seeds web's disk files: root noted as a kept disk, data
// noted as a file a kept disk backs on, swap not noted (debris).
func keptNoteFixture(t *testing.T) (*Server, string, string, string) {
	t.Helper()
	s, _ := provableCreateServer(t)
	seed := func(disk string) string {
		p := s.images.DiskPath("web", disk)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("kept "+disk), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	root, data, swap := seed("root"), seed("data"), seed("swap")
	if err := health.NoteKeptDisks(s.dataDir, "web", []string{root}); err != nil {
		t.Fatal(err)
	}
	if err := health.NoteKeptBackingFiles(s.dataDir, "web", []string{data}); err != nil {
		t.Fatal(err)
	}
	return s, root, data, swap
}

func mustExist(t *testing.T, what, p string) {
	t.Helper()
	if _, err := os.Stat(p); err != nil {
		t.Errorf("%s %s went: %v", what, filepath.Base(p), err)
	}
}

// The delete and rebuild debris sweep keeps every file this host's kept-disk
// note names, as a kept disk or as a file one backs on, and still removes
// the debris: a same-name VM that came here by migration, deleted or rebuilt
// here, used to sweep a disk an earlier VM of the name was deleted with and
// kept (re-review 2, F1). A note that cannot be read keeps every candidate.
//
// Mutation: drop the note from sweepVMDiskDebrisIn's keep set: red.
func TestSweepVMDiskDebris_KeepsWhatTheHostsKeptNoteNames(t *testing.T) {
	s, root, data, swap := keptNoteFixture(t)
	s.sweepVMDiskDebris(adminCtx(), "web")
	mustExist(t, "the noted kept disk", root)
	mustExist(t, "the noted file a kept disk backs on", data)
	if _, err := os.Stat(swap); !os.IsNotExist(err) {
		t.Errorf("web's debris %s survived (%v): the sweep did nothing, so this proves nothing", filepath.Base(swap), err)
	}

	t.Run("unreadable note", func(t *testing.T) {
		s, root, data, swap := keptNoteFixture(t)
		note := filepath.Join(s.dataDir, "kept-disks", "web.json")
		if err := os.WriteFile(note, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.sweepVMDiskDebris(adminCtx(), "web")
		for _, p := range []string{root, data, swap} {
			mustExist(t, "a candidate under an unreadable note", p)
		}
	})
}

// Every other path that removes a VM's disk file on this host keeps a file
// the host's kept-disk note names: the recorded-location delete (VM delete,
// cutover cleanup), a VM's own snapshot layers, and the reference check the
// migration, volume-move and detached-disk cleanups ask (F1).
//
// Mutations: drop the note check from deleteDiskAtRecordedLocation,
// removeOwnDiskLayers or pathStillReferenced: red.
func TestKeptNote_OtherRemovalsKeepItsFiles(t *testing.T) {
	t.Run("recorded location", func(t *testing.T) {
		s, root, _, _ := keptNoteFixture(t)
		d := &corrosion.DiskRecord{VMName: "web", DiskName: "root", HostName: s.hostName, Path: root, StorageType: "local"}
		if err := s.deleteDiskAtRecordedLocation(adminCtx(), d); err != nil {
			t.Fatalf("deleteDiskAtRecordedLocation: %v", err)
		}
		mustExist(t, "the noted kept disk", root)
	})
	t.Run("own snapshot layers", func(t *testing.T) {
		s, _, data, _ := keptNoteFixture(t)
		s.removeOwnDiskLayers(adminCtx(), "web", []string{data})
		mustExist(t, "the noted file a kept disk backs on", data)
	})
	t.Run("reference check", func(t *testing.T) {
		s, root, data, swap := keptNoteFixture(t)
		for _, p := range []string{root, data} {
			if ref, why, _ := s.pathStillReferenced(adminCtx(), p, "web", "root"); !ref {
				t.Errorf("%s, in the kept-disk note, reads as unreferenced", filepath.Base(p))
			} else if why == "" {
				t.Errorf("%s: referenced with no reason", filepath.Base(p))
			}
		}
		if ref, why, err := s.pathStillReferenced(adminCtx(), swap, "web", "root"); ref || err != nil {
			t.Errorf("%s, in no note, reads as referenced (%s, %v)", filepath.Base(swap), why, err)
		}
	})
}
