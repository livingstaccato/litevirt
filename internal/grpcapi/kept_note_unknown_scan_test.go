package grpcapi

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/health"
)

// A kept-disk note or a noted chain that cannot be read is judged as an
// unreadable kept-disks.json is (keptCollisionOnDisk): a write on this
// host's own storage is decided by the disk files here, and refused as
// keptChainsUnknownError when that scan cannot complete, which is what an
// import and a failover rebuild classify by. A chain that does read, noted
// or recorded, still refuses on its own finding first, and a write on shared
// storage elsewhere is not held.
//
// Mutations: refuse a note error directly with keptChainsRefusal, as rc7's
// relkept did: "unreadable note, local write" red; judge the unknown state
// before the registry's chains: "a readable registry chain refuses" red;
// drop the !writes.local exemption: "unreadable note, write elsewhere" red.
func TestKeptMissingBase_AnUnreadableNoteIsJudgedByTheDiskScan(t *testing.T) {
	t.Run("unreadable note, local write", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		note := badNote(t, s, "clone")
		err := s.keptMissingBaseRefusal(adminCtx(), keptWritesOf(true, s.images.DiskPath("web", "root")))
		var unknown *keptChainsUnknownError
		if !errors.As(err, &unknown) || !strings.Contains(err.Error(), note) {
			t.Fatalf("keptMissingBaseRefusal with an unreadable note = %v (%T); want a keptChainsUnknownError naming %s", err, err, note)
		}
		var kb *health.KeptBackingFileError
		if !errors.As(err, &kb) {
			t.Fatalf("keptMissingBaseRefusal with an unreadable note = %v; want a KeptBackingFileError (no retry helps)", err)
		}
	})
	t.Run("a readable registry chain refuses while a note cannot be read", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		badNote(t, s, "clone")
		base := s.images.DiskPath("web", "root")
		top := registryKeep(t, s, "old", base) // base missing
		err := s.keptMissingBaseRefusal(adminCtx(), keptWritesOf(true, base))
		var unknown *keptChainsUnknownError
		if err == nil || errors.As(err, &unknown) || !strings.Contains(err.Error(), top) ||
			!strings.Contains(err.Error(), "backs on although it is missing") {
			t.Fatalf("keptMissingBaseRefusal = %v; want the missing-base refusal naming %s, not the unknown-state one", err, top)
		}
	})
	t.Run("unreadable note, write elsewhere", func(t *testing.T) {
		s, _ := provableCreateServer(t)
		badNote(t, s, "clone")
		if err := s.keptMissingBaseRefusal(adminCtx(), keptWritesOf(false, filepath.Join(t.TempDir(), "web-root.qcow2"))); err != nil {
			t.Fatalf("a write on shared storage elsewhere was held by an unreadable note: %v", err)
		}
	})
}
