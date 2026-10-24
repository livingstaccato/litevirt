package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// keptSourceFixture is VM sv, stopped, its root disk a real qcow2 in the
// disk directory, recorded on this host. It returns the server and the disk.
func keptSourceFixture(t *testing.T) (*Server, string) {
	t.Helper()
	s, _ := provableCreateServer(t)
	base := s.images.DiskPath("sv", "root")
	if err := os.MkdirAll(filepath.Dir(base), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(base, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "sv", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "sv", DiskName: "root", HostName: s.hostName, Path: base, StorageType: "local", DeleteWithVM: true}}); err != nil {
		t.Fatal(err)
	}
	return s, base
}

func badNote(t *testing.T, s *Server, vm string) string {
	t.Helper()
	note := filepath.Join(s.dataDir, "kept-disks", vm+".json")
	if err := os.MkdirAll(filepath.Dir(note), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(note, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	return note
}

// Security review R1: every start of the source of a kept linked clone is
// refused. The operator start (startGatesLocked) also refuses while a note
// cannot be read; the shared start preflight (PrepareHardwareForStart, the
// only gate of the failover, reconciler and health restarts) refuses a
// positive finding only, so an unreadable note does not hold every restart
// on the host.
//
// Red on d4c11ecc1. Mutations: drop keptBaseRefusal from startGatesLocked:
// "operator start" red; from PrepareHardwareForStart: "automated start"
// red; make the preflight's failClosed true: "automated start, unreadable
// note" red.
func TestKeptBaseRefusal_EveryStartOfTheSource(t *testing.T) {
	vmOf := func(t *testing.T, s *Server) *corrosion.VMRecord {
		vm, err := corrosion.GetVM(adminCtx(), s.db, "sv")
		if err != nil || vm == nil {
			t.Fatal(err)
		}
		return vm
	}
	t.Run("operator start", func(t *testing.T) {
		s, base := keptSourceFixture(t)
		top := noteKeep(t, s, "svc", base)
		lease, err := s.startGatesLocked(adminCtx(), "StartVM", vmOf(t, s), 1, 256, true)
		if lease != nil {
			lease.release(context.Background())
		}
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("startGatesLocked = %v; want FailedPrecondition naming %s", err, top)
		}
	})
	t.Run("operator start, unreadable note", func(t *testing.T) {
		s, _ := keptSourceFixture(t)
		note := badNote(t, s, "svc")
		lease, err := s.startGatesLocked(adminCtx(), "StartVM", vmOf(t, s), 1, 256, true)
		if lease != nil {
			lease.release(context.Background())
		}
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), note) {
			t.Fatalf("startGatesLocked with an unreadable note = %v; want FailedPrecondition naming %s", err, note)
		}
	})
	t.Run("automated start", func(t *testing.T) {
		s, base := keptSourceFixture(t)
		top := noteKeep(t, s, "svc", base)
		release, err := s.PrepareHardwareForStart(adminCtx(), vmOf(t, s))
		if release != nil {
			release()
		}
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
			t.Fatalf("PrepareHardwareForStart = %v; want FailedPrecondition naming %s", err, top)
		}
	})
	t.Run("automated start, unreadable note", func(t *testing.T) {
		s, _ := keptSourceFixture(t)
		badNote(t, s, "svc")
		release, err := s.PrepareHardwareForStart(adminCtx(), vmOf(t, s))
		if release != nil {
			release()
		}
		if err != nil {
			t.Fatalf("PrepareHardwareForStart with an unreadable note = %v; want it left to the operator start's gate", err)
		}
	})
}

// Security review R1: an in-place backup restore over the source's disk
// would replace the base under a kept overlay; it is refused before
// anything is written, naming the overlay.
//
// Red on d4c11ecc1. Mutation: drop the keptFilesRefusal from
// inPlaceRestoreLocked: red.
func TestKeptFilesRefusal_InPlaceRestoreOverAKeptBase(t *testing.T) {
	s, base := keptSourceFixture(t)
	top := noteKeep(t, s, "svc", base)
	d, err := s.inPlaceRestoreTarget(adminCtx(), "sv", "root", "_default")
	if err == nil {
		d.release()
	}
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
		t.Fatalf("in-place restore over sv's disk = %v; want FailedPrecondition naming %s", err, top)
	}
}

// Review N1 (X1): a write that cannot tell whether it is at the missing base
// of a noted chain (its own path does not resolve) is refused, as rc7's
// registry leg refuses it, not taken as a miss.
//
// Mutation: treat a writes() error in keptNoteMissingBase as no hit: red.
func TestKeptNoteMissingBase_AWriteThatCannotTellIsRefused(t *testing.T) {
	s, _ := provableCreateServer(t)
	top := noteKeep(t, s, "clone", filepath.Join(t.TempDir(), "gone", "base.qcow2"))
	loop := filepath.Join(t.TempDir(), "loop")
	if err := os.Symlink(loop, loop); err != nil {
		t.Fatal(err)
	}
	w := keptWritesOf(true, filepath.Join(loop, "web-root.qcow2"))
	if w == nil || w.unknown == nil {
		t.Fatalf("keptWritesOf through a symlink loop = %+v; the fixture needs a write whose path does not resolve", w)
	}
	err := s.keptMissingBaseRefusal(adminCtx(), w)
	if err == nil || !strings.Contains(err.Error(), top) || !strings.Contains(err.Error(), "cannot be told") {
		t.Fatalf("keptMissingBaseRefusal = %v; want a refusal naming %s that says it cannot be told", err, top)
	}
}

// Review N1 (X4): a file named by another spelling of its directory (a
// symlink no chain uses) is still held, matched by its resolved path.
//
// Mutation: drop the resolved-path lookup from keptChainHeldIn: red.
func TestKeptNoteChain_HeldByAnyAliasOfItsDirectory(t *testing.T) {
	s, base, was := debrisFixture(t)
	top := noteKeep(t, s, "clone", base)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(filepath.Dir(base), alias); err != nil {
		t.Fatal(err)
	}
	via := filepath.Join(alias, filepath.Base(base))
	held, why := s.keptHolds(adminCtx(), via)
	if !held || !strings.Contains(why, top) {
		t.Fatalf("keptHolds(%s) = %v, %q; want it held by %s", via, held, why, top)
	}
	sameBytes(t, "the base", base, was)
}

// Review N3: an unreadable kept-disk note, which refuses every create here
// that writes a local disk, is named by disk_leftover's creates_refused, as
// an unreadable kept-disks.json is.
//
// Mutation: drop the keptNoteChains check from judgeKeptDisks: red.
func TestKeptDisks_AnUnreadableNoteIsNamedInHealth(t *testing.T) {
	s, _ := provableCreateServer(t)
	note := badNote(t, s, "clone")
	s.judgeKeptDisks(context.Background())
	open, ev := keptDiskCondition(t, s)
	if !open {
		t.Fatalf("disk_leftover is not raised: %s", ev)
	}
	var e map[string]any
	if err := json.Unmarshal([]byte(ev), &e); err != nil {
		t.Fatal(err)
	}
	if refused, _ := e["creates_refused"].(string); !strings.Contains(refused, note) {
		t.Fatalf("creates_refused = %q; want it to name %s", refused, note)
	}
}
