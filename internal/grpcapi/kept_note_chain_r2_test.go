package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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

// Security review R1, re-review P1 and P2: every start of the source of a
// kept linked clone is refused, the operator start (startGatesLocked) and
// the shared start preflight (PrepareHardwareForStart, the only gate of the
// failover, reconciler, onboot and health restarts) alike:
//
//   - a finding from a readable note refuses, whatever else cannot be read
//     (P1: an unrelated corrupt note made the preflight drop it, and an
//     onboot start after a reboot wrote the base);
//   - while kept state cannot be read, a VM that could be a base (a disk row,
//     live or deleted, names its disk as its backing_disk) is refused;
//   - and every other VM starts (P2: one bad note held every start on the
//     host).
//
// Red on d4c11ecc1 ("positive" subtests) and on 087ac16aa ("automated,
// positive with another note unreadable"; "operator, unknown, not a base").
// Mutations: drop keptBaseRefusal from startGatesLocked: "operator,
// positive" red; from PrepareHardwareForStart: the "automated" positive
// subtests red; return keptNoteChains' error without what it read
// (all-or-nothing again): "automated, positive with another note unreadable"
// red; keptOnUnknownIfBase treated as Allow: the "base candidate" subtests
// red; as Refuse: the "not a base" subtests red.
func TestKeptBaseRefusal_EveryStartOfTheSource(t *testing.T) {
	vmOf := func(t *testing.T, s *Server, name string) *corrosion.VMRecord {
		vm, err := corrosion.GetVM(adminCtx(), s.db, name)
		if err != nil || vm == nil {
			t.Fatal(err)
		}
		return vm
	}
	operator := func(t *testing.T, s *Server, name string) error {
		lease, err := s.startGatesLocked(adminCtx(), "StartVM", vmOf(t, s, name), 1, 256, true)
		if lease != nil {
			lease.release(context.Background())
		}
		return err
	}
	automated := func(t *testing.T, s *Server, name string) error {
		release, err := s.PrepareHardwareForStart(adminCtx(), vmOf(t, s, name))
		if release != nil {
			release()
		}
		return err
	}
	// deletedClone records a clone of sv's disk deleted with --keep-disks:
	// its disk row soft-deleted, its overlay's note unreadable.
	deletedClone := func(t *testing.T, s *Server, base string) string {
		top := filepath.Join(t.TempDir(), "svc-root.qcow2")
		if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "svc", HostName: s.hostName, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: "svc", DiskName: "root", HostName: s.hostName, Path: top, BackingDisk: base, StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteVM(adminCtx(), s.db, "svc"); err != nil {
			t.Fatal(err)
		}
		return badNote(t, s, "svc")
	}
	plainVM := func(t *testing.T, s *Server) {
		other := s.images.DiskPath("plain", "root")
		if err := qcow2.Create(other, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "plain", HostName: s.hostName, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: "plain", DiskName: "root", HostName: s.hostName, Path: other, StorageType: "local", DeleteWithVM: true}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, start := range []struct {
		name string
		do   func(*testing.T, *Server, string) error
	}{{"operator", operator}, {"automated", automated}} {
		t.Run(start.name+", positive", func(t *testing.T) {
			s, base := keptSourceFixture(t)
			top := noteKeep(t, s, "svc", base)
			if err := start.do(t, s, "sv"); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
				t.Fatalf("start of sv = %v; want FailedPrecondition naming %s", err, top)
			}
		})
		t.Run(start.name+", positive with another note unreadable", func(t *testing.T) {
			s, base := keptSourceFixture(t)
			top := noteKeep(t, s, "svc", base)
			badNote(t, s, "other")
			if err := start.do(t, s, "sv"); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), top) {
				t.Fatalf("start of sv = %v; want FailedPrecondition naming %s, though another note cannot be read", err, top)
			}
		})
		t.Run(start.name+", unknown, base candidate", func(t *testing.T) {
			s, base := keptSourceFixture(t)
			note := deletedClone(t, s, base)
			err := start.do(t, s, "sv")
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), note) || !strings.Contains(err.Error(), "svc") {
				t.Fatalf("start of sv while %s cannot be read = %v; want FailedPrecondition naming it and the clone svc", note, err)
			}
		})
		t.Run(start.name+", unknown, not a base", func(t *testing.T) {
			s, base := keptSourceFixture(t)
			deletedClone(t, s, base)
			plainVM(t, s)
			if err := start.do(t, s, "plain"); err != nil {
				t.Fatalf("start of plain, which nothing was cloned from, while a note cannot be read = %v; want it to go on", err)
			}
		})
	}
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
// Mutations: drop the keptNoteChains check from judgeKeptDisks: red; drop
// its keptCollisionScan (relkept-on70 merge): red.
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
	refused, _ := e["creates_refused"].(string)
	if !strings.Contains(refused, note) {
		t.Fatalf("creates_refused = %q; want it to name %s", refused, note)
	}
	// The disk scan reads the notes too, so it cannot complete either, and
	// every local create is held (keptCollisionOnDisk), as the evidence says.
	if !strings.Contains(refused, "whatever their names") {
		t.Fatalf("creates_refused = %q; want it to say every local create is held", refused)
	}
}

// Re-review P4: a cutover's runtime handoff starts the VM with StartDomain,
// outside startGatesLocked and PrepareHardwareForStart. It refuses, and
// leaves the domain down, while the VM backs a linked clone, live or kept.
//
// Red on 087ac16aa (the handoff starts it). Mutations: drop the kept check
// from finishVMReplaceRuntime: "kept clone" red; drop the linkedClonesOf
// check: "live clone" red.
func TestFinishVMReplaceRuntime_NeverStartsALinkedCloneBase(t *testing.T) {
	handoff := func(t *testing.T, s *Server) (corrosion.VMReplaceCleanup, *corrosion.VMRecord) {
		vm, err := corrosion.GetVM(adminCtx(), s.db, "sv")
		if err != nil || vm == nil {
			t.Fatalf("GetVM: %v", err)
		}
		dom := "<domain type='kvm'><name>sv-next</name><uuid>uuid-sv</uuid><memory unit='MiB'>256</memory><vcpu>1</vcpu><devices>" +
			"</devices></domain>"
		return corrosion.VMReplaceCleanup{OperationID: "op-sv", AcceptedState: "running",
			Handoff: corrosion.VMReplaceHandoff{XML: dom, UUID: "uuid-sv"},
			Manifest: corrosion.VMReplaceManifest{
				HostName: s.hostName, ReplacedVM: "sv", Replacement: "sv-next",
				ReplacementIncarnation: vm.CreatedAt, ReplacementUUID: "uuid-sv",
			}}, vm
	}
	check := func(t *testing.T, s *Server, want string) {
		cl, _ := handoff(t, s)
		err := s.finishVMReplaceRuntime(adminCtx(), cl)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("finishVMReplaceRuntime = %v; want a refusal naming %s", err, want)
		}
		if active, _ := s.virt.DomainIsActive("sv"); active {
			t.Fatal("the handoff started sv")
		}
	}
	t.Run("kept clone", func(t *testing.T) {
		s, base := keptSourceFixture(t)
		check(t, s, noteKeep(t, s, "svc", base))
	})
	t.Run("live clone", func(t *testing.T) {
		s, base := keptSourceFixture(t)
		top := filepath.Join(t.TempDir(), "svc-root.qcow2")
		if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: "svc", HostName: s.hostName, State: "stopped"}, nil,
			[]corrosion.DiskRecord{{VMName: "svc", DiskName: "root", HostName: s.hostName, Path: top, BackingDisk: base, StorageType: "local"}}); err != nil {
			t.Fatal(err)
		}
		check(t, s, "svc")
	})
	t.Run("control", func(t *testing.T) {
		s, _ := keptSourceFixture(t)
		cl, _ := handoff(t, s)
		if err := s.finishVMReplaceRuntime(adminCtx(), cl); err != nil {
			t.Fatalf("finishVMReplaceRuntime with no clone: %v", err)
		}
	})
}

// Re-review P3 (M1): a .superseded- copy's chain holds what it backs on, as
// a .kept- copy's does: a failover's set-aside of an overlay, or a kept
// overlay rebased onto a set-aside copy, still names that base.
//
// Mutation: leave the .superseded- copies out of keptNoteChains: red.
func TestKeptNoteChain_ASupersededCopyHoldsItsBase(t *testing.T) {
	s, base, was := debrisFixture(t)
	copyAt := filepath.Join(filepath.Dir(base), "old-root.qcow2.superseded-20260901T000000.000000000Z")
	if err := qcow2.CreateWithBackingFormat(copyAt, base, "qcow2", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	held, why := s.keptHolds(adminCtx(), base)
	if !held || !strings.Contains(why, copyAt) {
		t.Fatalf("keptHolds(%s) = %v, %q; want it held by the set-aside copy %s", base, held, why, copyAt)
	}
	s.sweepVMDiskDebris(adminCtx(), "web")
	sameBytes(t, "the base a .superseded- copy backs on", base, was)
}

// Re-review P3 (M2): a set-aside copy listing that cannot be read fails
// closed, as an unreadable note does: every removal keeps its file, and the
// refusal names the listing.
//
// Mutation: ignore a listKeptDisks error in keptNoteChains: red.
func TestKeptNoteChain_AnUnreadableCopyListingHoldsEverything(t *testing.T) {
	for _, which := range []string{".kept-", ".superseded-"} {
		t.Run(which, func(t *testing.T) {
			s, base, was := debrisFixture(t)
			boom := func(context.Context, *corrosion.Client, string) error {
				return errors.New("injected: the disk directory does not list")
			}
			if which == ".kept-" {
				old := listKeptDisks
				listKeptDisks = func(ctx context.Context, db *corrosion.Client, dir string) ([]health.KeptCopy, error) {
					return nil, boom(ctx, db, dir)
				}
				t.Cleanup(func() { listKeptDisks = old })
			} else {
				old := listSupersededDisks
				listSupersededDisks = func(ctx context.Context, db *corrosion.Client, dir string) ([]health.SupersededCopy, error) {
					return nil, boom(ctx, db, dir)
				}
				t.Cleanup(func() { listSupersededDisks = old })
			}
			held, why := s.keptHolds(adminCtx(), base)
			if !held || !strings.Contains(why, which) {
				t.Fatalf("keptHolds with the %s listing unreadable = %v, %q; want held, naming it", which, held, why)
			}
			s.sweepVMDiskDebris(adminCtx(), "web")
			sameBytes(t, "a candidate while a copy listing cannot be read", base, was)
		})
	}
}

// Re-review P2: a template is a possible base whatever its rows say (a
// clone's rows may be purged): while kept state cannot be read, its start
// is refused.
//
// Mutation: drop the template branch of keptMayBeABase: red.
func TestKeptMayBeABase_ATemplate(t *testing.T) {
	s, _ := keptSourceFixture(t)
	if base, _, err := s.keptMayBeABase(adminCtx(), "sv"); err != nil || base {
		t.Fatalf("keptMayBeABase(sv) before = %v, %v; want false", base, err)
	}
	if err := corrosion.SetVMTemplate(adminCtx(), s.db, "sv", true); err != nil {
		t.Fatal(err)
	}
	if base, why, err := s.keptMayBeABase(adminCtx(), "sv"); err != nil || !base || !strings.Contains(why, "template") {
		t.Fatalf("keptMayBeABase(template sv) = %v, %q, %v; want true, naming it a template", base, why, err)
	}
}
