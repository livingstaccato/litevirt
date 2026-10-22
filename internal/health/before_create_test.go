package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func samePath(p string) string { return p }

func trustedReplica() (bool, string) { return true, "" }

// seams restores the set-aside filesystem seams after the test.
func seams(t *testing.T) {
	t.Helper()
	lstat, rename := supersededLstat, supersededRename
	t.Cleanup(func() { supersededLstat, supersededRename = lstat, rename })
}

// webDeletedWhileNodeADown: web was recorded on node-a (its real disk at
// path), failed over to node-b, and was deleted — with --keep-disks when
// keep — while node-a was down.
func webDeletedWhileNodeADown(t *testing.T, keep bool) (*corrosion.Client, *Reconciler, string) {
	t.Helper()
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	if err := MarkStrandedForDelete(ctx, db, "node-b", "web", keep, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	return db, r, path
}

func setAsideCopies(t *testing.T, path, infix string) []string {
	t.Helper()
	m, err := filepath.Glob(path + infix + "*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A create on node-a clears web-root.qcow2. The real disk a failover left
// there is set aside for the retention; once the delete kept it
// (--keep-disks), it is moved to a .kept- name instead, which nothing removes.
// Either way the record is resolved and the bytes are kept.
//
// Mutation: ignore KeptByDelete — the kept disk is set aside as a
// .superseded- copy (the retention removes it).
func TestSetAsideBeforeCreate_MovesTheDiskByWhatTheDeleteSaid(t *testing.T) {
	for _, keep := range []bool{false, true} {
		t.Run(map[bool]string{false: "rm", true: "keep-disks"}[keep], func(t *testing.T) {
			db, r, path := webDeletedWhileNodeADown(t, keep)
			done, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
			moved := done.Moved
			if err != nil {
				t.Fatal(err)
			}
			want, other := supersededInfix, keptInfix
			if keep {
				want, other = keptInfix, supersededInfix
			}
			got := setAsideCopies(t, path, want)
			if len(got) != 1 || len(setAsideCopies(t, path, other)) != 0 || fileExists(path) {
				t.Fatalf("%s copies %v, %s copies %v, at path %v; want one %s copy",
					want, got, other, setAsideCopies(t, path, other), fileExists(path), want)
			}
			if b, _ := os.ReadFile(got[0]); string(b) != "the real disk" {
				t.Fatalf("the copy holds %q", b)
			}
			if len(moved) != 1 || moved[0].Kept != keep || moved[0].To != got[0] {
				t.Fatalf("moved = %+v", moved)
			}
			if strandedOpen(t, db) {
				t.Fatal("the record is still open")
			}
		})
	}
}

// A disk the delete kept is moved to a .kept- name with no record of a
// failover, or whatever the record says: one recorded on this host that the
// delete here did not remove (`lv rm --keep-disks web` then `lv create web`
// on the same host), and one recorded delete_with_vm=false.
//
// Mutations: drop the recorded-on-this-host rule — "same host" leaves the
// disk to the sweep; drop the delete_with_vm rule — "delete_with_vm=false"
// sets it aside as a .superseded- copy; ignore the host's note — "noted
// here" leaves it to the sweep.
func TestSetAsideBeforeCreate_KeptDisks(t *testing.T) {
	for _, tc := range []struct {
		name, update string
		record       bool
	}{
		{"same host", `UPDATE vm_disks SET host_name = 'node-a' WHERE vm_name = 'web'`, false},
		{"delete_with_vm=false", `UPDATE vm_disks SET delete_with_vm = 0 WHERE vm_name = 'web'`, true},
		{"noted here", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _, _, dataDir, path := strandedFixture(t)
			ctx := context.Background()
			if tc.update == "" {
				if err := NoteKeptDisks(dataDir, "web", []string{path}); err != nil {
					t.Fatal(err)
				}
				tc.update = `UPDATE vm_disks SET size_bytes = size_bytes WHERE vm_name = 'web'`
			}
			if tc.record {
				recordWeb(t, db, time.Now())
			}
			if err := db.Execute(ctx, tc.update); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
				t.Fatal(err)
			}
			done, err := SetAsideBeforeCreate(ctx, db, dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
			moved := done.Moved
			if err != nil {
				t.Fatal(err)
			}
			if len(moved) != 1 || !moved[0].Kept || len(setAsideCopies(t, path, keptInfix)) != 1 || fileExists(path) ||
				len(setAsideCopies(t, path, supersededInfix)) != 0 {
				t.Fatalf("moved %+v; kept copies %v; superseded %v", moved, setAsideCopies(t, path, keptInfix), setAsideCopies(t, path, supersededInfix))
			}
			if strandedOpen(t, db) {
				t.Fatal("the record is still open")
			}
		})
	}
}

// What is at a path the create clears cannot be read, or the move of a disk
// that must be kept fails: the create is refused, naming the path, the cause
// and what to do. Nothing is moved, and the record stays open.
//
// Mutation: ignore the lstat error (treat it as not there) — no refusal.
func TestSetAsideBeforeCreate_RefusesWhatCannotBeRead(t *testing.T) {
	for _, tc := range []struct{ name, op string }{{"lstat", "lstat"}, {"rename", "rename"}} {
		t.Run(tc.name, func(t *testing.T) {
			seams(t)
			db, r, path := webDeletedWhileNodeADown(t, false)
			if tc.op == "lstat" {
				supersededLstat = func(p string) (os.FileInfo, error) {
					if p == path {
						return nil, &os.PathError{Op: "lstat", Path: p, Err: syscall.EIO}
					}
					return os.Lstat(p)
				}
			} else {
				supersededRename = func(from, to string) error {
					return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EIO}
				}
			}
			_, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
			if err == nil {
				t.Fatal("the create was not refused")
			}
			msg := err.Error()
			for _, w := range []string{path, "input/output error", "retry", "another host"} {
				if !strings.Contains(msg, w) {
					t.Fatalf("refusal %q does not say %q", msg, w)
				}
			}
			if !fileExists(path) {
				t.Fatal("the disk was moved")
			}
			if !strandedOpen(t, db) {
				t.Fatal("the record was resolved")
			}
		})
	}
}

// A path that reads as missing is not there, and refuses nothing: ENOTDIR
// (a component is a file), and a rename that loses to the reconciler's own
// pass, which set the disk aside first (ENOENT).
//
// Mutation: refuse on any rename error — the lost race refuses the create.
func TestSetAsideBeforeCreate_NotThereRefusesNothing(t *testing.T) {
	t.Run("ENOTDIR", func(t *testing.T) {
		seams(t)
		db, r, path := webDeletedWhileNodeADown(t, false)
		supersededLstat = func(p string) (os.FileInfo, error) {
			if p == path {
				return nil, &os.PathError{Op: "lstat", Path: p, Err: syscall.ENOTDIR}
			}
			return os.Lstat(p)
		}
		if _, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now()); err != nil {
			t.Fatalf("refused: %v", err)
		}
	})
	t.Run("reconciler first", func(t *testing.T) {
		seams(t)
		db, r, path := webDeletedWhileNodeADown(t, false)
		first := path + supersededInfix + "first"
		supersededRename = func(from, to string) error {
			if err := os.Rename(from, first); err != nil { // the pass's rename
				t.Fatal(err)
			}
			return os.Rename(from, to)
		}
		done, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
		moved := done.Moved
		if err != nil {
			t.Fatalf("refused: %v", err)
		}
		if len(moved) != 0 || !fileExists(first) {
			t.Fatalf("moved %+v; the pass's copy present %v", moved, fileExists(first))
		}
	})
}

// On a replica that has not caught up, a create that would clear a file
// there is refused: the delete's record may not be here yet. One that clears
// nothing goes ahead, and leaves the record alone.
//
// Mutation: skip the trust check — the disk is moved on the untrusted
// replica.
func TestSetAsideBeforeCreate_RefusesOnAnUntrustedReplica(t *testing.T) {
	untrusted := func() (bool, string) { return false, "no peer answered" }
	db, r, path := webDeletedWhileNodeADown(t, false)
	_, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, untrusted, time.Now())
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "caught up") ||
		!strings.Contains(err.Error(), "no peer answered") {
		t.Fatalf("refusal = %v, want it to name %s and the replica", err, path)
	}
	if !fileExists(path) || len(setAsideCopies(t, path, supersededInfix)) != 0 {
		t.Fatal("the disk was moved on an untrusted replica")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, untrusted, time.Now()); err != nil {
		t.Fatalf("a create that clears nothing was refused: %v", err)
	}
	if !strandedOpen(t, db) {
		t.Fatal("the record was changed on an untrusted replica")
	}
}

// A recorded path that reads as missing keeps its entry while its directory
// is empty, as a volume not mounted yet reads; missing from a directory that
// lists other files, it is gone and its entry goes — as on the reconciler's
// pass (mayBeUnmounted).
//
// Mutations: drop the entry of every missing path — the record is resolved
// while the volume may be unmounted; leave such a path out of
// MayBeUnmounted — no event can name it.
func TestSetAsideBeforeCreate_MissingEntryWaitsForAVolumeNotMountedYet(t *testing.T) {
	for _, mounted := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty dir", true: "dir lists other files"}[mounted], func(t *testing.T) {
			db, r, path := webDeletedWhileNodeADown(t, false)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if mounted {
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "other-root.qcow2"), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			done, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if strandedOpen(t, db) == mounted {
				t.Fatalf("record open %v, want %v", strandedOpen(t, db), !mounted)
			}
			// The caller makes each a VM event (grpcapi).
			if want := !mounted; (len(done.MayBeUnmounted) == 1 && done.MayBeUnmounted[0] == path) != want {
				t.Fatalf("may be unmounted = %v, want %s listed: %v", done.MayBeUnmounted, path, want)
			}
		})
	}
}

// A disk the delete kept stays at its path on the reconciler's pass, and its
// entry goes: --keep-disks is never put on the retention clock.
//
// Mutations: drop the kept check in tendDeletedVMStranded — the disk is set
// aside as a .superseded- copy; drop the note — the create (with the record
// gone) leaves the disk to the sweep.
//
// The mark is written for --keep-disks only, and cleared by a plain delete
// of the same VM after it (an earlier --keep-disks attempt that failed).
func TestTendDeletedVMStranded_LeavesAKeptDiskAtItsPath(t *testing.T) {
	db, r, path := webDeletedWhileNodeADown(t, true)
	r.tendStrandedDisks(context.Background())
	if !fileExists(path) || len(setAsideCopies(t, path, supersededInfix)) != 0 {
		t.Fatalf("the kept disk was moved: copies %v", setAsideCopies(t, path, supersededInfix))
	}
	if strandedOpen(t, db) {
		t.Fatal("the record is still open")
	}
	// The record resolved, a create of web here later still moves it aside
	// as kept: the host noted it.
	if noted, _ := keptDisksOf(r.dataDir, "web"); len(noted) != 1 || noted[0] != path {
		t.Fatalf("noted %v, want %s", noted, path)
	}
	if err := db.Execute(context.Background(), `UPDATE health_conditions SET deleted_at = ?`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	done, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
	moved := done.Moved
	if err != nil || len(moved) != 1 || !moved[0].Kept {
		t.Fatalf("moved %+v, %v; want the kept disk moved to a .kept- name", moved, err)
	}
	if noted, _ := keptDisksOf(r.dataDir, "web"); len(noted) != 0 {
		t.Fatalf("the note still lists %v once the disk was moved", noted)
	}
}

// MarkStrandedForDelete flips the record's KeptByDelete both ways, and a
// plain delete after a --keep-disks attempt that failed clears it. Either way
// the record says which incarnation's delete decided (DeleteDecided).
//
// Mutations: skip the write when keep is false — the flag stays set; leave
// DeleteDecided unwritten — it is empty.
func TestMarkStrandedForDelete_SetsAndClears(t *testing.T) {
	db, _, _, _, _ := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	vm, err := corrosion.GetVM(ctx, db, "web")
	if err != nil || vm == nil || vm.CreatedAt == "" {
		t.Fatalf("web = %+v, %v", vm, err)
	}
	for _, keep := range []bool{true, false} {
		if err := MarkStrandedForDelete(ctx, db, "node-b", "web", keep, time.Now()); err != nil {
			t.Fatal(err)
		}
		_, ev, _ := strandedRow(t, db, "web", "node-a")
		if ev.KeptByDelete != keep || ev.DeleteDecided != vm.CreatedAt || len(ev.Disks) != 1 {
			t.Fatalf("after marking %v: %+v, want decided by %s", keep, ev, vm.CreatedAt)
		}
	}
}

// undecidedDelete: web was recorded on node-a (its real disk at path),
// failed over to node-b, and was deleted while node-a was down, by a delete
// whose decision node-a's record does not hold: an earlier release's (no
// mark), or a --keep-disks mark lost to node-a's write of the record from
// before it.
func undecidedDelete(t *testing.T, lost bool) (*corrosion.Client, *Reconciler, string) {
	t.Helper()
	db, _, r, _, path := strandedFixture(t)
	ctx := context.Background()
	recordWeb(t, db, time.Now())
	if lost {
		row, before, _, err := readStranded(ctx, db, "web", "node-a")
		if err != nil {
			t.Fatal(err)
		}
		if err := MarkStrandedForDelete(ctx, db, "node-b", "web", true, time.Now()); err != nil {
			t.Fatal(err)
		}
		if err := writeStranded(ctx, db, "node-a", row, true, before, time.Now()); err != nil {
			t.Fatal(err)
		}
		if _, ev, _ := strandedRow(t, db, "web", "node-a"); ev.KeptByDelete || ev.DeleteDecided != "" {
			t.Fatalf("the mark was not lost: %+v", ev)
		}
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	return db, r, path
}

var undecidedCases = map[bool]string{false: "earlier release's delete", true: "mark lost"}

// A disk still at its path whose record does not say what the deleted
// incarnation's delete decided stays where it is on the reconciler's pass,
// noted, and its record is resolved: it may be one --keep-disks kept. A
// create of web here later moves it to a .kept- name.
//
// Mutation: set it aside whenever KeptByDelete is unset (ignore
// DeleteDecided) — it is set aside as a .superseded- copy.
func TestTendDeletedVMStranded_KeepsTheDiskOfAnUndecidedDelete(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(undecidedCases[lost], func(t *testing.T) {
			db, r, path := undecidedDelete(t, lost)
			r.tendStrandedDisks(context.Background())
			if !fileExists(path) || len(setAsideCopies(t, path, supersededInfix)) != 0 {
				t.Fatalf("the disk was moved: copies %v", setAsideCopies(t, path, supersededInfix))
			}
			if strandedOpen(t, db) {
				t.Fatal("the record is still open")
			}
			if noted, _ := keptDisksOf(r.dataDir, "web"); len(noted) != 1 || noted[0] != path {
				t.Fatalf("noted %v, want %s", noted, path)
			}
			done, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
			if err != nil || len(done.Moved) != 1 || !done.Moved[0].Kept || len(setAsideCopies(t, path, keptInfix)) != 1 {
				t.Fatalf("moved %+v, %v; want the disk moved to a .kept- name", done.Moved, err)
			}
		})
	}
}

// A create before the pass moves such a disk to a .kept- name, never to a
// .superseded- one, and resolves the record.
//
// Mutation: as above, before the create — it is set aside as a .superseded-
// copy.
func TestSetAsideBeforeCreate_KeepsTheDiskOfAnUndecidedDelete(t *testing.T) {
	for _, lost := range []bool{false, true} {
		t.Run(undecidedCases[lost], func(t *testing.T) {
			db, r, path := undecidedDelete(t, lost)
			done, err := SetAsideBeforeCreate(context.Background(), db, r.dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			if len(done.Moved) != 1 || !done.Moved[0].Kept || len(setAsideCopies(t, path, keptInfix)) != 1 ||
				len(setAsideCopies(t, path, supersededInfix)) != 0 {
				t.Fatalf("moved %+v; kept %v; superseded %v", done.Moved, setAsideCopies(t, path, keptInfix), setAsideCopies(t, path, supersededInfix))
			}
			if b, _ := os.ReadFile(done.Moved[0].To); string(b) != "the real disk" {
				t.Fatalf("the .kept- file holds %q", b)
			}
			if strandedOpen(t, db) {
				t.Fatal("the record is still open")
			}
		})
	}
}

// A note whose paths are not in clean form still matches the path a create
// clears, and is forgotten once that disk is moved.
//
// Mutation: compare the note's paths as written — the note keeps the entry.
func TestSetAsideBeforeCreate_MatchesANotedPathInAnyForm(t *testing.T) {
	db, _, _, dataDir, path := strandedFixture(t)
	ctx := context.Background()
	if err := writeKeptDisks(dataDir, "web", keptDisksNote{Paths: []string{filepath.Dir(path) + "//./" + filepath.Base(path)}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	done, err := SetAsideBeforeCreate(ctx, db, dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
	if err != nil || len(done.Moved) != 1 || !done.Moved[0].Kept {
		t.Fatalf("moved %+v, %v; want the noted disk kept", done.Moved, err)
	}
	if noted, err := keptDisksOf(dataDir, "web"); err != nil || len(noted) != 0 {
		t.Fatalf("the note still lists %v (%v) once the disk was moved", noted, err)
	}
}

// A file a kept disk backs on (noted with NoteKeptBackingFiles) refuses a
// create that clears its path, naming it, with nothing moved: moving it
// breaks the kept chain, and the sweep would remove it. The note lists it as
// a kept disk too, for a build that does not know Under, and forgetting it
// drops it from both.
//
// Mutation: drop the Under refusal in SetAsideBeforeCreate: the file is
// moved to a .kept- name, red.
func TestSetAsideBeforeCreate_RefusesOverAFileAKeptDiskBacksOn(t *testing.T) {
	db, _, _, dataDir, path := strandedFixture(t)
	ctx := context.Background()
	if err := NoteKeptBackingFiles(dataDir, "web", []string{path}); err != nil {
		t.Fatal(err)
	}
	if noted, err := keptDisksOf(dataDir, "web"); err != nil || len(noted) != 1 || noted[0] != path {
		t.Fatalf("the note lists %v (%v); want %s as a kept disk too", noted, err, path)
	}
	if err := corrosion.DeleteVM(ctx, db, "web"); err != nil {
		t.Fatal(err)
	}
	done, err := SetAsideBeforeCreate(ctx, db, dataDir, "node-a", "web", []string{path}, samePath, trustedReplica, time.Now())
	if err == nil || !strings.Contains(err.Error(), path) || !strings.Contains(err.Error(), "backs on") || len(done.Moved) != 0 {
		t.Fatalf("SetAsideBeforeCreate = %+v, %v; want a refusal naming %s, nothing moved", done, err, path)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "the real disk" {
		t.Fatalf("the file a kept disk backs on was touched: %q, %v", b, err)
	}
	if err := forgetKeptDisks(dataDir, "web", []string{path}); err != nil {
		t.Fatal(err)
	}
	if n, err := keptNoteOf(dataDir, "web"); err != nil || len(n.Paths)+len(n.Under) != 0 {
		t.Fatalf("the note after forgetting %s = %+v, %v; want none", path, n, err)
	}
}
