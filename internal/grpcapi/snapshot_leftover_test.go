package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Re-review 3, I-2. A file at the name a snapshot's overlay would get that
// no litevirt merge marked as its leftover is someone else's — an operator's
// `cp vm-root.qcow2 vm-root.orig` before `lv snapshot create vm orig`. It
// survives, and the create is refused, as libvirt refused it on main.
func TestCreateSnapshot_AnOperatorsFileAtTheOverlayNameSurvives(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "op-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "op", "stopped", root, corrosion.DiskRecord{})
	copyOf := filepath.Join(dir, "op-root.orig")
	runQemuImg(t, "create", "-q", "-f", "qcow2", copyOf, "1M")
	before := sumOf(t, copyOf)
	_, err := f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "op", Name: "orig"})
	if err == nil || !strings.Contains(err.Error(), copyOf) {
		t.Errorf("CreateSnapshot = %v; want a refusal naming %s", err, copyOf)
	}
	if _, serr := os.Stat(copyOf); serr != nil || sumOf(t, copyOf) != before {
		t.Fatalf("the operator's file %s was removed or changed (%v)", copyOf, serr)
	}
}

// A symlink at the overlay's name is never followed: its target survives,
// whatever the link is. Unmarked, the create is refused; marked as a
// leftover, only the link itself goes.
func TestCreateSnapshot_ASymlinksTargetIsNeverRemoved(t *testing.T) {
	for _, marked := range []bool{false, true} {
		name := "unmarked"
		if marked {
			name = "marked"
		}
		t.Run(name, func(t *testing.T) {
			needQemuImg(t)
			dir := t.TempDir()
			root := filepath.Join(dir, "sy-root.qcow2")
			runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
			f := newMergeFixture(t, "sy", "stopped", root, corrosion.DiskRecord{})
			backup := filepath.Join(t.TempDir(), "sy-root-2026.qcow2")
			runQemuImg(t, "create", "-q", "-f", "qcow2", backup, "1M")
			link := filepath.Join(dir, "sy-root.bak")
			if err := os.Symlink(backup, link); err != nil {
				t.Fatal(err)
			}
			if marked {
				if err := os.WriteFile(link+".lv-leftover", nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			_, err := f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "sy", Name: "bak"})
			if _, serr := os.Stat(backup); serr != nil {
				t.Fatalf("the symlink's target %s was removed: %v", backup, serr)
			}
			_, lerr := os.Lstat(link)
			if marked {
				if err != nil || !os.IsNotExist(lerr) {
					t.Fatalf("a marked leftover link: create %v, link still there: %v", err, lerr)
				}
			} else if err == nil || lerr != nil {
				t.Fatalf("an unmarked link: create %v (want refused), link %v (want kept)", err, lerr)
			}
		})
	}
}

// A merge that moved the domain off a layer and then failed leaves the
// layer with nothing naming it, and marks it as its leftover — so a later
// snapshot of that name frees it, rather than being refused forever.
func TestDeleteSnapshot_AMergeThatFailsAfterThePivotMarksItsLeftover(t *testing.T) {
	needQemuImg(t)
	dir := t.TempDir()
	root := filepath.Join(dir, "lf-root.qcow2")
	runQemuImg(t, "create", "-q", "-f", "qcow2", root, "1M")
	f := newMergeFixture(t, "lf", "running", root, corrosion.DiskRecord{})
	top := f.snap(t, "s1", true)
	f.fake.FlattenPivotsThenFails = errors.New("block-commit vdb: commit refused")
	f.rm(t, "s1")
	f.fake.FlattenPivotsThenFails = nil
	if _, err := os.Lstat(top + ".lv-leftover"); err != nil {
		t.Fatalf("the layer the failed merge left (%s) is not marked as its leftover: %v", top, err)
	}
	if _, err := f.s.CreateSnapshot(adminCtx(), &pb.CreateSnapshotRequest{VmName: "lf", Name: "s1"}); err != nil {
		t.Fatalf("the name stays blocked by the merge's own leftover: %v", err)
	}
	if _, err := os.Lstat(top + ".lv-leftover"); !os.IsNotExist(err) {
		t.Fatalf("the leftover's marker outlived it: %v", err)
	}
}
