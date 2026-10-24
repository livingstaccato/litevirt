package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// klcFixture is rc7 lab 1 drill 7c up to the keep: VM sv on the first node
// of a two-node cluster, a linked clone svc of it, and `lv rm --keep-disks
// svc`, which notes only the clone's overlay (kept-disks/svc.json) and
// records nothing in kept-disks.json. It returns the source's disk (the
// overlay's base, holding data only it has), the overlay, and the base's
// bytes.
func klcFixture(t *testing.T) (*Node, pb.LiteVirtClient, string, string, []byte) {
	t.Helper()
	ctx := context.Background()
	n, cl := rkdCluster(t)
	base := rkdRootPath(t, n)
	appendTo(t, base, "THE ONLY COPY OF SV'S DATA")
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "sv", Force: true}); err != nil {
		t.Fatalf("lv stop sv: %v", err)
	}
	if _, err := cl.CloneVM(ctx, &pb.CloneVMRequest{Source: "sv", Target: "svc", Mode: "linked"}); err != nil {
		t.Fatalf("lv clone sv svc --mode linked: %v", err)
	}
	disks, err := corrosion.GetVMDisks(ctx, n.DB, "svc")
	if err != nil || len(disks) != 1 {
		t.Fatalf("svc's disks = %+v, %v", disks, err)
	}
	overlay := disks[0].Path
	if info, err := qcow2.Info(overlay); err != nil || info.BackingFile != base {
		t.Fatalf("svc's disk %s is not an overlay on %s: %+v, %v", overlay, base, info, err)
	}
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "svc", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks svc: %v", err)
	}
	note := filepath.Join(n.Server.DataDir(), "kept-disks", "svc.json")
	if b, err := os.ReadFile(note); err != nil || !strings.Contains(string(b), overlay) || strings.Contains(string(b), base) {
		t.Fatalf("svc's note %s = %q, %v; want it to name the overlay %s only", note, b, err, overlay)
	}
	if _, err := os.Stat(filepath.Join(n.Server.DataDir(), "kept-disks.json")); !os.IsNotExist(err) {
		t.Fatalf("kept-disks.json is there (stat %v); the drill's keep records nothing in it", err)
	}
	return n, cl, base, overlay, readFileT(t, base)
}

// klcIntact fails unless base still holds was and overlay still backs on it.
func klcIntact(t *testing.T, base, overlay string, was []byte, when string) {
	t.Helper()
	if got, err := os.ReadFile(base); err != nil || !bytes.Equal(got, was) {
		t.Fatalf("%s: the kept overlay's base %s was removed or replaced (err=%v)", when, base, err)
	}
	if info, err := qcow2.Info(overlay); err != nil || info.BackingFile != base {
		t.Fatalf("%s: the kept overlay %s no longer backs on %s: %+v, %v", when, overlay, base, info, err)
	}
}

// rc7 lab 1 F1, the drill sequence: a linked clone is kept with `lv rm
// --keep-disks`, which notes only its overlay. A plain `lv rm` of the source
// then removed the base under the kept overlay, and a same-name `lv run` of
// the source wrote a new, unrelated base under it, with no refusal. Now:
//
//   - the plain `lv rm` of the source is refused before anything is done,
//     naming the kept overlay, and the source, its domain and the base stay;
//   - a rebuild of the source is refused the same way;
//   - `lv rm --keep-disks` of the source, which the refusal offers, goes
//     through and keeps the base;
//   - `lv run` of the source then is refused: the base is held by the kept
//     overlay's chain, and is neither swept nor moved aside to a .kept- name
//     (which would break the overlay as surely as removing it).
//
// Red on 3720ac768 and on a63cd2835: the plain `lv rm` succeeds and removes
// the base. Mutations: drop the keptBaseRefusal call from deleteVM: the late
// hold leaves the base but the delete runs (the domain goes), red; drop it
// from RebuildVM: red; let the create guard leave a file the source's own
// note lists to SetAsideBeforeCreate whoever's chain holds it (the old
// `notesGovern && noted[f] != ""` skip): the base is moved to a .kept- name,
// red.
func TestFleet_KeptLinkedClone_SourceRmAndRunKeepTheBase(t *testing.T) {
	ctx := context.Background()
	n, cl, base, overlay, was := klcFixture(t)

	_, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), overlay) {
		t.Fatalf("plain lv rm sv = %v; want FailedPrecondition naming the kept overlay %s", err, overlay)
	}
	klcIntact(t, base, overlay, was, "plain lv rm sv")
	if vm, err := corrosion.GetVM(ctx, n.DB, "sv"); err != nil || vm == nil {
		t.Fatalf("sv's record after the refused delete = %+v, %v; want it kept", vm, err)
	}
	if !n.Virt.DomainExists("sv") {
		t.Fatal("sv's domain went in a refused delete")
	}

	_, err = cl.RebuildVM(ctx, &pb.RebuildVMRequest{Name: "sv"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), overlay) {
		t.Fatalf("lv rebuild sv = %v; want FailedPrecondition naming the kept overlay %s", err, overlay)
	}
	klcIntact(t, base, overlay, was, "lv rebuild sv")

	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks sv: %v", err)
	}
	klcIntact(t, base, overlay, was, "lv rm --keep-disks sv")

	_, err = cl.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}})
	if err == nil || !strings.Contains(err.Error(), overlay) {
		t.Fatalf("lv run sv = %v; want a refusal naming the kept overlay %s", err, overlay)
	}
	klcIntact(t, base, overlay, was, "lv run sv")
	if moved, _ := filepath.Glob(base + ".kept-*"); len(moved) > 0 {
		t.Fatalf("the base was moved aside to %v", moved)
	}
}

// The other half of F1: with the base already gone (removed by an older
// build, or by hand), a create of the source's name would write a new base
// under the kept overlay, which names that path. It is refused with nothing
// written there, though only svc's note, and no kept-disks.json entry,
// records the overlay.
//
// Red on 3720ac768 and on a63cd2835: the create succeeds and writes the base
// path. Mutation: drop the keptNoteMissingBase check from
// keptMissingBaseRefusal: red.
func TestFleet_KeptLinkedClone_RunOverAMissingBaseIsRefused(t *testing.T) {
	ctx := context.Background()
	n, cl, base, overlay, _ := klcFixture(t)
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks sv: %v", err)
	}
	aside := filepath.Join(t.TempDir(), "moved-base.qcow2")
	if err := os.Rename(base, aside); err != nil {
		t.Fatal(err)
	}

	_, err := cl.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}})
	if err == nil || !strings.Contains(err.Error(), overlay) || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("lv run sv over the missing base = %v; want a refusal naming the kept overlay %s and the missing base", err, overlay)
	}
	if _, err := os.Lstat(base); !os.IsNotExist(err) {
		t.Fatalf("a file was written at the kept overlay's missing base %s (lstat %v)", base, err)
	}
}
