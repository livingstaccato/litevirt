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
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/qcow2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// rkdCluster is a two-node cluster with VM sv created on its first node.
func rkdCluster(t *testing.T) (*Node, pb.LiteVirtClient) {
	t.Helper()
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	n := c.Nodes[0]
	importImageOn(t, c, n, "ubuntu")
	cl := c.SelfClient(n)
	rkdCreate(t, cl, n)
	return n, cl
}

func rkdCreate(t *testing.T, cl pb.LiteVirtClient, n *Node) {
	t.Helper()
	if _, err := cl.CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}}); err != nil {
		t.Fatalf("create sv: %v", err)
	}
}

// rkdRootPath is the path sv's root disk record names.
func rkdRootPath(t *testing.T, n *Node) string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), n.DB, "sv")
	if err != nil || len(disks) != 1 {
		t.Fatalf("sv's disks = %+v, %v", disks, err)
	}
	return disks[0].Path
}

// rkdRealOverlay lays sv's root disk out as libvirt's external snapshot s1
// does: the record names the overlay <stem>.s1, a real qcow2 whose backing
// file is the base <stem>.qcow2. It returns base and overlay.
func rkdRealOverlay(t *testing.T, n *Node, cl pb.LiteVirtClient) (string, string) {
	t.Helper()
	base := rkdRootPath(t, n)
	ov := strings.TrimSuffix(base, ".qcow2") + ".s1"
	appendTo(t, base, "OLD-BASE-DATA")
	if err := qcow2.CreateWithBackingFormat(ov, base, "qcow2", 0, nil); err != nil {
		t.Fatalf("overlay: %v", err)
	}
	n.Virt.SetDiskSource("sv", "vda", base)
	if _, err := cl.CreateSnapshot(context.Background(), &pb.CreateSnapshotRequest{VmName: "sv", Name: "s1"}); err != nil {
		t.Fatalf("snapshot s1: %v", err)
	}
	if got := rkdRootPath(t, n); got != ov {
		t.Fatalf("sv's root disk after the snapshot is recorded at %s, want the overlay %s", got, ov)
	}
	return base, ov
}

// rkdUntouched fails unless each file holds what it held, sv's record and
// domain are still there, and libvirt was asked to stop or undefine nothing
// of sv since from.
func rkdUntouched(t *testing.T, n *Node, files map[string][]byte, state string, from int) {
	t.Helper()
	for p, b := range files {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, b) {
			t.Errorf("%s changed or went (err=%v)", p, err)
		}
	}
	vm, err := corrosion.GetVM(context.Background(), n.DB, "sv")
	if err != nil || vm == nil || vm.State != state {
		t.Errorf("sv's record after the refusal = %+v, %v; want it kept, %s", vm, err, state)
	}
	if !n.Virt.DomainExists("sv") {
		t.Error("sv's domain went")
	}
	for op := range qfsOps(n, "sv", from) {
		if op == "destroy" || op == "undefine" || op == "shutdown" {
			t.Errorf("libvirt %s of sv during a refused delete", op)
		}
	}
}

func rkdRefused(t *testing.T, err error, want string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		t.Fatalf("lv rm --keep-disks sv = %v; want FailedPrecondition naming %q", err, want)
	}
}

// `lv rm --keep-disks` of a VM with a snapshot is refused before anything is
// done (review C1, I1 of a83ed7d27). Kept, the disk is a chain whose base
// sits at <vm>-root.qcow2, which a later create of the name writes its own
// root disk over; and the snapshot's record, firmware bundle and memory image
// stay keyed by the name, so that later VM lists s1 and its `lv snapshot rm`
// or `lv rm` removes them. The refusal names `lv snapshot rm`; the guest,
// the record, the domain, both disk files, the snapshot's record and its
// firmware bundle are as they were.
//
// Red on a83ed7d27: the delete succeeds. Mutation: drop
// keepDisksSnapshotRefusal from deleteVM (both calls): red.
func TestFleet_RmKeepDisks_VMWithSnapshotsIsRefused(t *testing.T) {
	ctx := context.Background()
	n, cl := rkdCluster(t)
	base, ov := rkdRealOverlay(t, n, cl)
	bundle := lv.SnapshotFirmwareBundlePath(n.Server.DataDir(), "sv", "s1")
	if err := os.MkdirAll(filepath.Dir(bundle), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bundle, []byte("OLD VM FIRMWARE"), 0o600); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(ctx, n.DB, "sv")
	files := map[string][]byte{base: readFileT(t, base), ov: readFileT(t, ov), bundle: readFileT(t, bundle)}
	from := len(n.Virt.EventLog())

	_, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true, Force: true})
	rkdRefused(t, err, "lv snapshot rm sv")
	rkdUntouched(t, n, files, vm.State, from)
	if snaps, err := corrosion.ListSnapshots(ctx, n.DB, "sv"); err != nil || len(snaps) != 1 {
		t.Errorf("sv's snapshot records after the refusal = %+v, %v; want s1", snaps, err)
	}
}

// A disk left an overlay on the VM's own <vm>-<disk>.qcow2 with no snapshot
// record, as a snapshot libvirt deletes as metadata only leaves it, is
// refused the same way: the delete would keep and note only the overlay, and
// a later create of the name would set aside or overwrite the base under it
// (review C1, probe "real overlay then recreate").
//
// Red on a83ed7d27: the delete succeeds. Mutation: drop
// keepDisksChainRefusal: red.
func TestFleet_RmKeepDisks_OverlayOnItsOwnDiskIsRefused(t *testing.T) {
	ctx := context.Background()
	n, cl := rkdCluster(t)
	base, ov := rkdRealOverlay(t, n, cl)
	if _, err := cl.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "sv", SnapshotName: "s1"}); err != nil {
		t.Fatalf("lv snapshot rm sv s1: %v", err)
	}
	if got := rkdRootPath(t, n); got != ov {
		t.Fatalf("sv's root disk is recorded at %s, want the overlay %s still", got, ov)
	}
	vm, _ := corrosion.GetVM(ctx, n.DB, "sv")
	files := map[string][]byte{base: readFileT(t, base), ov: readFileT(t, ov)}
	from := len(n.Virt.EventLog())

	_, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true, Force: true})
	rkdRefused(t, err, "is an overlay on "+base)
	rkdUntouched(t, n, files, vm.State, from)
}

// With its snapshots removed first, `lv rm --keep-disks` goes through and
// keeps the disk and the VM's NVRAM (review m2: the keep-state undefine, not
// the destructive one). A later create of the name sets the kept disk aside
// to a .kept- name, with its bytes, and lists none of the deleted VM's
// snapshots (review probe "snapshot then recreate").
//
// Mutation: the keep-disks delete undefines with UndefineDomain(name, true)
// (UNDEFINE_NVRAM): the NVRAM goes, red.
func TestFleet_RmKeepDisks_AfterItsSnapshotsGoKeepsDiskAndNVRAM(t *testing.T) {
	ctx := context.Background()
	n, cl := rkdCluster(t)
	base := rkdRootPath(t, n)
	appendTo(t, base, "OLD-BASE-DATA")
	if _, err := cl.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "sv", Name: "s1"}); err != nil {
		t.Fatalf("snapshot s1: %v", err)
	}
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("lv rm --keep-disks sv with s1 = %v; want refused", err)
	}
	if _, err := cl.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "sv", SnapshotName: "s1"}); err != nil {
		t.Fatalf("lv snapshot rm sv s1: %v", err)
	}
	if got := rkdRootPath(t, n); got != base {
		t.Fatalf("sv's root disk is recorded at %s, want %s", got, base)
	}
	nvram := n.FW.NvramPath("sv")
	if err := os.MkdirAll(filepath.Dir(nvram), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nvram, []byte("uefi vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	kept := readFileT(t, base)

	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks sv: %v", err)
	}
	if n.Virt.DomainExists("sv") {
		t.Error("sv's domain is still defined")
	}
	if b, err := os.ReadFile(nvram); err != nil || string(b) != "uefi vars" {
		t.Errorf("--keep-disks did not keep sv's NVRAM: %q, %v", b, err)
	}
	if !bytes.Equal(readFileT(t, base), kept) {
		t.Fatal("--keep-disks changed the kept disk")
	}

	// The operator takes the kept firmware state away before the name is
	// used again: a create over kept UEFI vars is refused (cli-reference.md).
	if err := os.Remove(nvram); err != nil {
		t.Fatal(err)
	}
	rkdCreate(t, cl, n)
	m := globT(t, base+".kept-*")
	if len(m) != 1 || !bytes.Equal(readFileT(t, m[0]), kept) {
		t.Errorf("the kept disk after a create of the name: %v; want it at one .kept- name with its bytes", m)
	}
	if snaps, err := corrosion.ListSnapshots(ctx, n.DB, "sv"); err != nil || len(snaps) != 0 {
		t.Errorf("the new sv lists snapshots %+v (%v); want none", snaps, err)
	}
}

// rkdCorruptHeader leaves path a file qemu cannot read as qcow2 while its
// magic still says qcow2: cluster_bits (header offset 20) is out of range.
func rkdCorruptHeader(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteAt([]byte{0, 0, 0, 99}, 20); err != nil {
		t.Fatal(err)
	}
	if _, err := qcow2.Info(path); err == nil {
		t.Fatalf("%s still reads as qcow2 after its header was broken", path)
	}
}

// A plain `lv rm` of a VM whose disk recorded delete_with_vm=false is an
// overlay on the VM's own <vm>-root.qcow2 keeps both files, and a later
// create of the name on the host refuses, naming the base, rather than
// moving it off its path (which breaks the overlay's backing reference) or
// letting its sweep remove it and write the new root disk there
// (re-review 1, P1). Nothing is moved; the overlay still backs on the base,
// byte for byte. Once the operator has moved the kept files away, the create
// goes ahead.
//
// Red on f4b919f9c (and on 4b13deaf1): the create succeeds and the base is
// replaced, with no .kept- copy. Mutation: drop the backing-file refusal in
// SetAsideBeforeCreate: red; drop the noting of backing files in
// noteKeptDisks: red.
func TestFleet_PlainRm_KeptChainIsNotTakenByARecreate(t *testing.T) {
	ctx := context.Background()
	n, cl := rkdCluster(t)
	base, ov := rkdRealOverlay(t, n, cl)
	if err := n.DB.Execute(ctx, `UPDATE vm_disks SET delete_with_vm = 0 WHERE vm_name = 'sv'`); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{base: readFileT(t, base), ov: readFileT(t, ov)}
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", Force: true}); err != nil {
		t.Fatalf("lv rm sv: %v", err)
	}

	_, err := cl.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), base) || !strings.Contains(err.Error(), "backs on") {
		t.Fatalf("create of sv over the kept chain = %v; want FailedPrecondition (it stands until the chain is moved) naming %s", err, base)
	}
	for p, b := range files {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, b) {
			t.Errorf("%s changed or went (err=%v)", p, err)
		}
	}
	if info, err := qcow2.Info(ov); err != nil || info.BackingFile != base {
		t.Errorf("the kept overlay's backing file = %+v, %v; want %s", info, err, base)
	}
	if m := globT(t, base+".kept-*"); len(m) != 0 {
		t.Errorf("the base was moved to %v, which leaves the kept overlay backing on nothing", m)
	}

	moved := filepath.Join(filepath.Dir(base), "operator-moved")
	if err := os.MkdirAll(moved, 0o700); err != nil {
		t.Fatal(err)
	}
	for p := range files {
		if err := os.Rename(p, filepath.Join(moved, filepath.Base(p))); err != nil {
			t.Fatal(err)
		}
	}
	rkdCreate(t, cl, n)
}

// The keep is decided from the kept disk's whole backing chain, so a chain
// that cannot be read in full refuses the delete before anything is done,
// naming the file, with --keep-disks and for a disk recorded
// delete_with_vm=false alike:
//   - the overlay's header is broken (it hides the base under it; re-review
//     1, N3);
//   - the base, which the overlay declares qcow2, has lost its qcow2 magic
//     (re-review 2, F2): it used to end the chain as a raw file would;
//   - the base is missing (F4).
//
// Red on f4b919f9c for the first; on dc4cad50d for the second.
// Mutations: end the walk at an unreadable header, at a declared-qcow2 file
// without the magic, or at a missing backing file: red.
func TestFleet_RmKeepDisks_UnreadableChainIsRefused(t *testing.T) {
	type breakage struct {
		name  string
		apply func(t *testing.T, base, ov string) string // returns the file the refusal names
	}
	breaks := []breakage{
		{"overlay header", func(t *testing.T, base, ov string) string { rkdCorruptHeader(t, ov); return ov }},
		{"base magic", func(t *testing.T, base, ov string) string {
			f, err := os.OpenFile(base, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.WriteAt([]byte{0, 0, 0, 0}, 0); err != nil {
				t.Fatal(err)
			}
			return base
		}},
		{"base missing", func(t *testing.T, base, ov string) string {
			if err := os.Rename(base, base+".elsewhere"); err != nil {
				t.Fatal(err)
			}
			return base
		}},
	}
	for _, keep := range []bool{true, false} {
		for _, br := range breaks {
			name := "keep-disks/" + br.name
			if !keep {
				name = "delete_with_vm=false/" + br.name
			}
			t.Run(name, func(t *testing.T) {
				ctx := context.Background()
				n, cl := rkdCluster(t)
				base, ov := rkdRealOverlay(t, n, cl)
				if _, err := cl.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "sv", SnapshotName: "s1"}); err != nil {
					t.Fatalf("lv snapshot rm sv s1: %v", err)
				}
				if !keep {
					if err := n.DB.Execute(ctx, `UPDATE vm_disks SET delete_with_vm = 0 WHERE vm_name = 'sv'`); err != nil {
						t.Fatal(err)
					}
				}
				named := br.apply(t, base, ov)
				vm, _ := corrosion.GetVM(ctx, n.DB, "sv")
				files := map[string][]byte{ov: readFileT(t, ov)}
				if present(base) {
					files[base] = readFileT(t, base)
				}
				from := len(n.Virt.EventLog())

				_, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: keep, Force: true})
				rkdRefused(t, err, named)
				if !strings.Contains(err.Error(), "cannot be read") {
					t.Fatalf("lv rm sv = %v; want the refusal for a chain that cannot be read", err)
				}
				rkdUntouched(t, n, files, vm.State, from)
			})
		}
	}
}

// A raw base under a qcow2 overlay that declares it raw ends the chain
// without a refusal, and is noted: a plain `lv rm` of a VM whose disk
// recorded delete_with_vm=false is that overlay goes through, and a create
// of the name then refuses over the base rather than taking it (re-review 2,
// probe RawBaseIsNoted).
//
// Mutation: keptChainLayers leaves a file without the qcow2 magic out of the
// chain: red.
func TestFleet_PlainRm_RawBaseUnderAKeptOverlayIsNoted(t *testing.T) {
	ctx := context.Background()
	n, cl := rkdCluster(t)
	base := rkdRootPath(t, n)
	ov := strings.TrimSuffix(base, ".qcow2") + ".s1"
	if err := os.WriteFile(base, []byte("RAW-BASE-DATA-NO-MAGIC"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBackingFormat(ov, base, "raw", 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	if err := n.DB.Execute(ctx, `UPDATE vm_disks SET path = ?, delete_with_vm = 0 WHERE vm_name = 'sv'`, ov); err != nil {
		t.Fatal(err)
	}
	b0 := readFileT(t, base)
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", Force: true}); err != nil {
		t.Fatalf("lv rm sv: %v", err)
	}
	_, err := cl.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}})
	if err == nil || !strings.Contains(err.Error(), base) {
		t.Fatalf("create of sv over the kept raw base = %v; want a refusal naming %s", err, base)
	}
	if got, _ := os.ReadFile(base); !bytes.Equal(got, b0) {
		t.Errorf("the raw base %s was replaced or removed", base)
	}
}

// A plain `lv rm` tombstones the VM's snapshot records once their files on
// this host are gone, so a later VM of the name lists none of them and its
// `lv rm --keep-disks` is not refused for them (re-review 1, N1).
//
// Red on dc4cad50d: s1 is still listed, and the keep-disks delete of the new
// VM is refused. Mutation: drop the tombstoning: red.
func TestFleet_PlainRm_TombstonesItsSnapshotRecords(t *testing.T) {
	ctx := context.Background()
	n, cl := rkdCluster(t)
	if _, err := cl.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "sv", Name: "s1"}); err != nil {
		t.Fatalf("snapshot s1: %v", err)
	}
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", Force: true}); err != nil {
		t.Fatalf("lv rm sv: %v", err)
	}
	if snaps, err := corrosion.ListSnapshots(ctx, n.DB, "sv"); err != nil || len(snaps) != 0 {
		t.Fatalf("snapshot records after lv rm sv = %+v, %v; want none", snaps, err)
	}
	rkdCreate(t, cl, n)
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv", KeepDisks: true}); err != nil {
		t.Fatalf("lv rm --keep-disks of the new sv, which has no snapshots: %v", err)
	}
}
