package fleet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// rc3 lab 2, drill 5 and F1, end to end. VM sv has a disk with two external
// snapshots (base <sv>-root.qcow2, overlays .s1 and .s2, the record naming
// .s2). Its domain is undefined out of band, and a peer does not answer
// whether it runs sv, so `lv rm sv` takes the stale-record path and keeps the
// disks, the RAM image and the snapshot records. A later `lv run sv` on the
// same host used to clear the base the kept overlays back on and write its
// new disk there: the kept .s2 then sat on another guest's disk.
//
// Now the create is refused, naming the base, and every file of the kept
// chain is byte-identical afterwards. The delete writes the kept-disk note
// with the chain (kept-disks/sv.json), and the create's debris sweep refuses
// a file a kept chain backs on even without it.
//
// Red on 7e610a7f7: no note, the create succeeds and the base is replaced.
// Mutations: drop both the stale-record note (noteDeleteKeptDisks) and the
// create guard (keptFileCreateRefusal): red, the base replaced. Drop the note
// alone: red (no note; the guard still refuses). Drop the guard alone: green,
// the note's under refuses the create (the grpcapi tests cover the guard).
func TestFleet_StaleDeleteWithASilentPeerThenSameNameCreateKeepsTheChain(t *testing.T) {
	ctx := context.Background()
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	t.Cleanup(c.Stop)
	c.WaitConverged(t, convergeTimeout)
	n, silent := c.Nodes[0], c.Nodes[2]
	importImageOn(t, c, n, "ubuntu")
	cl := c.SelfClient(n)
	rkdCreate(t, cl, n)

	// The chain: base, s1 on it, s2 on s1, each taken as libvirt's external
	// snapshot takes it (the record follows the new top).
	base := rkdRootPath(t, n)
	stem := strings.TrimSuffix(base, ".qcow2")
	appendTo(t, base, "THE ONLY COPY OF SV'S DATA")
	below := base
	for _, snap := range []string{"s1", "s2"} {
		ov := stem + "." + snap
		if err := qcow2.CreateWithBackingFormat(ov, below, "qcow2", 0, nil); err != nil {
			t.Fatalf("overlay %s: %v", snap, err)
		}
		n.Virt.SetDiskSource("sv", "vda", below)
		if _, err := cl.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "sv", Name: snap}); err != nil {
			t.Fatalf("snapshot %s: %v", snap, err)
		}
		if got := rkdRootPath(t, n); got != ov {
			t.Fatalf("sv's root disk after snapshot %s is recorded at %s, want %s", snap, got, ov)
		}
		below = ov
	}
	chain := []string{base, stem + ".s1", stem + ".s2"}
	was := map[string][]byte{}
	for _, p := range chain {
		was[p] = readFileT(t, p)
	}

	// The stale record: stopped, its domain undefined behind litevirt's back
	// (virsh undefine --snapshots-metadata --nvram).
	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "sv", Force: true}); err != nil {
		t.Fatalf("stop sv: %v", err)
	}
	if err := n.Virt.UndefineDomain("sv", true); err != nil {
		t.Fatalf("undefine sv: %v", err)
	}
	// The silent peer: its delete probe gets no answer.
	silent.HookUnary("DeleteVM", func(context.Context, any, grpc.UnaryHandler) (any, error) {
		return nil, status.Error(codes.Unavailable, "injected: the daemon is stopped (SIGSTOP)")
	})

	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv"}); err != nil {
		t.Fatalf("lv rm sv with a silent peer: %v", err)
	}
	if vm, _ := corrosion.GetVM(ctx, n.DB, "sv"); vm != nil {
		t.Fatal("sv's record survived: the delete did not take the stale-record path")
	}
	for _, p := range chain {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, was[p]) {
			t.Fatalf("%s changed or went in the delete (err=%v)", filepath.Base(p), err)
		}
	}
	if _, err := os.Stat(filepath.Join(n.Server.DataDir(), "kept-disks", "sv.json")); err != nil {
		t.Errorf("no kept-disk note for sv after the stale-record delete: %v", err)
	}

	// The same-name create on the same host.
	_, err := cl.CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "sv", Image: "ubuntu", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name}}})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), base) {
		t.Errorf("lv run sv over the kept chain = %v; want FailedPrecondition naming %s", err, base)
	}
	for _, p := range chain {
		if got, err := os.ReadFile(p); err != nil || !bytes.Equal(got, was[p]) {
			t.Errorf("%s changed or went in the create (err=%v): the kept chain lost its data", filepath.Base(p), err)
		}
	}
	if info, err := qcow2.Info(stem + ".s1"); err != nil || info.BackingFile != base {
		t.Errorf("s1's backing = %+v, %v; want %s", info, err, base)
	}
}
