// A pivoted move whose committed disk row reached only some replicas. The
// holder committed the row onto the copy and pushed it to c, then died before
// its push to b landed. The VM was rescheduled to b, whose row still named
// the source: b started it there and wrote it. b was lost, and the VM was
// rescheduled to c, whose row names the copy (the reschedule moves only the
// host). c must not boot the copy, which would drop every write b made.
//
// Multi-node by construction: the hosts' rows disagree because of the order
// their histories were delivered in.
package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// TestFleet_MoveUnresolved_SplitRowHoldsAfterTheSecondReschedule (I7-2).
//
//  1. a records a live move of split's disk onto a copy on a shared nfs pool,
//     commits the row, pivots and writes the copy; its history reaches c only.
//  2. a is proven powered off; split is rescheduled to b, whose row names
//     the source. b starts it there and writes it.
//  3. b's history reaches c: c's row now names b and the copy.
//  4. b is lost and proven powered off; split is rescheduled to c, whose row
//     names c and the copy.
//  5. c's start is refused: the row stays on the copy, nothing is booted,
//     both files keep their writes, the condition stays open.
//  6. On c, `--accept <src>` points the row back at the source, keeping b's
//     writes, and the copy stays on disk.
//
// Mutation: trust a row naming the copy whatever changed hands — c boots
// the copy and closes the condition.
func TestFleet_MoveUnresolved_SplitRowHoldsAfterTheSecondReschedule(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	a, b, cn := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	aData := filepath.Join(c.tmpRoot, a.Name, "data")
	src := sharedDiskVM(t, c, a, "split", a.Name, "running", "")
	hot, warm := filepath.Dir(src), filepath.Join(c.tmpRoot, "warm")
	dst := filepath.Join(warm, "split-root.qcow2")
	if err := os.MkdirAll(warm, 0o755); err != nil {
		t.Fatal(err)
	}
	// Both files are on nfs pools every host defines alike, and mounted.
	for _, n := range c.Nodes {
		for _, h := range c.Nodes {
			for _, p := range []corrosion.StoragePoolRecord{
				{HostName: h.Name, Name: "hot", Driver: "nfs", Source: "nas:/hot", Target: hot},
				{HostName: h.Name, Name: "warm", Driver: "nfs", Source: "nas:/vol", Target: warm},
			} {
				if err := corrosion.UpsertStoragePool(ctx, n.DB, p); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	tab := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		fmt.Sprintf("2 1 0:40 / %s rw,nosuid,nodev,noexec,nosymfollow - nfs4 nas:/hot rw\n", hot) +
		fmt.Sprintf("3 1 0:41 / %s rw,nosuid,nodev,noexec,nosymfollow - nfs4 nas:/vol rw\n", warm)
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) { return []byte(tab), nil }))
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, a, cn)
	vm, err := corrosion.GetVM(ctx, a.DB, "split")
	if err != nil || vm == nil {
		t.Fatalf("read split: %+v %v", vm, err)
	}

	// 1. a's live move: recorded, committed, pivoted; only c hears of it.
	m := health.UnresolvedMove{VM: "split", Disk: "root", TargetDev: "vda", Src: src, SrcType: "nfs", SrcPool: "hot",
		Dst: dst, DstType: "nfs", DstPool: "warm", Live: true, At: "2026-10-18T10:00:00.000000001Z",
		Owner: a.Name, OwnerEpoch: vm.OwnerEpoch}
	if err := health.RecordUnresolvedMove(aData, m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("copy"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, a.DB, "split", "root", a.Name, dst, "nfs", "warm"); err != nil {
		t.Fatal(err)
	}
	m.Pivoted = true
	if err := health.RecordUnresolvedMove(aData, m); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(ctx, a.DB, aData, a.Name, "split"); err != nil {
		t.Fatal(err)
	}
	const aWrites, bWrites = "a's writes after the pivot", "b's writes since the failover"
	if err := os.WriteFile(dst, []byte(aWrites), 0o644); err != nil {
		t.Fatal(err)
	}
	pumpMutations(t, c, a, cn)

	// 2. a is proven powered off; split is rescheduled to b, which starts it
	// on the source its row names and writes it.
	for _, n := range []*Node{b, cn} {
		if err := corrosion.InsertFenceLog(ctx, n.DB, corrosion.FenceLogRecord{ID: "confirm-" + a.Name, HostName: a.Name,
			Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpdateHostState(ctx, n.DB, a.Name, "fenced"); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.RescheduleVMHost(ctx, b.DB, "split", b.Name, "stopped"); err != nil {
		t.Fatalf("reschedule split to %s: %v", b.Name, err)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, b.DB, "split"); len(disks) != 1 || disks[0].Path != src {
		t.Fatalf("split's disk row on %s = %+v, want the source", b.Name, disks)
	}
	if err := b.Virt.DefineDomain(`<domain><name>split</name><devices><disk type='file' device='disk'><source file='` + src +
		`'/><target dev='vda' bus='virtio'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "split"}); err != nil {
		t.Fatalf("failover start of split on %s: %v", b.Name, err)
	}
	if err := os.WriteFile(src, []byte(bWrites), 0o644); err != nil {
		t.Fatal(err)
	}
	modTimes(t, dst, src)

	// 3. b's history reaches c; 4. b is lost, and split is rescheduled to c.
	pumpMutations(t, c, b, cn)
	if err := corrosion.InsertFenceLog(ctx, cn.DB, corrosion.FenceLogRecord{ID: "confirm-" + b.Name, HostName: b.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, cn.DB, b.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RescheduleVMHost(ctx, cn.DB, "split", cn.Name, "stopped"); err != nil {
		t.Fatalf("reschedule split to %s: %v", cn.Name, err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, cn.DB, "split")
	if len(disks) != 1 || disks[0].Path != dst || disks[0].HostName != cn.Name {
		t.Fatalf("split's disk row on %s = %+v, want the copy on %s (the replicas disagree)", cn.Name, disks, cn.Name)
	}
	if !health.MoveConditionCovers(ctx, cn.DB, "split", "root") {
		t.Fatal("a's condition did not reach c")
	}

	// 5. c holds: it does not boot the copy.
	_, err = c.SelfClient(cn).StartVM(ctx, &pb.StartVMRequest{Name: "split"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--accept "+src) ||
		!strings.Contains(err.Error(), "--accept "+dst) {
		t.Fatalf("start of split on %s: %v; want it held naming both exits", cn.Name, err)
	}
	if st, _ := cn.Virt.DomainState("split"); st == "running" {
		t.Fatalf("split runs on %s", cn.Name)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, cn.DB, "split"); len(disks) != 1 || disks[0].Path != dst {
		t.Fatalf("split's disk row on %s = %+v, want it left as it was", cn.Name, disks)
	}
	if !health.MoveConditionCovers(ctx, cn.DB, "split", "root") {
		t.Fatal("the condition was closed")
	}
	for p, w := range map[string]string{src: bWrites, dst: aWrites} {
		if got, err := os.ReadFile(p); err != nil || string(got) != w {
			t.Fatalf("%s = %q %v, want %q", p, got, err, w)
		}
	}

	// 6. c keeps b's writes.
	accept := metadata.AppendToOutgoingContext(ctx, grpcapi.MoveAcceptMDKey, src)
	if _, err := c.SelfClient(cn).ResolveHealthCondition(accept, &pb.ResolveHealthConditionRequest{
		Code: health.MoveUnresolvedCode, SubjectKind: "vm", SubjectId: "split", Reason: "b ran it on the source",
	}); err != nil {
		t.Fatalf("lv health resolve --accept %s on %s: %v", src, cn.Name, err)
	}
	if health.MoveConditionCovers(ctx, cn.DB, "split", "root") {
		t.Fatal("the condition is still open")
	}
	if disks, _ := corrosion.GetVMDisks(ctx, cn.DB, "split"); len(disks) != 1 || disks[0].Path != src {
		t.Fatalf("split's disk row on %s = %+v, want the source", cn.Name, disks)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != aWrites {
		t.Fatalf("the copy = %q %v, want it kept", got, err)
	}
}
