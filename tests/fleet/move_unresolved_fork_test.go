// A live volume move whose pivot never reached the rest of the cluster, then
// a failover onto the source: the history forks. The holder pivoted the guest
// onto the copy and wrote it until it was lost; the new owner, which never saw
// the move's condition, started the VM on the source and wrote that. When the
// condition arrives late, the owner can keep its own writes.
//
// Multi-node by construction: the move's record and condition are the
// holder's, the late delivery is replication, and the exit is taken on the
// owner against its own domain.
package fleet

import (
	"context"
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
)

// TestFleet_MoveUnresolved_ForkedHistoryKeepsTheOwnersWrites: holder a pivots
// fork's disk onto the copy with replication to b cut, and is lost; b fails
// the VM over and starts it on the source, writing to it; a's condition then
// arrives. b's start is refused with a text that names `--accept <src>` and
// does not call the source stale; `--accept <src>` on b keeps the source with
// b's writes, keeps the copy on disk and audits the divergence; b starts the
// VM on the source; a, back, drops its record and raises nothing.
//
// Mutation: drop the ownership check from the forked-history exit — the
// "no change of hands" unit case goes red; drop the exit — `--accept src`
// here is refused as stale.
func TestFleet_MoveUnresolved_ForkedHistoryKeepsTheOwnersWrites(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	aData := filepath.Join(c.tmpRoot, a.Name, "data")
	src := sharedDiskVM(t, c, a, "fork", a.Name, "running", "")
	pumpMutations(t, c, a, b)
	vm, err := corrosion.GetVM(ctx, a.DB, "fork")
	if err != nil || vm == nil {
		t.Fatalf("read fork: %+v %v", vm, err)
	}

	// a's live move: recorded, committed, pivoted. Nothing reaches b.
	dst := filepath.Join(filepath.Dir(src), "warm", "fork-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	m := health.UnresolvedMove{VM: "fork", Disk: "root", TargetDev: "vda", Src: src, SrcType: "nfs",
		Dst: dst, DstType: "nfs", DstPool: "warm", Live: true, At: "2026-10-18T10:00:00.000000001Z",
		Owner: a.Name, OwnerEpoch: vm.OwnerEpoch}
	if err := health.RecordUnresolvedMove(aData, m); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(ctx, a.DB, aData, a.Name, "fork"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, a.DB, "fork", "root", a.Name, dst, "nfs", "warm"); err != nil {
		t.Fatal(err)
	}
	m.Pivoted = true
	if err := health.RecordUnresolvedMove(aData, m); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(ctx, a.DB, aData, a.Name, "fork"); err != nil {
		t.Fatal(err)
	}
	const aWrites, bWrites = "a's writes after the pivot", "b's writes since the failover"
	if err := os.WriteFile(dst, []byte(aWrites), 0o644); err != nil {
		t.Fatal(err)
	}

	// a is lost and proven powered off; b fails fork over and starts it on
	// the file its disk row names, the source, and the guest writes it.
	if err := corrosion.InsertFenceLog(ctx, b.DB, corrosion.FenceLogRecord{ID: "confirm-" + a.Name, HostName: a.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, b.DB, a.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.TransferVMOwnerWithDisks(ctx, b.DB, "fork", b.Name, "stopped", vm.OwnerEpoch); err != nil {
		t.Fatalf("fail fork over to %s: %v", b.Name, err)
	}
	if err := b.Virt.DefineDomain(`<domain><name>fork</name><devices><disk type='file' device='disk'><source file='` + src +
		`'/><target dev='vda' bus='virtio'/></disk></devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "fork"}); err != nil {
		t.Fatalf("failover start of fork on %s: %v", b.Name, err)
	}
	if xml := b.Virt.DefinedXML("fork"); !strings.Contains(xml, src) {
		t.Fatalf("%s did not start fork on the source:\n%s", b.Name, xml)
	}
	if err := os.WriteFile(src, []byte(bWrites), 0o644); err != nil {
		t.Fatal(err)
	}

	// a's history reaches b late.
	pumpMutations(t, c, a, b)
	if !health.MoveConditionCovers(ctx, b.DB, "fork", "root") {
		t.Fatal("a's condition did not reach b")
	}
	if disks, _ := corrosion.GetVMDisks(ctx, b.DB, "fork"); len(disks) != 1 || disks[0].Path != src || disks[0].HostName != b.Name {
		t.Fatalf("fork's disk row on b = %+v, want the source on %s", disks, b.Name)
	}

	// b's next start is refused, naming the exit that keeps its writes.
	if _, err := c.SelfClient(b).StopVM(ctx, &pb.StopVMRequest{Name: "fork"}); err != nil {
		t.Fatalf("stop fork on %s: %v", b.Name, err)
	}
	_, err = c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "fork"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--accept "+src) ||
		strings.Contains(err.Error(), "lacks the writes") || strings.Contains(err.Error(), "virsh edit") {
		t.Fatalf("start of fork on %s after the late condition: %v; want a refusal naming --accept %s, "+
			"neither calling the source stale nor steering the config onto the copy", b.Name, err, src)
	}

	// The owner keeps its writes.
	accept := metadata.AppendToOutgoingContext(ctx, grpcapi.MoveAcceptMDKey, src)
	if _, err := c.SelfClient(b).ResolveHealthCondition(accept, &pb.ResolveHealthConditionRequest{
		Code: health.MoveUnresolvedCode, SubjectKind: "vm", SubjectId: "fork", Reason: "ran on the source since the failover",
	}); err != nil {
		t.Fatalf("lv health resolve --accept %s on %s: %v", src, b.Name, err)
	}
	if health.MoveConditionCovers(ctx, b.DB, "fork", "root") {
		t.Fatal("the condition is still open")
	}
	for p, w := range map[string]string{src: bWrites, dst: aWrites} {
		if got, err := os.ReadFile(p); err != nil || string(got) != w {
			t.Fatalf("%s = %q %v, want %q", p, got, err, w)
		}
	}
	rows, err := b.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), dst) {
		t.Fatalf("divergence audit on %s = %+v %v, want one row naming %s", b.Name, rows, err, dst)
	}
	if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "fork"}); err != nil {
		t.Fatalf("start of fork on %s after the resolution: %v", b.Name, err)
	}
	if xml := b.Virt.DefinedXML("fork"); !strings.Contains(xml, src) {
		t.Fatalf("%s did not start fork on the source:\n%s", b.Name, xml)
	}

	// a returns: it drops its record of the move and raises nothing.
	pumpMutations(t, c, b, a)
	if err := health.PublishUnresolvedMoves(ctx, a.DB, aData, a.Name, "fork"); err != nil {
		t.Fatalf("a's publish on return: %v", err)
	}
	if health.MoveConditionCovers(ctx, a.DB, "fork", "root") {
		t.Fatal("a raised the condition again over the resolution")
	}
	if left, _ := health.UnresolvedMovesOf(aData, "fork"); len(left) != 0 {
		t.Fatalf("a kept its record: %+v", left)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("the copy is gone: %v", err)
	}
}
