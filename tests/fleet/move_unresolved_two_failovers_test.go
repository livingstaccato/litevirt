// A forked move history carried through a second failover. The holder pivoted
// the guest onto the copy with replication cut and was lost; the VM failed
// over to b, which started it on the source and wrote it; the move's condition
// reached b late; then b was lost too, and the VM failed over to c. c has no
// domain of the VM, so a start there would rebuild it from the disk row: it
// must not point that row at the copy by itself, which would drop every write
// b made.
//
// Multi-node by construction: three hosts' histories, delivered late and
// steered, and the start marker is b's own.
package fleet

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// TestFleet_MoveUnresolved_SecondFailoverHoldsAForkedHistory (I6-1).
//
//  1. a records a live move of fork's disk onto a copy on a shared nfs pool,
//     commits the row, pivots and writes the copy; nothing reaches b or c.
//  2. a is proven powered off; fork fails over to b (one change of hands),
//     which starts it on the source and writes it.
//  3. a's condition reaches b late. b's domain is then lost; with the copy
//     made the later file, only b's record of its own start holds b's next
//     start back.
//  4. b is lost; fork fails over to c, either by a transfer (a second change
//     of hands) or by a reschedule that mints no generation (so it is one
//     generation on from the move, and only the files' times show b wrote the
//     source).
//  5. c, with no domain, refuses the start: the row stays on the source, both
//     files keep their writes, the condition stays open, nothing is audited
//     as an automatic repoint.
//  6. On c, `--accept <src>` keeps b's writes with no domain defined.
//
// Mutations: drop the start record from the heal — step 3 boots the copy;
// drop the modification-time check — the reschedule case boots the copy;
// drop the whole check — both cases do.
func TestFleet_MoveUnresolved_SecondFailoverHoldsAForkedHistory(t *testing.T) {
	for _, tc := range []struct {
		name       string
		reschedule bool
	}{
		{name: "transfer to c"},
		{name: "reschedule to c with no new generation", reschedule: true},
	} {
		t.Run(tc.name, func(t *testing.T) { secondFailover(t, tc.reschedule) })
	}
}

func secondFailover(t *testing.T, reschedule bool) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3})
	a, b, cn := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	aData := filepath.Join(c.tmpRoot, a.Name, "data")
	src := sharedDiskVM(t, c, a, "fork", a.Name, "running", "")
	dst := filepath.Join(filepath.Dir(src), "warm", "fork-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatal(err)
	}
	// The copy's pool is the same nfs export at the same directory on every
	// host, and it is mounted.
	for _, n := range c.Nodes {
		for _, h := range c.Nodes {
			if err := corrosion.UpsertStoragePool(ctx, n.DB, corrosion.StoragePoolRecord{HostName: h.Name, Name: "warm",
				Driver: "nfs", Source: "nas:/vol", Target: filepath.Dir(dst)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	tab := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		fmt.Sprintf("2 1 0:40 / %s rw,nosuid,nodev,noexec,nosymfollow - nfs4 nas:/vol rw\n", filepath.Dir(dst))
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) { return []byte(tab), nil }))
	pumpMutations(t, c, a, b)
	pumpMutations(t, c, a, cn)
	vm, err := corrosion.GetVM(ctx, a.DB, "fork")
	if err != nil || vm == nil {
		t.Fatalf("read fork: %+v %v", vm, err)
	}

	// 1. a's live move: recorded, committed, pivoted. Nothing leaves a.
	m := health.UnresolvedMove{VM: "fork", Disk: "root", TargetDev: "vda", Src: src, SrcType: "nfs",
		Dst: dst, DstType: "nfs", DstPool: "warm", Live: true, At: "2026-10-18T10:00:00.000000001Z",
		Owner: a.Name, OwnerEpoch: vm.OwnerEpoch}
	if err := health.RecordUnresolvedMove(aData, m); err != nil {
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

	// 2. a is proven powered off; fork fails over to b, which starts it on
	// the source and writes it.
	for _, n := range []*Node{b, cn} {
		if err := corrosion.InsertFenceLog(ctx, n.DB, corrosion.FenceLogRecord{ID: "confirm-" + a.Name, HostName: a.Name,
			Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpdateHostState(ctx, n.DB, a.Name, "fenced"); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.TransferVMOwnerWithDisks(ctx, b.DB, "fork", b.Name, "stopped", vm.OwnerEpoch); err != nil {
		t.Fatalf("fail fork over to %s: %v", b.Name, err)
	}
	domXML := `<domain><name>fork</name><devices><disk type='file' device='disk'><source file='` + src +
		`'/><target dev='vda' bus='virtio'/></disk></devices></domain>`
	if err := b.Virt.DefineDomain(domXML); err != nil {
		t.Fatal(err)
	}
	if _, err := c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "fork"}); err != nil {
		t.Fatalf("failover start of fork on %s: %v", b.Name, err)
	}
	if err := os.WriteFile(src, []byte(bWrites), 0o644); err != nil {
		t.Fatal(err)
	}
	modTimes(t, dst, src)

	// 3. a's history reaches b late; b's domain is then lost. Even with the
	// copy made the later file, b holds: it started the VM since the move.
	pumpMutations(t, c, a, b)
	if !health.MoveConditionCovers(ctx, b.DB, "fork", "root") {
		t.Fatal("a's condition did not reach b")
	}
	if _, err := c.SelfClient(b).StopVM(ctx, &pb.StopVMRequest{Name: "fork"}); err != nil {
		t.Fatalf("stop fork on %s: %v", b.Name, err)
	}
	if err := b.Virt.UndefineDomain("fork", false); err != nil {
		t.Fatal(err)
	}
	modTimes(t, src, dst)
	_, err = c.SelfClient(b).StartVM(ctx, &pb.StartVMRequest{Name: "fork"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "started the VM") {
		t.Fatalf("start of fork on %s with its domain lost: %v; want it held by its own start", b.Name, err)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, b.DB, "fork"); len(disks) != 1 || disks[0].Path != src {
		t.Fatalf("fork's disk row on %s = %+v, want the source", b.Name, disks)
	}
	modTimes(t, dst, src) // b's writes are the later ones

	// 4. b is lost and proven powered off; fork fails over to c, which
	// followed b, and a's history reaches it late too.
	pumpMutations(t, c, b, cn)
	pumpMutations(t, c, a, cn)
	if err := corrosion.InsertFenceLog(ctx, cn.DB, corrosion.FenceLogRecord{ID: "confirm-" + b.Name, HostName: b.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, cn.DB, b.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	onB, err := corrosion.GetVM(ctx, cn.DB, "fork")
	if err != nil || onB == nil || onB.HostName != b.Name || onB.OwnerEpoch != vm.OwnerEpoch+1 {
		t.Fatalf("fork on %s before the second failover = %+v %v, want %s at generation %d", cn.Name, onB, err, b.Name, vm.OwnerEpoch+1)
	}
	if reschedule {
		err = corrosion.RescheduleVMHost(ctx, cn.DB, "fork", cn.Name, "stopped")
	} else {
		err = corrosion.TransferVMOwnerWithDisks(ctx, cn.DB, "fork", cn.Name, "stopped", onB.OwnerEpoch)
	}
	if err != nil {
		t.Fatalf("fail fork over to %s: %v", cn.Name, err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, cn.DB, "fork")
	if len(disks) != 1 || disks[0].Path != src || disks[0].HostName != cn.Name {
		t.Fatalf("fork's disk row on %s = %+v, want the source on %s", cn.Name, disks, cn.Name)
	}

	// 5. c holds: it does not boot the copy.
	_, err = c.SelfClient(cn).StartVM(ctx, &pb.StartVMRequest{Name: "fork"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--accept "+src) ||
		!strings.Contains(err.Error(), "--accept "+dst) || strings.Contains(err.Error(), "lacks the writes") {
		t.Fatalf("start of fork on %s after the second failover: %v; want the forked-history refusal", cn.Name, err)
	}
	if disks, _ := corrosion.GetVMDisks(ctx, cn.DB, "fork"); len(disks) != 1 || disks[0].Path != src {
		t.Fatalf("fork's disk row on %s = %+v, want the source kept", cn.Name, disks)
	}
	if !health.MoveConditionCovers(ctx, cn.DB, "fork", "root") {
		t.Fatal("the condition was closed")
	}
	if rows, _ := cn.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.auto_repoint'`); len(rows) != 0 {
		t.Fatalf("an automatic repoint was audited: %+v", rows)
	}
	for p, w := range map[string]string{src: bWrites, dst: aWrites} {
		if got, err := os.ReadFile(p); err != nil || string(got) != w {
			t.Fatalf("%s = %q %v, want %q", p, got, err, w)
		}
	}

	// 6. c keeps b's writes with no domain defined.
	accept := metadata.AppendToOutgoingContext(ctx, grpcapi.MoveAcceptMDKey, src)
	if _, err := c.SelfClient(cn).ResolveHealthCondition(accept, &pb.ResolveHealthConditionRequest{
		Code: health.MoveUnresolvedCode, SubjectKind: "vm", SubjectId: "fork", Reason: "b ran it on the source",
	}); err != nil {
		t.Fatalf("lv health resolve --accept %s on %s: %v", src, cn.Name, err)
	}
	if health.MoveConditionCovers(ctx, cn.DB, "fork", "root") {
		t.Fatal("the condition is still open")
	}
	if disks, _ := corrosion.GetVMDisks(ctx, cn.DB, "fork"); len(disks) != 1 || disks[0].Path != src {
		t.Fatalf("fork's disk row on %s = %+v, want the source", cn.Name, disks)
	}
	if _, err := os.Stat(dst); err != nil {
		t.Fatalf("the copy is gone: %v", err)
	}
}

// modTimes gives earlier an older modification time than later.
func modTimes(t *testing.T, earlier, later string) {
	t.Helper()
	e, l := time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
	if err := os.Chtimes(earlier, e, e); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(later, l, l); err != nil {
		t.Fatal(err)
	}
}
