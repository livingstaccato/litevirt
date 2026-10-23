package fleet

import (
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

// rc4 lab 2, drill 5: the disks a stale-record delete kept while a peer was
// silent stayed, with disk_leftover, until someone deleted the files and the
// records by hand. `lv host kept-disks <host> --release <vm>`, asked on
// another node, is answered on the host that holds them: refused while the
// deleted VM's snapshot record is still taken over the chain, removing
// nothing; once that record is gone, it removes the whole chain (the overlay,
// the base under it, never the image they stand on), its kept-disk note and
// its kept-disks.json entry, writes an audit row there, and disk_leftover
// clears.
//
// Red without the release (the RPC does not exist). Mutations: drop the
// snapshot record refusal: red at the refusal; drop the note removal: red.
func TestFleet_KeptDisksReleaseRemovesTheChainAndClearsDiskLeftover(t *testing.T) {
	ctx := context.Background()
	stageFakeGenisoimage(t)
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	t.Cleanup(c.Stop)
	c.WaitConverged(t, convergeTimeout)
	n, asker, silent := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	importImageOn(t, c, n, "ubuntu")
	cl := c.SelfClient(n)
	rkdCreate(t, cl, n)

	base := rkdRootPath(t, n)
	ov := strings.TrimSuffix(base, ".qcow2") + ".s1"
	appendTo(t, base, "SV'S DATA")
	if err := qcow2.CreateWithBackingFormat(ov, base, "qcow2", 0, nil); err != nil {
		t.Fatalf("overlay: %v", err)
	}
	n.Virt.SetDiskSource("sv", "vda", base)
	if _, err := cl.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "sv", Name: "s1"}); err != nil {
		t.Fatalf("snapshot s1: %v", err)
	}
	if got := rkdRootPath(t, n); got != ov {
		t.Fatalf("sv's root after the snapshot is %s, want %s", got, ov)
	}
	baseInfo, err := qcow2.Info(base)
	if err != nil {
		t.Fatal(err)
	}
	image := baseInfo.BackingFile // the image the base stands on, if it is an overlay of it

	if _, err := cl.StopVM(ctx, &pb.StopVMRequest{Name: "sv", Force: true}); err != nil {
		t.Fatalf("stop sv: %v", err)
	}
	if err := n.Virt.UndefineDomain("sv", true); err != nil {
		t.Fatalf("undefine sv: %v", err)
	}
	silent.HookUnary("DeleteVM", func(context.Context, any, grpc.UnaryHandler) (any, error) {
		return nil, status.Error(codes.Unavailable, "injected: the daemon is stopped (SIGSTOP)")
	})
	if _, err := cl.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "sv"}); err != nil {
		t.Fatalf("lv rm sv with a silent peer: %v", err)
	}
	note := filepath.Join(n.Server.DataDir(), "kept-disks", "sv.json")
	registry := filepath.Join(n.Server.DataDir(), "kept-disks.json")
	if _, err := os.Stat(note); err != nil {
		t.Fatalf("no kept-disk note after the stale-record delete: %v", err)
	}
	if b, _ := os.ReadFile(registry); !strings.Contains(string(b), ov) {
		t.Fatalf("kept-disks.json does not name %s after the stale-record delete: %s", ov, b)
	}
	n.Server.JudgeKeptDisksForTest(ctx)
	if row, found, _ := corrosion.GetHealthCondition(ctx, n.DB, "vm_delete", "disk_leftover", "host", n.Name); !found ||
		row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("disk_leftover is not raised on %s for the kept chain (%+v, %v): the test proves nothing", n.Name, row, found)
	}

	ask := c.SelfClient(asker)
	list, err := ask.KeptDisks(ctx, &pb.KeptDisksRequest{Host: n.Name})
	if err != nil {
		t.Fatalf("lv host kept-disks %s: %v", n.Name, err)
	}
	if list.Host != n.Name || len(list.Chains) != 1 || list.Chains[0].VmName != "sv" || len(list.Chains[0].Files) != 2 ||
		list.Chains[0].Files[0].Path != ov || list.Chains[0].Files[1].Path != base || !list.Chains[0].Files[1].Under {
		t.Fatalf("kept-disks on %s = %+v; want sv's chain, %s then %s under it", n.Name, list, ov, base)
	}

	// Refused while the deleted VM's snapshot record is taken over it.
	_, err = ask.KeptDisks(ctx, &pb.KeptDisksRequest{Host: n.Name, Release: "sv"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "snapshot records s1 of VM sv") {
		t.Fatalf("release sv with its snapshot record = %v; want FailedPrecondition naming it", err)
	}
	for _, p := range []string{ov, base, note} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("%s went in a refused release: %v", filepath.Base(p), err)
		}
	}

	if err := corrosion.DeleteSnapshot(ctx, n.DB, "sv", "s1"); err != nil {
		t.Fatalf("drop sv's snapshot record: %v", err)
	}
	resp, err := ask.KeptDisks(ctx, &pb.KeptDisksRequest{Host: n.Name, Release: "sv", ExpectPaths: []string{ov, base}})
	if err != nil {
		t.Fatalf("release sv: %v", err)
	}
	if len(resp.Chains) != 1 || !resp.Chains[0].Released {
		t.Fatalf("release answer = %+v; want sv's chain released", resp)
	}
	for _, p := range []string{ov, base, note} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("%s is still there after the release (%v)", p, err)
		}
	}
	if image != "" {
		if _, err := os.Stat(image); err != nil {
			t.Errorf("the image the chain stood on, %s, went with it: %v", image, err)
		}
	}
	if b, _ := os.ReadFile(registry); strings.Contains(string(b), ov) {
		t.Errorf("kept-disks.json still names %s after the release: %s", ov, b)
	}
	if row, found, _ := corrosion.GetHealthCondition(ctx, n.DB, "vm_delete", "disk_leftover", "host", n.Name); !found ||
		row.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("disk_leftover on %s after the release = %+v (found %v); want resolved", n.Name, row, found)
	}
	rows, err := n.DB.Query(ctx, `SELECT username, detail, result FROM audit_log
		WHERE action = 'host.kept_disks.release' AND host_name = ? AND result = 'ok'`, n.Name)
	if err != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), ov+" (") ||
		!strings.Contains(rows[0].String("detail"), base+" (") || rows[0].String("username") == "" {
		t.Errorf("audit rows on %s = %v, %v; want one ok row by the operator naming %s and %s with their sizes", n.Name, rows, err, ov, base)
	}

	list, err = ask.KeptDisks(ctx, &pb.KeptDisksRequest{Host: n.Name})
	if err != nil || len(list.Chains) != 0 {
		t.Errorf("kept-disks on %s after the release = %+v, %v; want none", n.Name, list, err)
	}
}
