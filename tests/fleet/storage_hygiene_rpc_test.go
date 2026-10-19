// Fleet scenarios: lv pit-overlays and lv replication checkpoints, entered on
// a node that does not hold the VM.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// setAsideFleet is two nodes on one database: VM web on node-1, its disk a
// file with a window token, and two set-aside overlays beside it — one of the
// disk's current window, one of an older one.
func setAsideFleet(t *testing.T) (c *Cluster, current, older string) {
	t.Helper()
	c = New(t, Options{Nodes: 2, SharedCRDT: true})
	owner := c.Nodes[1]
	disk := filepath.Join(t.TempDir(), "web-root.qcow2")
	if err := os.WriteFile(disk, []byte("disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(disk, "user.litevirt.pit_window", []byte("tok-now"), 0); err != nil {
		t.Skipf("no user xattrs here: %v", err)
	}
	if err := corrosion.InsertVM(context.Background(), owner.DB, corrosion.VMRecord{Name: "web", HostName: owner.Name, State: "stopped", Spec: `{"name":"web"}`}, nil,
		[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: owner.Name, StorageType: "local", Path: disk}}); err != nil {
		t.Fatal(err)
	}
	mk := func(token, stamp string) string {
		if err := os.WriteFile(pitoverlay.Path(disk), []byte("overlay-"+token), 0o600); err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(pitoverlay.Binding{State: pitoverlay.StateWindow, Token: token})
		if err := os.WriteFile(pitoverlay.SidecarPath(disk), b, 0o600); err != nil {
			t.Fatal(err)
		}
		to, err := pitoverlay.SetAside(disk, stamp)
		if err != nil {
			t.Fatal(err)
		}
		return to
	}
	return c, mk("tok-now", "20261018-120000"), mk("tok-old", "20261017-120000")
}

// lv pit-overlays ls --vm web and rm, entered on node-0: both are answered on
// node-1, web's host. The older overlay is removed; the current window's
// evidence is refused.
//
// Mutation "rm not forwarded" (RemoveSetAsideOverlay acts on the entry's
// host): node-0 finds no disk of web there and refuses with NotFound; red.
func TestFleet_PITOverlaysForwardedToTheVMsHost(t *testing.T) {
	c, current, older := setAsideFleet(t)
	ctx := context.Background()
	entry, owner := c.Nodes[0], c.Nodes[1]
	resp, err := c.SelfClient(entry).ListSetAsideOverlays(ctx, &pb.ListSetAsideOverlaysRequest{VmName: "web"})
	if err != nil {
		t.Fatalf("ListSetAsideOverlays through %s: %v", entry.Name, err)
	}
	if resp.GetHost() != owner.Name || len(resp.GetOverlays()) != 2 {
		t.Fatalf("answered by %s with %d overlays, want %s with 2", resp.GetHost(), len(resp.GetOverlays()), owner.Name)
	}
	rm := func(name string) error {
		_, err := c.SelfClient(entry).RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{VmName: "web", DiskName: "root", Name: filepath.Base(name)})
		return err
	}
	if err := rm(current); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("remove of the current window's evidence = %v, want FailedPrecondition", err)
	}
	if err := rm(older); err != nil {
		t.Fatalf("remove of the older overlay: %v", err)
	}
	if _, err := os.Lstat(older); !os.IsNotExist(err) {
		t.Error("the older overlay is still there")
	}
	if _, err := os.Lstat(current); err != nil {
		t.Errorf("the evidence is gone: %v", err)
	}
}

// Rolling upgrade: a VM's host on an older build has no ListSetAsideOverlays;
// the entry passes its Unimplemented on, which lv explains.
func TestFleet_PITOverlaysOnAnOlderHostIsUnimplemented(t *testing.T) {
	c, _, _ := setAsideFleet(t)
	defer c.Nodes[1].DoNotImplement("ListSetAsideOverlays")()
	_, err := c.SelfClient(c.Nodes[0]).ListSetAsideOverlays(context.Background(), &pb.ListSetAsideOverlaysRequest{VmName: "web"})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("list against an older host = %v, want Unimplemented", err)
	}
}

// lv replication checkpoints rm entered on node-2 retires the row on every
// replica; a row a live schedule uses is refused.
func TestFleet_ReplicationCheckpointRmReplicates(t *testing.T) {
	c, _, _ := replicaFleet(t)
	ctx := context.Background()
	entry := c.Nodes[2]
	if _, err := c.SelfClient(entry).DeleteReplicationCheckpoint(ctx, &pb.DeleteReplicationCheckpointRequest{VmName: "web", TargetPool: "dr"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rm of a row web's live schedule uses = %v, want FailedPrecondition", err)
	}
	if _, err := c.SelfClient(entry).DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{VmName: "web", TargetPool: "dr", Scope: "vm"}); err != nil {
		t.Fatal(err)
	}
	// The schedule removal retired dr; the cluster schedule's dr2 is in use.
	if _, err := c.SelfClient(entry).DeleteReplicationCheckpoint(ctx, &pb.DeleteReplicationCheckpointRequest{VmName: "web", TargetPool: "dr2"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("rm of the cluster schedule's row = %v, want FailedPrecondition", err)
	}
	if _, err := c.SelfClient(entry).DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{Scope: "cluster", TargetPool: "dr2"}); err != nil {
		t.Fatal(err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	// A row the schedule removal could not retire (an older build's): put it back, then rm it.
	if err := corrosion.SetReplicationCheckpoint(ctx, entry.DB, "web", "dr2", "lvrepl-root-20261018-010000"); err != nil {
		t.Fatal(err)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	resp, err := c.SelfClient(entry).DeleteReplicationCheckpoint(ctx, &pb.DeleteReplicationCheckpointRequest{VmName: "web", TargetPool: "dr2"})
	if err != nil {
		t.Fatalf("rm of an unused row: %v", err)
	}
	// m-7: carried out on web's host, which says what became of the bitmap.
	if resp.GetHost() != c.Nodes[0].Name || resp.GetBitmap() == "" || resp.GetBitmap() == "none" {
		t.Errorf("answered by %q with bitmap %q, want web's host %s and the bitmap's fate", resp.GetHost(), resp.GetBitmap(), c.Nodes[0].Name)
	}
	waitHistoryApplied(t, c, 30*time.Second)
	for _, n := range c.Nodes {
		if got := liveCheckpoints(t, n, "web"); len(got) != 0 {
			t.Errorf("live checkpoint rows of web on %s = %v, want none", n.Name, got)
		}
	}
}

// adminUserToken creates user on src with the admin role, loads a real auth
// engine on every node, and returns the user's token.
func adminUserToken(t *testing.T, c *Cluster, src *Node, user string) string {
	t.Helper()
	ctx := context.Background()
	admin := c.SelfClient(src)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: user, Password: user + "-password-0123456789", Role: "admin"}); err != nil {
		t.Fatal(err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: user, Name: user})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		e := auth.NewEngine(n.DB)
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		n.Server.SetAuthEngine(e)
	}
	return tok.Token
}

// detachedOrphan places a set-aside overlay, with a binding naming VM gone, in
// n's <data_dir>/disks beside a disk path no VM has.
func detachedOrphan(t *testing.T, c *Cluster, n *Node) string {
	t.Helper()
	dir := filepath.Join(c.tmpRoot, n.Name, "data", "disks")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	disk := filepath.Join(dir, "gone-root.qcow2") // deleted with its VM
	o := pitoverlay.Path(disk) + ".orphan-20261001-000000"
	if err := os.WriteFile(o, []byte("old window"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(pitoverlay.Binding{Owner: pitoverlay.Owner{VM: "gone", VMUUID: "u-gone", Disk: "root"}, State: pitoverlay.StateWindow, Token: "t"})
	if err := os.WriteFile(o+".id", b, 0o600); err != nil {
		t.Fatal(err)
	}
	return o
}

// I-1. lv pit-overlays ls --host node-1, entered on node-0 by a user scoped
// to another project: node-1 answers the forward as the peer, so the entry
// filters by the user's own read. The user sees none of web's overlays and
// no detached one; an admin sees all three.
//
// Mutation "no entry filter" (ListSetAsideOverlays returns the forwarded
// answer as it is): the scoped user sees all three; red.
func TestFleet_PITOverlaysHostListingIsFilteredByTheCaller(t *testing.T) {
	c, _, _ := setAsideFleet(t)
	entry, owner := c.Nodes[0], c.Nodes[1]
	detachedOrphan(t, c, owner)
	ctx := context.Background()
	scoped := scopedOperatorToken(t, c, entry, "carol", "other")
	resp, err := c.bearerClient(entry, scoped).ListSetAsideOverlays(ctx, &pb.ListSetAsideOverlaysRequest{Host: owner.Name})
	if err != nil {
		t.Fatalf("scoped listing: %v", err)
	}
	if n := len(resp.GetOverlays()); n != 0 {
		t.Errorf("a user scoped to project other sees %d overlays of %s: %+v", n, owner.Name, resp.GetOverlays())
	}
	all, err := c.SelfClient(entry).ListSetAsideOverlays(ctx, &pb.ListSetAsideOverlaysRequest{Host: owner.Name})
	if err != nil {
		t.Fatal(err)
	}
	detached := 0
	for _, o := range all.GetOverlays() {
		if o.GetDetached() {
			detached++
			if o.GetVmName() != "gone" || o.GetOwnerVmUuid() != "u-gone" || o.GetInUse() != "" {
				t.Errorf("detached overlay %+v: want owner gone/u-gone, removable", o)
			}
		}
	}
	if len(all.GetOverlays()) != 3 || detached != 1 {
		t.Errorf("an admin sees %d overlays (%d detached), want 3 (1)", len(all.GetOverlays()), detached)
	}
}

// I-2 and m-1. A detached overlay is removed by host and path through
// another node; the audit row on the host that removed it names the operator
// who ran it, not the forwarding peer.
//
// Mutation "actor not carried" (the forward drops repairActorMDKey): the row
// names admin; red.
func TestFleet_DetachedPITOverlayRemovedAndAuditedAsTheOperator(t *testing.T) {
	c, _, _ := setAsideFleet(t)
	entry, owner := c.Nodes[0], c.Nodes[1]
	o := detachedOrphan(t, c, owner)
	tok := adminUserToken(t, c, entry, "alice")
	ctx := context.Background()
	if _, err := c.bearerClient(entry, tok).RemoveSetAsideOverlay(ctx, &pb.RemoveSetAsideOverlayRequest{Host: owner.Name, Path: o}); err != nil {
		t.Fatalf("remove by path through %s: %v", entry.Name, err)
	}
	if _, err := os.Lstat(o); !os.IsNotExist(err) {
		t.Error("the detached overlay is still there")
	}
	if _, err := os.Lstat(o + ".id"); !os.IsNotExist(err) {
		t.Error("its binding is still there")
	}
	rows, err := owner.DB.Query(ctx, `SELECT username FROM audit_log WHERE action = 'pit.overlay.remove' AND result = 'ok'`)
	if err != nil || len(rows) != 1 || rows[0].String("username") != "alice" {
		t.Fatalf("audit rows %v (%v), want one by alice", rows, err)
	}
}
