package fleet

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// heldCluster is two nodes with the daemon's firewall wired, and a guarded VM
// on src whose domain an older release defined (a vnetN tap): a live move
// hands it over paused. The migration fake lands it on dst as libvirt would.
func heldCluster(t *testing.T) (*Cluster, *Node, *Node, map[string]*recordingNft) {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	nfts := map[string]*recordingNft{}
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
		nfts[n.Name] = wireNodeFirewall(t, n)
	}
	guardedVM(t, c, src, "old", "10.30.0.61", "52:54:00:77:06:01")
	if _, err := c.SelfClient(src).StopVM(context.Background(), &pb.StopVMRequest{Name: "old", Force: true}); err != nil {
		t.Fatal(err)
	}
	asOlderDomain(src, "old")
	if _, err := c.SelfClient(src).StartVM(context.Background(), &pb.StartVMRequest{Name: "old"}); err != nil {
		t.Fatalf("StartVM: %v", err)
	}
	src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		x, _ := src.Virt.DumpXML(name)
		if err := dst.Virt.DefineDomain(x); err != nil {
			return err
		}
		if p.Paused {
			dst.Virt.SetState(name, libvirtfake.StatePaused)
		} else {
			dst.Virt.SetState(name, libvirtfake.StateRunning)
			dst.Virt.OnRunning(name)
		}
		return nil
	}
	t.Cleanup(grpcapi.SetHandOverTimingForTests(20*time.Millisecond, 600*time.Millisecond))
	return c, src, dst, nfts
}

func rawState(n *Node, name string) libvirtfake.State {
	st, _ := n.Virt.RawState(name)
	return st
}

// heldCondition is dst's firewall.nic.held condition, if raised.
func heldCondition(t *testing.T, n *Node) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, grpcapi.FirewallEvaluator,
		grpcapi.CondFirewallHeld, "host", n.Name)
	if err != nil {
		t.Fatal(err)
	}
	return row, ok && row.Lifecycle != corrosion.ConditionResolved
}

// TestFleet_NICGuard_HeldHandOverRetried (re-review R3-I2): the source
// retries a paused hand-over's resume when the target fails it once, and the
// guest runs on the target, its guard in force when it did.
func TestFleet_NICGuard_HeldHandOverRetried(t *testing.T) {
	c, src, dst, nfts := heldCluster(t)
	var fails atomic.Int32
	dst.Virt.FailResumeDomain = func(string) error {
		if fails.Add(1) == 1 {
			return errors.New("transient resume failure")
		}
		return nil
	}
	g := watchGuardAtRunning(t, dst, nfts[dst.Name])
	if err := migrateAt(t, c, src, "old", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if st := rawState(dst, "old"); st != libvirtfake.StateRunning {
		t.Fatalf("after a transient resume failure the guest is %s on the target, want running", st)
	}
	if got := g.all("old"); !everyTrue(got) {
		t.Errorf("guard in force when the guest ran on the target: %v", got)
	}
	if held := dst.Server.HeldGuestsForTests(); len(held) != 0 {
		t.Errorf("the target still holds %v", held)
	}
}

// TestFleet_NICGuard_HeldHandOverReported (re-review R3-I2): when the target
// cannot let the guest run, the drain says so instead of reporting a clean
// move, the target raises a critical condition naming the VM and the command,
// and it resumes the guest itself once its guards are in force.
func TestFleet_NICGuard_HeldHandOverReported(t *testing.T) {
	c, src, dst, nfts := heldCluster(t)
	ctx := context.Background()
	setHostCapacity(t, c, src.Name, 64, 65536, nil)
	setHostCapacity(t, c, dst.Name, 64, 65536, nil)
	dst.Virt.FailResumeDomain = func(string) error { return errors.New("qemu would not resume") }

	st, err := c.SelfClient(src).DrainHost(ctx, &pb.DrainHostRequest{Name: src.Name})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	var last *pb.DrainProgress
	for {
		p, rerr := st.Recv()
		if rerr != nil {
			break
		}
		if p.GetVmName() == "old" {
			last = p
		}
	}
	if last == nil || last.GetStatus() != "error" || !strings.Contains(last.GetError(), "held paused on "+dst.Name) {
		t.Fatalf("drain progress for a guest left paused on its target = %+v, want an error naming the hold", last)
	}
	if st := rawState(dst, "old"); st != libvirtfake.StatePaused {
		t.Fatalf("fixture: the guest is %s on the target, want paused", st)
	}

	dst.Server.ResumeHeldGuestsOnce(ctx)
	row, raised := heldCondition(t, dst)
	if !raised || row.Severity != corrosion.SeverityCritical ||
		!strings.Contains(row.Evidence, "old") || !strings.Contains(row.Evidence, "lv firewall nic-guard resume old") {
		t.Fatalf("held condition = %+v (raised %v), want critical, naming the VM and the command", row, raised)
	}

	dst.Virt.FailResumeDomain = nil
	g := watchGuardAtRunning(t, dst, nfts[dst.Name])
	dst.Server.ResumeHeldGuestsOnce(ctx)
	if st := rawState(dst, "old"); st != libvirtfake.StateRunning {
		t.Fatalf("the target did not resume the guest once it could: %s", st)
	}
	if got := g.all("old"); !everyTrue(got) {
		t.Errorf("guard in force when the target resumed the guest: %v", got)
	}
	if _, raised := heldCondition(t, dst); raised {
		t.Error("the held condition outlived the hold")
	}
}

// TestFleet_NICGuard_HeldHandOverSurvivesTargetRestart (re-review R3-I2): the
// target's daemon restarts between the guest arriving paused and the
// source's resume. The source gives up and reports it; the restarted daemon
// knows from its own disk that it holds the guest for its guard, and lets it
// run once the guard is in force.
func TestFleet_NICGuard_HeldHandOverSurvivesTargetRestart(t *testing.T) {
	c, src, dst, _ := heldCluster(t)
	ctx := context.Background()
	// The resume never reaches the target: its daemon is restarting.
	down := func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		if r, ok := req.(*pb.ArmNICFirewallRequest); ok && r.GetResume() {
			return nil, status.Error(codes.Unavailable, "the daemon is restarting")
		}
		return h(ctx, req)
	}
	for i := 0; i < 64; i++ {
		dst.HookUnary("ArmNICFirewall", down)
	}
	err := migrateAt(t, c, src, "old", dst.Name)
	if err == nil || !strings.Contains(err.Error(), "held paused") {
		t.Fatalf("migrate with the target down at hand-over = %v, want an error naming the hold", err)
	}
	if st := rawState(dst, "old"); st != libvirtfake.StatePaused {
		t.Fatalf("fixture: the guest is %s on the target, want paused", st)
	}

	// The restart: a new daemon process on the same host — its disk, its
	// replica and its libvirt survive; nothing in memory does.
	restarted := grpcapi.NewServerForTests(grpcapi.TestServerOpts{
		HostName: dst.Name, DataDir: filepath.Join(c.tmpRoot, dst.Name, "data"), PKIDir: dst.PKIDir, DB: dst.DB, Virt: dst.Virt,
	})
	restarted.SetBridgeEnsure(func(string) error { return nil })
	nft := &recordingNft{}
	wireServerFirewall(t, dst, restarted, nft)
	g := watchGuardAtRunning(t, dst, nft)
	restarted.ResumeHeldGuestsOnce(ctx)
	if st := rawState(dst, "old"); st != libvirtfake.StateRunning {
		t.Fatalf("the restarted target did not resume the guest it held: %s", st)
	}
	if got := g.all("old"); !everyTrue(got) {
		t.Errorf("guard in force when the restarted target resumed the guest: %v", got)
	}
}

// TestFleet_NICGuard_ResumeHeldCommand (re-review R3-I2): `lv firewall
// nic-guard resume` lets a held guest run once its guards are in force,
// through any node; it refuses a guest that is not held.
func TestFleet_NICGuard_ResumeHeldCommand(t *testing.T) {
	c, src, dst, _ := heldCluster(t)
	ctx := context.Background()
	dst.Virt.FailResumeDomain = func(string) error { return errors.New("qemu would not resume") }
	if err := migrateAt(t, c, src, "old", dst.Name); err == nil {
		t.Fatal("fixture: the hand-over succeeded")
	}
	dst.Virt.FailResumeDomain = nil
	if _, err := c.SelfClient(src).ResumeHeldVM(ctx, &pb.ResumeHeldVMRequest{VmName: "old"}); err != nil {
		t.Fatalf("resume through another node: %v", err)
	}
	if st := rawState(dst, "old"); st != libvirtfake.StateRunning {
		t.Fatalf("after the command the guest is %s", st)
	}
	if _, err := c.SelfClient(src).ResumeHeldVM(ctx, &pb.ResumeHeldVMRequest{VmName: "old"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("resuming a guest that is not held: %v, want FailedPrecondition", err)
	}
}
