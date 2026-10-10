package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/nictap"
)

// recordingNft is an nft that keeps every ruleset applied to it.
type recordingNft struct {
	mu   sync.Mutex
	last map[string]string // table header → ruleset
}

func (r *recordingNft) Apply(_ context.Context, ruleset string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.last == nil {
		r.last = map[string]string{}
	}
	key := "inet"
	if strings.Contains(ruleset, "table bridge "+firewall.NICTableName) {
		key = "bridge"
	}
	r.last[key] = ruleset
	return "", nil
}

func (r *recordingNft) Flush(context.Context) (string, error) { return "", nil }

func (r *recordingNft) nicTable() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.last["bridge"]
}

// wireNodeFirewall gives node n the firewall the daemon gives a host: a
// reconciler over its own replica and its libvirt's taps, an arming set, and
// the before-start hook (daemon.go) that puts a VM's NIC firewall in force
// before libvirt starts it.
func wireNodeFirewall(t *testing.T, n *Node) *recordingNft {
	t.Helper()
	return wireNodeFirewallWith(t, n, &recordingNft{})
}

// wireNodeFirewallWith is wireNodeFirewall onto a given nft: the daemon's
// wiring (daemon.go), including the host label that says this host enforces
// NIC guards.
func wireNodeFirewallWith(t *testing.T, n *Node, nft *recordingNft) *recordingNft {
	t.Helper()
	return wireServerFirewall(t, n, n.Server, nft)
}

// wireServerFirewall is wireNodeFirewallWith onto a given server of n's — a
// restarted daemon's. The host label carries the build that set it, and
// counts only while the host reports that build (re-review m2).
func wireServerFirewall(t *testing.T, n *Node, srv *grpcapi.Server, nft *recordingNft) *recordingNft {
	t.Helper()
	if err := corrosion.UpdateHostVersion(context.Background(), n.DB, n.Name, "fleet-build"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetHostLabel(context.Background(), n.DB, n.Name, corrosion.LabelNICGuards, "fleet-build"); err != nil {
		t.Fatal(err)
	}
	arm := firewall.NewArming()
	loader := firewall.CorrosionPlanLoader(n.DB, n.Name, firewall.Plan{}, firewall.LoaderOptions{
		RunningTaps: n.Virt.RunningDomainTaps,
		TapBridge:   func(string) string { return "" },
		Arming:      arm,
	})
	rec := firewall.NewReconciler(loader, firewall.NewApplier(nft), 0)
	rec.SetArming(arm)
	srv.SetFirewallReconciler(rec)
	n.Virt.SetStartGuard(srv.NICStartGuard(context.Background()))
	return nft
}

// TestFleet_NICGuard_InForceBeforeFirstPacket (re-review I-10): a guarded
// NIC's guard is in the applied per-NIC table BEFORE its domain starts — at
// create, at a stop and start, and on the target of a migration before the
// guest arrives — not at the next reconcile tick, up to 30 s later.
func TestFleet_NICGuard_InForceBeforeFirstPacket(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	nfts := map[string]*recordingNft{}
	for _, n := range c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
		n.Server.SetBridgeEnsure(func(string) error { return nil })
		nfts[n.Name] = wireNodeFirewall(t, n)
	}
	const mac = "52:54:00:77:00:01"
	guardChain := "chain guard_" + nictap.Name(mac) + " {"

	// The guard each start found in force.
	var mu sync.Mutex
	atStart := map[int]bool{}
	starts := 0
	src.Virt.FailStartDomain = func(name string) error {
		mu.Lock()
		defer mu.Unlock()
		atStart[starts] = strings.Contains(nfts[src.Name].nicTable(), guardChain)
		starts++
		return nil
	}
	if _, err := c.SelfClient(src).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: "web", Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: src.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", Ip: "10.30.0.41", Mac: mac}},
	}}); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if _, err := c.SelfClient(src).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM: %v", err)
	}
	if _, err := c.SelfClient(src).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM: %v", err)
	}
	mu.Lock()
	if starts < 2 || !atStart[0] || !atStart[1] {
		t.Errorf("guard in force at each start: %v (%d starts)", atStart, starts)
	}
	mu.Unlock()

	// Migration: the target has the guard in force when libvirt hands the
	// guest over.
	inForce := false
	src.Virt.FailMigrateToTarget = func(name, uri string) error {
		inForce = strings.Contains(nfts[dst.Name].nicTable(), guardChain)
		return nil
	}
	if err := migrateAt(t, c, src, "web", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !inForce {
		t.Errorf("the migration target did not have the guard in force when the guest arrived:\n%s", nfts[dst.Name].nicTable())
	}
	if rec, err := corrosion.GetNICGuard(ctx, src.DB, "web", mac); err != nil || rec == nil || !rec.Guarded() {
		t.Fatalf("fixture: the NIC is not guarded: %+v, %v", rec, err)
	}
}
