package fleet

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/nictap"
)

func lvTap(mac string) string { return nictap.Name(mac) }

// guardAtRunning records, each time a domain of n's starts running, whether
// the per-NIC table then held the guard chain of each tap the domain runs
// with — the tap it ACTUALLY has, whatever its name.
type guardAtRunning struct {
	mu   sync.Mutex
	seen map[string][]bool // domain → one entry per time it came up
}

func watchGuardAtRunning(t *testing.T, n *Node, nft *recordingNft) *guardAtRunning {
	t.Helper()
	g := &guardAtRunning{seen: map[string][]bool{}}
	n.Virt.OnRunning = func(name string) {
		taps, _ := n.Virt.RunningDomainTaps()
		table := nft.nicTable()
		ok := len(taps[name]) > 0
		for _, tap := range taps[name] {
			ok = ok && strings.Contains(table, "chain guard_"+tap+" {")
		}
		g.mu.Lock()
		g.seen[name] = append(g.seen[name], ok)
		g.mu.Unlock()
	}
	return g
}

func (g *guardAtRunning) all(name string) []bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]bool(nil), g.seen[name]...)
}

func guardedVM(t *testing.T, c *Cluster, n *Node, name, ip, mac string) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 256, Placement: &pb.PlacementSpec{Host: n.Name},
		Network: []*pb.NetworkAttachment{{Name: "lan", Ip: ip, Mac: mac}},
	}}); err != nil {
		t.Fatalf("CreateVM %s: %v", name, err)
	}
	if rec, err := corrosion.GetNICGuard(context.Background(), n.DB, name, mac); err != nil || rec == nil || !rec.Guarded() {
		t.Fatalf("fixture: %s's NIC is not guarded: %+v, %v", name, rec, err)
	}
}

// asOlderDomain strips the tap name this build gives a NIC from a domain's
// definition: the domain an older release defined, which gets vnetN.
func asOlderDomain(n *Node, name string) {
	re := regexp.MustCompile(`<target dev="lvt[0-9a-f]+"></target>`)
	n.Virt.SetInactiveXML(name, re.ReplaceAllString(n.Virt.DefinedXML(name), ""))
}

func everyTrue(b []bool) bool {
	for _, v := range b {
		if !v {
			return false
		}
	}
	return len(b) > 0
}

// TestFleet_NICGuard_InForceAfterAReboot (re-review R2-I2): after a host
// boots, its nft tables are empty, and its onboot, self-heal and
// restart-policy starts may run before the daemon has wired the firewall. A
// start that comes first waits for it, so the guard is in force when the
// guest runs.
func TestFleet_NICGuard_InForceAfterAReboot(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	openNICGuards(t, n)
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	wireNodeFirewall(t, n)
	guardedVM(t, c, n, "web", "10.30.0.51", "52:54:00:77:01:01")
	if _, err := c.SelfClient(n).StopVM(context.Background(), &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatal(err)
	}

	// The reboot: an empty table, nothing wired, and a start that does not
	// wait for the daemon.
	n.Virt.SetStartGuard(lv.StartGuard{})
	n.Virt.RequireStartGuard(10*time.Second, nil)
	fresh := &recordingNft{}
	g := watchGuardAtRunning(t, n, fresh)
	started := make(chan error, 1)
	go func() { started <- n.Virt.StartDomain("web") }() // what onboot does
	time.Sleep(100 * time.Millisecond)
	wireNodeFirewallWith(t, n, fresh) // the daemon gets there
	if err := <-started; err != nil {
		t.Fatalf("onboot start: %v", err)
	}
	if got := g.all("web"); !everyTrue(got) {
		t.Errorf("guard in force when the guest ran after a reboot: %v", got)
	}
}

// TestFleet_NICGuard_DrainArmsTheTarget (re-review R2-I3): `lv host drain`
// moves a VM live through the same arming as `lv migrate`: the target has its
// guard in force when the guest arrives.
func TestFleet_NICGuard_DrainArmsTheTarget(t *testing.T) {
	c, src, dst, _ := isoLiveMoveCluster(t)
	defer c.Stop()
	ctx := context.Background()
	nfts := map[string]*recordingNft{}
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		nfts[n.Name] = wireNodeFirewall(t, n)
	}
	const mac = "52:54:00:77:02:01"
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{Name: "web", HostName: src.Name, State: "running",
		Spec: `{"name":"web","uuid":"u-web","cpu":1,"memory_mib":256}`, CPUActual: 1, MemActual: 256},
		[]corrosion.InterfaceRecord{{VMName: "web", NetworkName: "lan", MAC: mac, IP: "10.30.0.52"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.PutNICGuard(ctx, src.DB, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "web", MAC: mac, Mode: corrosion.NICGuardOn,
		VMUUID: "u-web", Network: "lan"}, "t"); err != nil {
		t.Fatal(err)
	}
	dom := `<domain type='kvm'><name>web</name><memory unit='MiB'>256</memory><vcpu>1</vcpu><devices>` +
		`<interface type='bridge'><source bridge='br-lan'/><mac address='` + mac + `'/><target dev='` + lvTap(mac) + `'/></interface></devices></domain>`
	src.Virt.SetInactiveXML("web", dom)
	src.Virt.SetActiveXML("web", dom)
	src.Virt.SetState("web", "running")
	inForce := false
	src.Virt.FailMigrateToTarget = func(name, uri string) error {
		if name == "web" {
			inForce = strings.Contains(nfts[dst.Name].nicTable(), "chain guard_"+lvTap(mac)+" {")
		}
		return nil
	}
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
		if p.GetVmName() == "web" {
			last = p
		}
	}
	if last == nil || last.GetStatus() != "done" || last.GetStrategy() != pb.MigrateStrategy_MIGRATE_LIVE {
		t.Fatalf("drain progress for web = %+v, want a live move, done", last)
	}
	if !inForce {
		t.Errorf("the drain target did not have the guard in force when the guest arrived:\n%s", nfts[dst.Name].nicTable())
	}
}

// TestFleet_NICGuard_OlderDomainGuardedUnderItsOwnTap (re-review R2-I4): a
// guarded NIC whose domain an older release defined (no tap name: libvirt
// gives it vnetN) is started paused, its guard put in force under the tap it
// actually got, and only then let run — on a start and on a migration target.
func TestFleet_NICGuard_OlderDomainGuardedUnderItsOwnTap(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	nfts := map[string]*recordingNft{}
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
		nfts[n.Name] = wireNodeFirewall(t, n)
	}
	guardedVM(t, c, src, "old", "10.30.0.53", "52:54:00:77:03:01")
	if _, err := c.SelfClient(src).StopVM(ctx, &pb.StopVMRequest{Name: "old", Force: true}); err != nil {
		t.Fatal(err)
	}
	asOlderDomain(src, "old")
	g := watchGuardAtRunning(t, src, nfts[src.Name])
	if _, err := c.SelfClient(src).StartVM(ctx, &pb.StartVMRequest{Name: "old"}); err != nil {
		t.Fatalf("StartVM: %v", err)
	}
	taps, _ := src.Virt.RunningDomainTaps()
	if tap := taps["old"]["52:54:00:77:03:01"]; !strings.HasPrefix(tap, "vnet") {
		t.Fatalf("fixture: the older domain's tap is %q, want a vnetN", tap)
	}
	if got := g.all("old"); !everyTrue(got) {
		t.Errorf("start: guard in force under the domain's own tap when it ran: %v", got)
	}

	// Migration: the guest lands paused, the target arms it under its own
	// tap there, then lets it run.
	dg := watchGuardAtRunning(t, dst, nfts[dst.Name])
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
	if err := migrateAt(t, c, src, "old", dst.Name); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if got := dg.all("old"); !everyTrue(got) {
		t.Errorf("migration: guard in force under the target's own tap when the guest ran there: %v", got)
	}
}

// TestFleet_NICGuard_DeletedWithTheVM (re-review m1): a VM's guard records go
// with it; a later VM of the same name and MAC inherits nothing.
func TestFleet_NICGuard_DeletedWithTheVM(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	openNICGuards(t, n)
	n.Server.SetBridgeEnsure(func(string) error { return nil })
	guardedVM(t, c, n, "gone", "10.30.0.54", "52:54:00:77:04:01")
	if _, err := c.SelfClient(n).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "gone"}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if rec, err := corrosion.GetNICGuard(context.Background(), n.DB, "gone", "52:54:00:77:04:01"); err != nil || rec != nil {
		t.Errorf("the deleted VM's guard record outlived it: %+v, %v", rec, err)
	}
}

// TestFleet_NICGuard_GuardedVMStaysOnGuardingHosts (re-review m8): until
// every host runs a build that knows NIC guards, a guarded VM is not moved to
// a host that does not advertise them, where it would run unguarded while
// `nic-guard ls` says on.
func TestFleet_NICGuard_GuardedVMStaysOnGuardingHosts(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
	}
	wireNodeFirewall(t, src) // dst is "older": no guards, no label
	guardedVM(t, c, src, "web", "10.30.0.55", "52:54:00:77:05:01")
	// src's own release latch lags the one the guard was written under
	// (a latch forms per node): it must narrow the move itself.
	src.Server.SetReleaseFeatureGate(grantAllGate{t: t, lagging: true})
	err := migrateAt(t, c, src, "web", dst.Name)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("migrating a guarded VM to a host that does not advertise guards: %v, want FailedPrecondition", err)
	}
	if n := migrateCalls(src); n != 0 {
		t.Errorf("the refused move reached libvirt %d time(s)", n)
	}
}
