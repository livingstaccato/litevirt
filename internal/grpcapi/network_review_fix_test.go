package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/vfio"
)

func TestNetworkMove_ExcludesStartDomainRewrite(t *testing.T) {
	s, p, v, old, next := moveFixture(t)
	p.fail = map[string]error{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cfg, _ := json.Marshal(old)
	if e := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); e != nil {
		t.Fatal(e)
	}
	iso := filepath.Join(t.TempDir(), "installer.iso")
	writeISO(t, iso)
	previous := filepath.Join(t.TempDir(), "previous.iso")
	spec, _ := json.Marshal(&pb.VMSpec{Iso: iso})
	vm := corrosion.VMRecord{Name: "guest", HostName: s.hostName, State: "stopped", Spec: string(spec)}
	if e := corrosion.InsertVM(ctx, s.db, vm, []corrosion.InterfaceRecord{{VMName: "guest", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); e != nil {
		t.Fatal(e)
	}
	x, _ := v.DumpXMLInactive("guest")
	x = strings.Replace(x, "</devices>", `<disk type="file" device="cdrom"><source file="`+previous+`"/></disk></devices>`, 1)
	v.SetInactiveXML("guest", x)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	orig := judgeCDROMs
	judgeCDROMs = func(s *Server, vm *corrosion.VMRecord, x string) (string, error) {
		close(entered)
		<-release
		return orig(s, vm, x)
	}
	t.Cleanup(func() { judgeCDROMs = orig })
	var wg sync.WaitGroup
	defer func() {
		unblock()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("start/rewrite/move workers did not join")
		}
	}()
	started := make(chan error, 1)
	wg.Add(1)
	go func() { defer wg.Done(); _, e := s.startVMLockedWithin(ctx, &vm, 0); started <- e }()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("actual ISO judgement not reached")
	}
	cfg, _ = json.Marshal(next)
	if e := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); e != nil {
		t.Fatal(e)
	}
	moved := make(chan error, 1)
	wg.Add(1)
	go func() { defer wg.Done(); _, e := s.provisionDevice(ctx, s.db, "lan", next, "", s.hostName); moved <- e }()
	joined := false
	select {
	case <-moved:
		joined = true
		t.Error("move crossed captured domain rewrite")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	select {
	case e := <-started:
		if e != nil {
			t.Fatal(e)
		}
	case <-ctx.Done():
		t.Fatal("start did not join")
	}
	if !joined {
		select {
		case <-moved:
		case <-ctx.Done():
			t.Fatal("move did not join")
		}
	}
	for label, read := range map[string]func(string) (string, error){"live": v.DumpXML, "persistent": v.DumpXMLInactive} {
		got, e := read("guest")
		if e != nil {
			t.Fatal(e)
		}
		if !strings.Contains(got, iso) || strings.Contains(got, previous) {
			t.Errorf("%s ISO was not remapped: %s", label, got)
		}
		dev := libvirt.InterfaceBridges(got)["52:54:00:00:00:01"]
		if !p.ServingGateway("lan", compose.NetworkDef{Interface: dev}) {
			t.Errorf("%s definition restored retired device %s", label, dev)
		}
	}
}

// This fixture runs the production DHCP gate with the production preexistence
// facts: a private pidfile remembers service; release removes it, not the
// bridge. Only an affirmative gate creates the modeled DHCP/gateway service.
// No network command, process, signal, socket or shared state is consulted.
type dhcpDecisionProvisioner struct {
	bridgeRemovalProv
	dir      string
	bridges  map[string]bool
	gateways map[string]bool
	fail     map[string]error
	suppress map[string]bool
	releases int
	attempts []string
}

func (p *dhcpDecisionProvisioner) pid(dev string) string { return filepath.Join(p.dir, dev+".pid") }
func (p *dhcpDecisionProvisioner) ServingGateway(_ string, d compose.NetworkDef) bool {
	_, e := os.Stat(p.pid(d.Interface))
	return e == nil && p.gateways[d.Interface]
}
func (p *dhcpDecisionProvisioner) facts(d compose.NetworkDef) network.DHCPHostFacts {
	_, e := os.Stat(p.pid(d.Interface))
	return network.DHCPHostFacts{BridgePreExisted: p.bridges[d.Interface] && (d.NetBoxPrefixID != 0 || e != nil)}
}
func (p *dhcpDecisionProvisioner) WouldServeGateway(_ context.Context, _ *corrosion.Client, _ string, d compose.NetworkDef, _ string) bool {
	return network.DHCPWouldServe(d, p.facts(d))
}
func (p *dhcpDecisionProvisioner) Provision(_ context.Context, _ *corrosion.Client, _ string, d compose.NetworkDef, _, _ string) (string, error) {
	p.attempts = append(p.attempts, d.Interface)
	if e := p.fail[d.Interface]; e != nil {
		return "", e
	}
	facts := p.facts(d)
	p.bridges[d.Interface] = true
	if network.DHCPWouldServe(d, facts) && !p.suppress[d.Interface] {
		if _, _, _, _, e := network.SubnetRange(d.Subnet); e != nil {
			return "", e
		}
		if e := os.WriteFile(p.pid(d.Interface), []byte("private modeled DHCP"), 0600); e != nil {
			return "", e
		}
		p.gateways[d.Interface] = true
	}
	return d.Interface, nil
}
func (p *dhcpDecisionProvisioner) ReleaseDeviceServices(_ string, d compose.NetworkDef) {
	p.releases++
	os.Remove(p.pid(d.Interface))
	delete(p.gateways, d.Interface)
}
func (p *dhcpDecisionProvisioner) RetireDevice(_ context.Context, _ *corrosion.Client, _ string, d compose.NetworkDef, _ string) error {
	os.Remove(p.pid(d.Interface))
	delete(p.gateways, d.Interface)
	delete(p.bridges, d.Interface)
	return nil
}
func TestNetworkMove_RestoresImplicitDHCPService(t *testing.T) {
	for _, mode := range []string{"restore", "failed_restore_restart", "silent_restore_restart"} {
		t.Run(mode, func(t *testing.T) {
			both := mode != "restore"
			s, _, v, old, next := moveFixture(t)
			old.DHCP = false
			next.DHCP = false
			p := &dhcpDecisionProvisioner{dir: t.TempDir(), bridges: map[string]bool{}, gateways: map[string]bool{}, fail: map[string]error{}}
			s.SetNetworkProvisioner(p)
			ctx := context.Background()
			if _, e := s.provisionDevice(ctx, s.db, "lan", old, "", s.hostName); e != nil {
				t.Fatal(e)
			}
			if !p.ServingGateway("lan", old) {
				t.Fatal("initial implicit DHCP service was not created")
			}
			p.fail["newbr"] = errors.New("new device failed")
			if mode == "failed_restore_restart" {
				p.fail["oldbr"] = errors.New("old restoration failed")
			} else if mode == "silent_restore_restart" {
				p.suppress = map[string]bool{"oldbr": true}
			}
			if _, e := s.provisionDevice(ctx, s.db, "lan", next, "", s.hostName); e == nil {
				t.Fatal("move should fail")
			}
			if p.releases != 1 {
				t.Fatal("actual same-subnet service release not reached")
			}
			if both {
				pending := s.netDevs.pending["oldbr"]
				if !pending.Recover || !pending.Released || pending.Def.DHCP {
					t.Fatalf("lost implicit service recovery ownership: %+v", pending)
				}
				fresh := testServer(t)
				fresh.db = s.db
				fresh.virt = v
				fresh.SetNetworkProvisioner(p)
				fresh.SetNetworkDeviceStatePath(s.netDevs.statePath)
				// A still-unrestored service must stop the retry before the new device.
				p.attempts = nil
				if _, e := fresh.provisionDevice(ctx, fresh.db, "lan", next, "", fresh.hostName); e == nil {
					t.Fatal("unrestored recovery should fail")
				}
				if len(p.attempts) != 1 || p.attempts[0] != "oldbr" {
					t.Fatalf("retry crossed unrestored service: %v", p.attempts)
				}
				delete(p.suppress, "oldbr")
				delete(p.fail, "oldbr")
				p.attempts = nil
				if _, e := fresh.provisionDevice(ctx, fresh.db, "lan", next, "", fresh.hostName); e == nil {
					t.Fatal("new device should still fail")
				}
				if len(p.attempts) == 0 || p.attempts[0] != "oldbr" {
					t.Errorf("retry skipped old recovery: %v", p.attempts)
				}
			}
			if !p.ServingGateway("lan", old) {
				t.Error("nil rollback result did not restore implicit DHCP and gateway")
			}
			got, _ := v.DumpXMLInactive("guest")
			if libvirt.InterfaceBridges(got)["52:54:00:00:00:01"] != "oldbr" {
				t.Error("failed move changed stopped NIC")
			}
		})
	}
	t.Run("operator_bridge", func(t *testing.T) {
		s, _, v, old, next := moveFixture(t)
		old.DHCP, next.DHCP = false, false
		p := &dhcpDecisionProvisioner{dir: t.TempDir(), bridges: map[string]bool{"oldbr": true}, gateways: map[string]bool{}, fail: map[string]error{}}
		s.SetNetworkProvisioner(p)
		ctx := context.Background()
		if _, e := s.provisionDevice(ctx, s.db, "lan", old, "", s.hostName); e != nil {
			t.Fatal(e)
		}
		p.fail["newbr"] = errors.New("new device failed")
		for i := 0; i < 2; i++ {
			if _, e := s.provisionDevice(ctx, s.db, "lan", next, "", s.hostName); e == nil {
				t.Fatal("move should fail")
			}
			if p.ServingGateway("lan", old) || p.releases != 0 {
				t.Fatal("operator bridge gained unauthorized DHCP or release")
			}
			fresh := testServer(t)
			fresh.db, fresh.virt = s.db, v
			fresh.SetNetworkProvisioner(p)
			fresh.SetNetworkDeviceStatePath(s.netDevs.statePath)
			s = fresh
		}
	})
}

// Hardware regressions exercise domain/storage behavior without issuing host
// network effects. Install these before any handler can create or start a VM.
func isolateReviewHardwareNetwork(t *testing.T, s *Server) {
	t.Helper()
	s.SetNetworkProvisioner(&bridgeRemovalProv{})
	s.SetNetworkEffects(isolatedNetworkEffects{})
	s.SetNetworkDeviceStatePath(filepath.Join(t.TempDir(), "network-devices.json"))
}

func TestNetworkMove_PCIPreflightKeepsServedDeviceAfterFailedMove(t *testing.T) {
	s, p, v, old, _ := moveFixture(t)
	s.SetNetworkEffects(isolatedNetworkEffects{})
	enableHardwareV2(t, s)
	fs := newPCIBindFakeFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	spec, _ := json.Marshal(&pb.VMSpec{Name: "guest", Cpu: 2, MemoryMib: 512})
	vm := corrosion.VMRecord{Name: "guest", HostName: s.hostName, State: "stopped", Spec: string(spec)}
	if err := corrosion.InsertVM(ctx, s.db, vm, []corrosion.InterfaceRecord{{VMName: "guest", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatal(err)
	}
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	seedAddressIntent(t, s, "guest", "review-pci", "0000:41:00.0")
	if _, err := s.startVMLockedWithin(ctx, &vm, 0); err != nil {
		t.Fatal(err)
	}
	if len(p.released) != 1 || !p.ServingGateway("lan", old) {
		t.Fatal("start did not attempt failed move and restore old service")
	}
	if fs.binds != 1 || len(liveRealizations(t, ctx, s, "guest")) != 1 {
		t.Fatal("actual PCI preflight did not bind and realize the intent")
	}
	for label, read := range map[string]func(string) (string, error){"live": v.DumpXML, "persistent": v.DumpXMLInactive} {
		x, err := read("guest")
		if err != nil {
			t.Fatal(err)
		}
		if !hostdevAliasInXML(x, pciMemberAlias("review-pci", "m0")) {
			t.Fatalf("%s lost PCI intent", label)
		}
		dev := libvirt.InterfaceBridges(x)["52:54:00:00:00:01"]
		if dev != "oldbr" || !p.ServingGateway("lan", compose.NetworkDef{Interface: dev}) {
			t.Errorf("%s PCI rewrite selected unserved device %s after failed move", label, dev)
		}
	}
}
