package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/litevirt/litevirt/internal/lxc"
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
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Per-device failures preserve the distinction between failure of the new
// device and failure to restore services after the old device was released.
type moveProvisioner struct {
	bridgeRemovalProv
	mu                sync.Mutex
	serving           map[string]bool
	fail              map[string]error
	released, retired []string
	before            func(context.Context, string)
	gatewayCheck      func()
}

func (p *moveProvisioner) Provision(ctx context.Context, _ *corrosion.Client, n string, d compose.NetworkDef, _, _ string) (string, error) {
	dev := d.Interface
	if p.before != nil {
		p.before(ctx, dev)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.fail[dev]; err != nil {
		return "", err
	}
	p.serving[dev] = true
	return dev, nil
}
func (p *moveProvisioner) ServingGateway(_ string, d compose.NetworkDef) bool {
	if p.gatewayCheck != nil {
		p.gatewayCheck()
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.serving[d.Interface]
}
func (p *moveProvisioner) WouldServeGateway(context.Context, *corrosion.Client, string, compose.NetworkDef, string) bool {
	return true
}
func (p *moveProvisioner) ReleaseDeviceServices(_ string, d compose.NetworkDef) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.serving, d.Interface)
	p.released = append(p.released, d.Interface)
}
func (p *moveProvisioner) RetireDevice(_ context.Context, _ *corrosion.Client, _ string, d compose.NetworkDef, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.retired = append(p.retired, d.Interface)
	delete(p.serving, d.Interface)
	return nil
}
func moveFixture(t *testing.T) (*Server, *moveProvisioner, *libvirtfake.Fake, compose.NetworkDef, compose.NetworkDef) {
	t.Helper()
	s := testServer(t)
	v := libvirtfake.New()
	s.virt = v
	old := compose.NetworkDef{Type: "bridge", Interface: "oldbr", Subnet: "192.0.2.0/24", DHCP: true}
	next := old
	next.Interface = "newbr"
	cfg, _ := json.Marshal(next)
	if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); err != nil {
		t.Fatal(err)
	}
	x := `<domain><name>guest</name><devices><interface type="bridge"><mac address="52:54:00:00:00:01"/><source bridge="oldbr"/></interface></devices></domain>`
	v.SetInactiveXML("guest", x)
	v.SetState("guest", "stopped")
	s.SetNetworkDeviceStatePath(filepath.Join(t.TempDir(), "network-devices.json"))
	s.netDevs.setDef("lan", old, true)
	p := &moveProvisioner{serving: map[string]bool{"oldbr": true}, fail: map[string]error{"newbr": errors.New("new device failed")}}
	s.SetNetworkProvisioner(p)
	return s, p, v, old, next
}
func TestNetworkMove_RollbackRestoresOrRetainsRecovery(t *testing.T) {
	for _, both := range []bool{false, true} {
		t.Run(map[bool]string{false: "old restored", true: "both fail"}[both], func(t *testing.T) {
			s, p, v, old, next := moveFixture(t)
			if both {
				p.fail["oldbr"] = errors.New("old device failed")
			}
			if _, err := s.provisionDevice(context.Background(), s.db, "lan", next, "", s.hostName); err == nil {
				t.Fatal("expected new provision failure")
			}
			if len(p.released) != 1 {
				t.Fatal("did not enter actual same-subnet release branch")
			}
			if got := libvirt.InterfaceBridges(v.DefinedXML("guest"))["52:54:00:00:00:01"]; got != "oldbr" {
				t.Fatalf("failed move changed stopped definition: %s", got)
			}
			if got, _ := s.servedDef("lan"); got.Interface != "oldbr" {
				t.Fatalf("failed move forgot old definition: %+v", got)
			}
			if !both && !p.ServingGateway("lan", old) {
				t.Fatal("old service not recovered")
			}
			if both {
				// A fresh Server must see the failed-recovery obligation, not just old
				// definitions; no process globals or shared /run state are involved.
				fresh := testServer(t)
				fresh.virt = v
				fresh.SetNetworkProvisioner(p)
				fresh.SetNetworkDeviceStatePath(s.netDevs.statePath)
				fresh.netDevs.mu.Lock()
				fresh.netDevs.loadLocked()
				pending := len(fresh.netDevs.pending)
				fresh.netDevs.mu.Unlock()
				if pending == 0 {
					t.Error("failed recovery obligation vanished across fresh Server")
				}
				delete(p.fail, "oldbr")
				if _, err := fresh.provisionDevice(context.Background(), fresh.db, "lan", next, "", fresh.hostName); err == nil {
					t.Fatal("new device should still fail")
				}
				if !p.ServingGateway("lan", old) {
					t.Error("retry failed to restore old service")
				}
			}
		})
	}
}
func TestNetworkDeviceUsers_UnsupportedLinkerFailsClosed(t *testing.T) {
	for _, state := range []string{"running", "stopped", "defined"} {
		t.Run(state, func(t *testing.T) {
			s := testServer(t)
			s.SetContainerRuntime(&fakeCTRuntime{listNames: []string{"ct"}, stateByName: map[string]string{"ct": state}})
			s.virt = libvirtfake.New()
			v := s.virt.(*libvirtfake.Fake)
			v.SetInactiveXML("vm", `<domain><devices><interface><mac address="52:54:00:00:00:01"/><source bridge="rawbr"/></interface></devices></domain>`)
			v.SetState("vm", "stopped")
			users, err := s.deviceUsersAll(context.Background())
			if err == nil || !strings.Contains(err.Error(), "NIC links") {
				t.Errorf("unsupported container holder silently absent: %v", err)
			}
			if len(users["rawbr"].stopped) != 1 {
				t.Fatalf("known VM holder lost: %+v", users)
			}
		})
	}
}
func TestMigrationMTU_UsesServedOldDevice(t *testing.T) {
	s, _, _, _, _ := moveFixture(t)
	s.virt.(*libvirtfake.Fake).SetBridgeMTU("oldbr", 1400)
	s.virt.(*libvirtfake.Fake).SetBridgeMTU("newbr", 1500)
	if got := s.nicMTUProblem(context.Background(), []*pb.NICMTUExpectation{{Network: "lan", Mtu: 1400}}); got != "" {
		t.Fatalf("target judged new device instead of served old device: %s", got)
	}
}

func TestNetworkMove_ExcludesInFlightWorkloadStart(t *testing.T) {
	s, p, v, old, next := moveFixture(t)
	p.fail = map[string]error{}
	put := func(d compose.NetworkDef) {
		cfg, _ := json.Marshal(d)
		if err := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	put(old)
	vm := corrosion.VMRecord{Name: "guest", HostName: s.hostName, State: "stopped", Spec: "{}"}
	if err := corrosion.InsertVM(context.Background(), s.db, vm, []corrosion.InterfaceRecord{{VMName: "guest", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); err != nil {
		t.Fatal(err)
	}
	entered, release, started := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }

	var workers sync.WaitGroup
	defer func() {
		unblock()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("start/move workers did not join")
		}
	}()

	v.FailStartDomain = func(string) error { close(entered); <-release; return nil }
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, err := s.startVMLockedWithin(context.Background(), &vm, 0)
		started <- err
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("start never entered fake runtime")
	}
	put(next)
	checked := make(chan struct{}, 1)
	p.gatewayCheck = func() {
		select {
		case checked <- struct{}{}:
		default:
		}
	}
	moved := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, err := s.provisionDevice(context.Background(), s.db, "lan", next, "", s.hostName)
		moved <- err
	}()
	crossed := false
	select {
	case <-checked:
		crossed = true
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	select {
	case err := <-started:
		if err != nil {
			t.Errorf("start: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("start did not join")
	}
	select {
	case <-moved:
	case <-time.After(2 * time.Second):
		t.Fatal("move did not join")
	}
	if crossed {
		t.Error("move reached gateway release decision while StartDomain was in flight")
	}
	// Either the move was refused after observing the start or the definition
	// moved before the start: the running NIC must still have its gateway.
	live, _ := v.DumpXML("guest")
	dev := libvirt.InterfaceBridges(live)["52:54:00:00:00:01"]
	if !p.ServingGateway("lan", compose.NetworkDef{Interface: dev}) {
		t.Errorf("running guest on %s lost gateway during concurrent move", dev)
	}
}

// The old-device rollback is deliberately blocked inside the provider, while
// a second network tries the shared device and a sweep tries retirement.
func TestNetworkMove_RollbackExcludesSharedDeviceAndCanceledSweep(t *testing.T) {
	s, p, _, _, next := moveFixture(t)
	entered, unblock := make(chan struct{}), make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(unblock) }) }
	var workers sync.WaitGroup
	defer func() {
		release()
		done := make(chan struct{})
		go func() { workers.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("workers did not join")
		}
	}()
	p.before = func(_ context.Context, dev string) {
		if dev == "oldbr" {
			close(entered)
			<-unblock
		}
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, _ = s.provisionDevice(context.Background(), s.db, "lan", next, "", s.hostName)
	}()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("rollback not reached")
	}
	// This shared-device operation cannot enter Provision until rollback ends.
	canceled, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		_, e := s.provisionDevice(canceled, s.db, "shared", next, "", s.hostName)
		result <- e
	}()
	cancel()
	select {
	case e := <-result:
		if !errors.Is(e, context.Canceled) {
			t.Errorf("blocked shared provision: %v", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled provision stayed blocked")
	}

	waitingSweep := make(chan struct{})
	workers.Add(1)
	go func() { defer workers.Done(); s.retirePendingDevices(context.Background()); close(waitingSweep) }()
	select {
	case <-waitingSweep:
		t.Fatal("sweep crossed rollback boundary")
	case <-time.After(100 * time.Millisecond):
	}
	sweepCtx, stop := context.WithCancel(context.Background())
	stop()
	sweepDone := make(chan struct{})
	workers.Add(1)
	go func() { defer workers.Done(); s.retirePendingDevices(sweepCtx); close(sweepDone) }()
	select {
	case <-sweepDone:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled sweep stayed blocked")
	}
	p.mu.Lock()
	retired := len(p.retired)
	p.mu.Unlock()
	if retired != 0 {
		t.Fatal("sweep retired rollback device")
	}
	release()
}

func TestNetworkDeviceState_PrivateRestartAndErrors(t *testing.T) {
	for _, tc := range []string{"missing", "corrupt", "truncated", "directory"} {
		t.Run(tc, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "state")
			switch tc {
			case "corrupt":
				_ = os.WriteFile(path, []byte("broken"), 0600)
			case "truncated":
				_ = os.WriteFile(path, []byte(`{"defs":`), 0600)
			case "directory":
				_ = os.Mkdir(path, 0700)
			}
			s := testServer(t)
			s.SetNetworkDeviceStatePath(path)
			if _, ok := s.netDevs.lastDef("lan"); ok {
				t.Fatal("invented persisted device")
			}
			def := compose.NetworkDef{Type: "bridge", Interface: "oldbr"}
			s.netDevs.setDef("lan", def, true)
			if got, ok := s.netDevs.lastDef("lan"); !ok || got.Interface != "oldbr" {
				t.Fatal("memory retry obligation lost")
			}
			if tc == "directory" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				s.netDevs.setDef("lan", def, true)
			}
			fresh := testServer(t)
			fresh.SetNetworkDeviceStatePath(path)
			if got, ok := fresh.netDevs.lastDef("lan"); !ok || got.Interface != "oldbr" {
				t.Fatal("fresh server lost successfully retried save")
			}
			st, e := os.Stat(path)
			if e != nil || st.Mode().Perm() != 0600 {
				t.Fatalf("state mode: %v %v", st, e)
			}
			if _, e := os.Stat(path + ".tmp"); !os.IsNotExist(e) {
				t.Fatalf("temporary state remains: %v", e)
			}
		})
	}
}

type linkInner struct {
	lxc.Runtime
	links             map[int]string
	readErr, writeErr error
}

func (r *linkInner) NetLinks(string) (map[int]string, error) { return r.links, r.readErr }
func (r *linkInner) SetNetLink(_ string, n int, b string) error {
	if r.writeErr != nil {
		return r.writeErr
	}
	r.links[n] = b
	return nil
}

type linkCT struct {
	fakeCTRuntime
	links       map[int]string
	readErr     error
	failOrdinal int
	fail        bool
}

func (r *linkCT) ContainerNICLinks(context.Context, string) (map[int]string, error) {
	out := map[int]string{}
	for n, b := range r.links {
		out[n] = b
	}
	return out, r.readErr
}
func (r *linkCT) SetContainerNICLink(_ context.Context, _ string, n int, b string) error {
	if r.fail && n == r.failOrdinal {
		return errors.New("write refused")
	}
	r.links[n] = b
	return nil
}
func TestContainerLinks_AdapterAndPartialRetry(t *testing.T) {
	ctx := context.Background()
	unsupported := NewLXCRuntimeAdapter(struct{ lxc.Runtime }{})
	if _, e := unsupported.ContainerNICLinks(ctx, "ct"); e == nil {
		t.Fatal("unsupported read accepted")
	}
	if e := unsupported.SetContainerNICLink(ctx, "ct", 0, "newbr"); e == nil {
		t.Fatal("unsupported write accepted")
	}
	sentinel := errors.New("private adapter error")
	inner := &linkInner{links: map[int]string{0: "oldbr"}, readErr: sentinel, writeErr: sentinel}
	adapter := NewLXCRuntimeAdapter(inner)
	if _, e := adapter.ContainerNICLinks(ctx, "ct"); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	if e := adapter.SetContainerNICLink(ctx, "ct", 0, "newbr"); !errors.Is(e, sentinel) {
		t.Fatal(e)
	}
	for _, state := range []string{"running", "stopped", "defined"} {
		t.Run(state, func(t *testing.T) {
			s, p, v, _, next := moveFixture(t)
			p.fail = map[string]error{}
			ct := &linkCT{fakeCTRuntime: fakeCTRuntime{listNames: []string{"ct"}, stateByName: map[string]string{"ct": state}}, links: map[int]string{0: "oldbr", 1: "oldbr"}, fail: true, failOrdinal: 1}
			s.SetContainerRuntime(ct)
			v.SetActiveXML("active", `<domain><devices><interface><mac address="52:54:00:00:00:aa"/><source bridge="rawbr"/></interface></devices></domain>`)
			v.SetInactiveXML("active", `<domain><devices><interface><mac address="52:54:00:00:00:aa"/><source bridge="persistbr"/></interface></devices></domain>`)
			v.SetState("active", "running")
			all, e := s.deviceUsersAll(ctx)
			if e != nil {
				t.Fatal(e)
			}
			if len(all["rawbr"].running) != 1 || len(all["persistbr"].running) != 1 {
				t.Fatalf("live/persistent raw holders lost: %+v", all)
			}
			ct.readErr = sentinel
			if _, e := s.deviceUsersAll(ctx); !errors.Is(e, sentinel) {
				t.Fatalf("read failure lost: %v", e)
			}
			ct.readErr = nil
			s.repointStoppedOn(ctx, "lan", "oldbr", next.Interface)
			if state == "stopped" {
				if ct.links[0] != "newbr" || ct.links[1] != "oldbr" {
					t.Fatalf("partial write: %v", ct.links)
				}
				users, e := s.deviceUsers(ctx, "oldbr")
				if e != nil || users.none() {
					t.Fatalf("failed NIC ceased being holder: %+v %v", users, e)
				}
				ct.fail = false
				s.repointStoppedOn(ctx, "lan", "oldbr", "newbr")
				if ct.links[0] != "newbr" || ct.links[1] != "newbr" {
					t.Fatalf("retry did not finish: %v", ct.links)
				}
			} else if ct.links[0] != "oldbr" || ct.links[1] != "oldbr" {
				t.Fatalf("non-stopped config changed: %v", ct.links)
			}
		})
	}
}

// A start's follower writes the config again after provisioning. A second
// move must not retire that newly served device while this write is pending.
type followBarrierVirt struct {
	*libvirtfake.Fake
	mu               sync.Mutex
	writes           int
	entered, release chan struct{}
}

func (v *followBarrierVirt) SetNICBridgeConfig(vm, mac, bridge string) error {
	if bridge == "newbr" {
		v.mu.Lock()
		v.writes++
		block := v.writes == 2
		v.mu.Unlock()
		if block {
			close(v.entered)
			<-v.release
		}
	}
	return v.Fake.SetNICBridgeConfig(vm, mac, bridge)
}
func TestNetworkMove_ExcludesFollowerConfigWrite(t *testing.T) {
	s, p, v, _, next := moveFixture(t)
	p.fail = map[string]error{}
	vm := corrosion.VMRecord{Name: "guest", HostName: s.hostName, State: "stopped", Spec: "{}"}
	if e := corrosion.InsertVM(context.Background(), s.db, vm, []corrosion.InterfaceRecord{{VMName: "guest", NetworkName: "lan", MAC: "52:54:00:00:00:01"}}, nil); e != nil {
		t.Fatal(e)
	}
	wrapped := &followBarrierVirt{Fake: v, entered: make(chan struct{}), release: make(chan struct{})}
	s.virt = wrapped
	var once sync.Once
	unblock := func() { once.Do(func() { close(wrapped.release) }) }
	var wg sync.WaitGroup
	defer func() {
		unblock()
		done := make(chan struct{})
		go func() { wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("follower/move workers did not join")
		}
	}()
	started := make(chan error, 1)
	wg.Add(1)
	go func() { defer wg.Done(); _, e := s.startVMLockedWithin(context.Background(), &vm, 0); started <- e }()
	select {
	case <-wrapped.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("follower write after provision not reached")
	}
	third := next
	third.Interface = "thirdbr"
	cfg, _ := json.Marshal(third)
	if e := corrosion.UpsertNetwork(context.Background(), s.db, corrosion.NetworkRecord{Name: "lan", Type: "bridge", Config: string(cfg)}); e != nil {
		t.Fatal(e)
	}
	moved := make(chan error, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, e := s.provisionDevice(context.Background(), s.db, "lan", third, "", s.hostName)
		moved <- e
	}()
	joined := false
	select {
	case <-moved:
		joined = true
		t.Error("later move crossed a pending follower config write")
	case <-time.After(100 * time.Millisecond):
	}
	unblock()
	select {
	case e := <-started:
		if e != nil {
			t.Error(e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("start did not join")
	}
	if !joined {
		select {
		case <-moved:
		case <-time.After(2 * time.Second):
			t.Fatal("later move did not join")
		}
	}
	live, _ := v.DumpXML("guest")
	dev := libvirt.InterfaceBridges(live)["52:54:00:00:00:01"]
	if !p.ServingGateway("lan", compose.NetworkDef{Interface: dev}) {
		t.Errorf("follower started guest on retired device %s", dev)
	}
}
