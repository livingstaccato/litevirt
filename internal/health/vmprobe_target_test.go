package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
)

// These tests run the REAL probe transport. The VM is stood in for by a
// listener on 127.0.0.2 — deliberately not 127.0.0.1 — so a probe that goes to
// the HOST's localhost (the bug: the target used to be dialled literally, on
// the host) reaches nothing, while a probe resolved against the VM's address
// reaches the stand-in.

const vmStandIn = "127.0.0.2"

// listenAsVM starts a TCP listener on the VM stand-in address and returns its
// port. It first proves the same port is NOT answering on the host's
// 127.0.0.1, or the tests below could pass by probing the wrong machine.
func listenAsVM(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", vmStandIn+":0")
	if err != nil {
		t.Skipf("cannot bind %s (needs Linux loopback /8): %v", vmStandIn, err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	assertHostLocalhostDoesNotAnswer(t, port)
	return ln, port
}

func assertHostLocalhostDoesNotAnswer(t *testing.T, port string) {
	t.Helper()
	if c, err := net.DialTimeout("tcp", "127.0.0.1:"+port, time.Second); err == nil {
		c.Close()
		t.Skipf("precondition: something answers on 127.0.0.1:%s; the test could not tell host from VM", port)
	}
}

type targetFixture struct {
	t      *testing.T
	ctx    context.Context
	db     *corrosion.Client
	v      *VMChecker
	events <-chan events.Event
}

// newTargetFixture registers node1 and a running VM "web" on it with
// healthcheck hc and the given NICs, created long enough ago that it is out of
// its start grace — so a failed probe counts toward the healthcheck's action.
// The real probe transport is used (no SetProbeFunc).
func newTargetFixture(t *testing.T, hc *pb.HealthCheckSpec, ifaces ...corrosion.InterfaceRecord) *targetFixture {
	t.Helper()
	db := testVMDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "a", MemTotal: 8192,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Healthcheck: hc})
	for i := range ifaces {
		ifaces[i].VMName = "web"
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "web", HostName: "node1", Spec: string(spec), State: "running",
	}, ifaces, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'web'`, old); err != nil {
		t.Fatalf("backdate created_at: %v", err)
	}
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	bus := events.NewBus()
	ch, cancel := bus.Subscribe()
	t.Cleanup(cancel)
	v.SetEventBus(bus)
	return &targetFixture{t: t, ctx: ctx, db: db, v: v, events: ch}
}

func (f *targetFixture) health() VMHealth {
	f.t.Helper()
	vm, err := corrosion.GetVM(f.ctx, f.db, "web")
	if err != nil || vm == nil {
		f.t.Fatalf("GetVM: %v %v", vm, err)
	}
	h, err := EvaluateVMHealth(f.ctx, f.db, vm)
	if err != nil {
		f.t.Fatalf("EvaluateVMHealth: %v", err)
	}
	return h
}

// acted reports whether the healthcheck's action ran (or was attempted).
func (f *targetFixture) acted() bool {
	f.t.Helper()
	f.v.mu.Lock()
	n := f.v.actionCount["web"]
	f.v.mu.Unlock()
	for {
		select {
		case e := <-f.events:
			if e.Action == "vm.health.failed" && e.Target == "web" {
				return true
			}
		default:
			return n > 0
		}
	}
}

func hc(typ, target string) *pb.HealthCheckSpec {
	return &pb.HealthCheckSpec{Type: typ, Target: target, Interval: "1ms", Retries: 1, Action: "restart"}
}

func withIP(ip string) corrosion.InterfaceRecord {
	return corrosion.InterfaceRecord{NetworkName: "lan", Ordinal: 0, MAC: "52:54:00:aa:bb:01", IP: ip}
}

// The lab failure, exactly: `target: "22"` was dialled as an address on the
// host ("missing port in address"), never passed, and the default restart
// action restarted a healthy VM.
func TestVMProbe_BarePortProbesTheVMAddress(t *testing.T) {
	_, port := listenAsVM(t)
	f := newTargetFixture(t, hc("tcp", port), withIP(vmStandIn))
	f.v.SweepOnce(f.ctx)
	if h := f.health(); h.Verdict != VerdictHealthy {
		t.Fatalf("tcp %q against a VM listening on it: %+v, want healthy", port, h)
	}
	if f.acted() {
		t.Fatal("a VM whose probe passes had its healthcheck action run")
	}
}

// localhost in a target means the VM, not the host the checker runs on.
func TestVMProbe_LocalhostMeansTheVM(t *testing.T) {
	_, port := listenAsVM(t)
	for _, target := range []string{"localhost:" + port, "127.0.0.1:" + port, ":" + port} {
		t.Run(target, func(t *testing.T) {
			f := newTargetFixture(t, hc("tcp", target), withIP(vmStandIn))
			f.v.SweepOnce(f.ctx)
			if h := f.health(); h.Verdict != VerdictHealthy {
				t.Fatalf("tcp %q: %+v, want healthy (probed the host, not the VM?)", target, h)
			}
		})
	}
}

func TestVMProbe_HTTPLocalhostURLProbesTheVM(t *testing.T) {
	ln, err := net.Listen("tcp", vmStandIn+":0")
	if err != nil {
		t.Skipf("cannot bind %s: %v", vmStandIn, err)
	}
	var mu sync.Mutex
	var gotPath string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.RequestURI()
		mu.Unlock()
	}))
	srv.Listener.Close()
	srv.Listener = ln
	srv.Start()
	defer srv.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	assertHostLocalhostDoesNotAnswer(t, port)

	f := newTargetFixture(t, hc("http", "http://localhost:"+port+"/health?deep=1"), withIP(vmStandIn))
	f.v.SweepOnce(f.ctx)
	if h := f.health(); h.Verdict != VerdictHealthy {
		t.Fatalf("http localhost URL against a VM serving it: %+v, want healthy", h)
	}
	mu.Lock()
	defer mu.Unlock()
	if gotPath != "/health?deep=1" {
		t.Errorf("VM received request for %q, want /health?deep=1 (path and query kept)", gotPath)
	}
}

// With no address known for the VM the probe cannot be run. That is not a
// failure: the verdict says why and is "unknown" (so a vm_healthy wait keeps
// waiting and times out saying so), and the restart action never fires.
func TestVMProbe_NoAddressIsUnknownAndNeverActs(t *testing.T) {
	for name, ifaces := range map[string][]corrosion.InterfaceRecord{
		"no NIC":          nil,
		"NIC, no address": {withIP("")},
	} {
		t.Run(name, func(t *testing.T) {
			f := newTargetFixture(t, hc("tcp", "22"), ifaces...)
			f.v.SetNICIPDiscovery(func(string) string { return "" })
			for i := 0; i < 5; i++ { // retries is 1: any counted failure would act
				f.v.SweepOnce(f.ctx)
			}
			h := f.health()
			if h.Verdict != VerdictUnknown || h.Satisfied {
				t.Fatalf("VM with no address: %+v, want unknown and not satisfied", h)
			}
			if !strings.Contains(h.Detail, "no address known") {
				t.Errorf("detail %q does not say no address is known for the VM", h.Detail)
			}
			if f.acted() {
				t.Fatal("the healthcheck action ran for a VM whose probe could not be run (no address)")
			}
			f.v.mu.Lock()
			fails := f.v.failures["web"]
			f.v.mu.Unlock()
			if fails != 0 {
				t.Errorf("failures = %d for a probe that was never run, want 0", fails)
			}
		})
	}
}

// A NIC whose address is not recorded yet is looked up on the owner host by
// its MAC (ARP / dnsmasq leases in production).
func TestVMProbe_DiscoversTheAddressByMAC(t *testing.T) {
	_, port := listenAsVM(t)
	f := newTargetFixture(t, hc("tcp", port), withIP(""))
	var asked string
	f.v.SetNICIPDiscovery(func(mac string) string {
		asked = mac
		if mac == "52:54:00:aa:bb:01" {
			return vmStandIn
		}
		return ""
	})
	f.v.SweepOnce(f.ctx)
	if h := f.health(); h.Verdict != VerdictHealthy {
		t.Fatalf("address discovered by MAC: %+v, want healthy", h)
	}
	if asked != "52:54:00:aa:bb:01" {
		t.Errorf("discovery asked for MAC %q, want the NIC's", asked)
	}
}

// The recorded address — what `lv ls`, DNS and the LB use — wins over a live
// lookup.
func TestVMProbe_RecordedAddressWinsOverDiscovery(t *testing.T) {
	_, port := listenAsVM(t)
	f := newTargetFixture(t, hc("tcp", port), withIP(vmStandIn))
	f.v.SetNICIPDiscovery(func(string) string { return "127.0.0.9" })
	f.v.SweepOnce(f.ctx)
	if h := f.health(); h.Verdict != VerdictHealthy {
		t.Fatalf("recorded address should be probed: %+v", h)
	}
}

// An explicit host is probed as given, and needs no VM address at all.
func TestVMProbe_ExplicitHostIsUsedAsGiven(t *testing.T) {
	// Every loopback address means the VM, so an explicit host has to be a
	// non-loopback one, and no non-loopback listener is portable in a test:
	// the transport is scripted here, and sees the target it would dial.
	f := newTargetFixture(t, hc("tcp", "10.0.0.9:80")) // no NIC: no VM address
	var seen string
	f.v.SetProbeFunc(func(_ context.Context, _ corrosion.VMRecord, h *pb.HealthCheckSpec) (bool, string) {
		seen = h.Target
		return true, ""
	})
	f.v.SweepOnce(f.ctx)
	if seen != "10.0.0.9:80" {
		t.Fatalf("explicit target reached the transport as %q, want 10.0.0.9:80 unchanged", seen)
	}
	if h := f.health(); h.Verdict != VerdictHealthy {
		t.Fatalf("explicit target with no VM address: %+v, want healthy", h)
	}
}

// The scripted transport sees the RESOLVED target, which is what lets a fleet
// test drive target resolution.
func TestVMProbe_ProbeFuncSeesTheResolvedTarget(t *testing.T) {
	f := newTargetFixture(t, hc("http", "http://localhost:8080/health"), withIP("10.1.2.3"))
	var seen string
	f.v.SetProbeFunc(func(_ context.Context, _ corrosion.VMRecord, h *pb.HealthCheckSpec) (bool, string) {
		seen = h.Target
		return true, ""
	})
	f.v.SweepOnce(f.ctx)
	if seen != "http://10.1.2.3:8080/health" {
		t.Fatalf("transport saw %q, want http://10.1.2.3:8080/health", seen)
	}
}

// A stored target that cannot be interpreted (a VM created before validation,
// or through a path that does not validate) can never pass. It must not
// restart-loop the VM: it is reported, as unknown, and never acted on.
func TestVMProbe_UninterpretableTargetIsReportedNotActedOn(t *testing.T) {
	f := newTargetFixture(t, hc("tcp", "ssh"), withIP(vmStandIn))
	for i := 0; i < 3; i++ {
		f.v.SweepOnce(f.ctx)
	}
	h := f.health()
	if h.Verdict != VerdictUnknown {
		t.Fatalf("uninterpretable target: %+v, want unknown", h)
	}
	if !strings.Contains(h.Detail, `"ssh"`) {
		t.Errorf("detail %q does not name the bad target", h.Detail)
	}
	if f.acted() {
		t.Fatal("the healthcheck action ran for a target that cannot be probed")
	}
}

// A real failure against the VM's address still counts and still acts: the
// no-address rule must not have swallowed genuine failures.
func TestVMProbe_RealFailureAgainstTheVMStillActs(t *testing.T) {
	ln, port := listenAsVM(t)
	ln.Close() // the VM's port is closed: connection refused on 127.0.0.2
	f := newTargetFixture(t, hc("tcp", port), withIP(vmStandIn))
	f.v.SweepOnce(f.ctx)
	h := f.health()
	if h.Verdict != VerdictUnhealthy {
		t.Fatalf("closed port on the VM: %+v, want unhealthy", h)
	}
	if !strings.Contains(h.Detail, vmStandIn+":"+port) {
		t.Errorf("detail %q does not name the resolved address", h.Detail)
	}
	if !f.acted() {
		t.Fatal("a genuine probe failure outside grace did not run the healthcheck action")
	}
}

// A VM that loses its address across a restart must say so, not leave an
// older "unknown" (here: "the VM is stopped", from the previous incarnation)
// standing as the only explanation.
func TestVMProbe_NoAddressReplacesAnOlderUnknown(t *testing.T) {
	_, port := listenAsVM(t)
	f := newTargetFixture(t, hc("tcp", port), withIP(vmStandIn))
	f.v.SetNICIPDiscovery(func(string) string { return "" })
	f.v.SweepOnce(f.ctx)
	if h := f.health(); h.Verdict != VerdictHealthy {
		t.Fatalf("setup: %+v, want healthy", h)
	}
	if err := corrosion.UpdateVMState(f.ctx, f.db, "web", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx) // settles the verdict to unknown: the VM is stopped
	if err := corrosion.UpdateVMInterfaceIP(f.ctx, f.db, "web", "lan", ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := corrosion.UpdateVMStateStrict(f.ctx, f.db, "web", "running", "started"); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx)
	h := f.health()
	if h.Verdict != VerdictUnknown || !strings.Contains(h.Detail, "no address known") {
		t.Fatalf("restarted VM with no address: %+v, want unknown / no address known", h)
	}
	if f.acted() {
		t.Fatal("the healthcheck action ran for a VM with no address")
	}
}
