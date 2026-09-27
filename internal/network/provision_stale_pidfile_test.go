package network

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fakeDnsmasq models the pidfiles on one host: present and alive per path.
// StartDHCP writes a live one; removing deletes it.
type fakeDnsmasq struct {
	present, alive map[string]bool
	starts         int
}

func installFakeDnsmasq(t *testing.T, stale ...string) *fakeDnsmasq {
	t.Helper()
	f := &fakeDnsmasq{present: map[string]bool{}, alive: map[string]bool{}}
	for _, p := range stale {
		f.present[p] = true
	}
	origState, origRemove, origStart, origExec := dnsmasqState, removePidFile, startDHCPFunc, execCommand
	dnsmasqState = func(p string) (bool, bool) { return f.present[p], f.alive[p] }
	removePidFile = func(p string) error { delete(f.present, p); delete(f.alive, p); return nil }
	startDHCPFunc = func(_, _, _, _, _, pidFile string) error {
		f.starts++
		f.present[pidFile], f.alive[pidFile] = true, true
		return nil
	}
	execCommand = func(string, ...string) ([]byte, error) { return nil, nil }
	t.Cleanup(func() {
		dnsmasqState, removePidFile, startDHCPFunc, execCommand = origState, origRemove, origStart, origExec
	})
	return f
}

// provisionedAfter is the network reconciler's question, asked with every
// interface present: does this host still need a provision pass?
func provisionedAfter(name string, def compose.NetworkDef) bool {
	return provisionedHere(name, def, hostProbe{
		ifaceExists: func(string) bool { return true },
		dnsmasq:     func(p string) (bool, bool) { return dnsmasqState(p) },
	})
}

// A dnsmasq litevirt ran on a bridge it created has died. On the next pass the
// bridge exists, so "the bridge pre-existed" reads true and — without the
// pidfile as the record that litevirt served DHCP there — Provision declined to
// serve, left the stale pidfile, and the reconciler re-provisioned forever.
// The pidfile is that record: Provision restarts dnsmasq, and the pass after
// has nothing to do.
func TestProvision_StalePidfileOnLitevirtBridgeRestartsDnsmasq(t *testing.T) {
	existing := testLoopbackInterface(t) // exists, so bridgePreExisted is true
	def := compose.NetworkDef{Type: "bridge", Interface: existing, Subnet: "10.0.5.0/24"}
	pid := dnsmasqPidFile(existing)
	f := installFakeDnsmasq(t, pid)
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if provisionedAfter("lan", def) {
		t.Fatal("setup: a dead dnsmasq must read as not provisioned")
	}
	if _, err := Provision(ctx, db, "lan", def, "10.0.0.1", "host1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if f.starts != 1 {
		t.Fatalf("Provision started dnsmasq %d times, want 1: litevirt served DHCP on this bridge, and its dnsmasq died", f.starts)
	}
	if !provisionedAfter("lan", def) {
		t.Fatal("after Provision the network still reads as not provisioned: the reconciler would re-provision every pass")
	}
}

// A bridge with no litevirt pidfile that already existed is an infrastructure
// bridge, and still gets no DHCP server it was never asked for.
func TestProvision_PreExistingBridgeWithoutPidfileStillGetsNoDnsmasq(t *testing.T) {
	existing := testLoopbackInterface(t)
	def := compose.NetworkDef{Type: "bridge", Interface: existing, Subnet: "10.0.5.0/24"}
	f := installFakeDnsmasq(t)
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Provision(ctx, db, "lan", def, "10.0.0.1", "host1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if f.starts != 0 {
		t.Fatalf("Provision started dnsmasq on a pre-existing bridge litevirt never served")
	}
}

// A vxlan host that ran dnsmasq as the gateway, then lost the election, has a
// dead dnsmasq's pidfile left. It must not serve, and must not keep reading as
// unprovisioned: it removes the stale pidfile, and the pass after has nothing
// to do.
func TestProvision_StalePidfileOnNonGatewayVXLANIsRemoved(t *testing.T) {
	def := compose.NetworkDef{Type: "vxlan", VNI: 43, Underlay: testLoopbackInterface(t), Subnet: "10.0.5.0/24"}
	pid := dnsmasqPidFileVNI(43)
	f := installFakeDnsmasq(t, pid)
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	// Sorts before "host1", so host1 is not the gateway.
	if err := UpsertVTEP(ctx, db, "ov", "aaa-peer", "10.9.9.9", 43); err != nil {
		t.Fatal(err)
	}
	if provisionedAfter("ov", def) {
		t.Fatal("setup: a dead dnsmasq must read as not provisioned")
	}
	if _, err := Provision(ctx, db, "ov", def, "10.0.0.1", "host1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if f.starts != 0 {
		t.Fatal("a non-gateway vxlan host started dnsmasq")
	}
	if f.present[pid] {
		t.Fatal("the dead dnsmasq's pidfile is still there")
	}
	if !provisionedAfter("ov", def) {
		t.Fatal("after Provision the network still reads as not provisioned: the reconciler would re-provision every pass")
	}
}

// Only a DEAD dnsmasq's pidfile is removed: a live one is not Provision's to
// orphan.
func TestProvision_LiveDnsmasqPidfileIsKept(t *testing.T) {
	def := compose.NetworkDef{Type: "vxlan", VNI: 44, Underlay: testLoopbackInterface(t), Subnet: "10.0.5.0/24"}
	pid := dnsmasqPidFileVNI(44)
	f := installFakeDnsmasq(t)
	f.present[pid], f.alive[pid] = true, true
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := UpsertVTEP(ctx, db, "ov", "aaa-peer", "10.9.9.9", 44); err != nil {
		t.Fatal(err)
	}
	if _, err := Provision(ctx, db, "ov", def, "10.0.0.1", "host1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if !f.present[pid] {
		t.Fatal("Provision removed a live dnsmasq's pidfile")
	}
}

// A flat bridge whose definition no longer serves DHCP (host isolation) has a
// dead dnsmasq's pidfile left: the same convergence, by removal.
func TestProvision_StalePidfileWhereDefinitionNoLongerServesIsRemoved(t *testing.T) {
	existing := testLoopbackInterface(t)
	def := compose.NetworkDef{Type: "bridge", Interface: existing, Subnet: "10.0.5.0/24", HostIsolation: true}
	pid := dnsmasqPidFile(existing)
	f := installFakeDnsmasq(t, pid)
	db := corrosion.NewTestClientT(t)
	ctx := context.Background()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if _, err := Provision(ctx, db, "lan", def, "10.0.0.1", "host1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if f.starts != 0 || f.present[pid] {
		t.Fatalf("starts=%d pidfile present=%v, want no dnsmasq and no pidfile", f.starts, f.present[pid])
	}
	if !provisionedAfter("lan", def) {
		t.Fatal("after Provision the network still reads as not provisioned")
	}
}
