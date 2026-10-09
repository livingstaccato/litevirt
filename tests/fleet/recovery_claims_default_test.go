package fleet

// Recovery claims on by default (colonelpanik/litevirt#250, D1): a cluster
// whose hosts' configs never mention enforcement.recovery_claim latches
// recovery_claim_v1 once genesis has run, and its two coordinators then
// cannot both recover one workload. One host with an explicit false keeps the
// token from latching anywhere, and recovery runs the pre-claim path.
//
// Every other recovery-claim scenario switches enforcement on by hand
// (enableRecoveryClaims) and fakes the latch. These two take the flag from
// daemon.LoadConfig, as the daemon does, and latch recovery_claim_v1 through
// a real health.Checker pinging every peer's real advertisement, so the
// default and the kill switch are what decide the outcome.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// configuredClaimsGate is claimsGate with recovery_claim_v1 answered by a real
// health.Checker: the token latches only when every voting member advertises
// it, which each does only while its own enforcement.recovery_claim is on.
// Every other token answers as claimsGate does (split_brain_gate_v1,
// voter_config_v1 and claim_incarnation_v1 are mandatory on this build).
type configuredClaimsGate struct {
	claimsGate
	chk *health.Checker
}

func (g configuredClaimsGate) Enforced(ctx context.Context, tok string) bool {
	if tok == capabilities.RecoveryClaimV1 {
		return g.chk.Enforced(ctx, tok)
	}
	return claimsLatched(tok)
}
func (g configuredClaimsGate) Latched(tok string) bool {
	if tok == capabilities.RecoveryClaimV1 {
		return g.chk.Latched(tok)
	}
	return claimsLatched(tok)
}
func (g configuredClaimsGate) DurablyLatched(tok string) bool {
	if tok == capabilities.RecoveryClaimV1 {
		return g.chk.DurablyLatched(tok)
	}
	return claimsLatched(tok)
}
func (g configuredClaimsGate) CapabilityActive(ctx context.Context, tok string) (bool, string) {
	if tok == capabilities.RecoveryClaimV1 {
		return g.chk.CapabilityActive(ctx, tok)
	}
	return claimsLatched(tok), ""
}
func (g configuredClaimsGate) CapabilityActiveForHealth(ctx context.Context, tok string) (bool, string) {
	if tok == capabilities.RecoveryClaimV1 {
		return g.chk.CapabilityActiveForHealth(ctx, tok)
	}
	return claimsLatched(tok), ""
}

// loadEnforcement is daemon.LoadConfig over a config holding host_name and
// the given enforcement text. Only the enforcement block is used.
func loadEnforcement(t *testing.T, n *Node, enforcement string) daemon.EnforcementConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("host_name: "+n.Name+"\n"+enforcement), 0o600); err != nil {
		t.Fatalf("write config for %s: %v", n.Name, err)
	}
	t.Setenv("LITEVIRT_CONFIG", path)
	cfg, err := daemon.LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig for %s: %v", n.Name, err)
	}
	return cfg.Enforcement
}

// configuredClaimFleet is claimFleet with enforcement taken from config:
// each node's enforcement block, keyed by its index in c.Nodes (none: no
// enforcement key at all), goes through
// LoadConfig, its flag is wired as the daemon wires it, genesis runs, and
// recovery_claim_v1 is left to latch, or not, on a real checker per node.
// The latch is driven while every node is up, then the victim is killed
// exactly as in claimFleet. It reports whether each node enforces claims.
func configuredClaimFleet(t *testing.T, clock *VirtualClock, seed int64, enforcement map[int]string,
	vms ...string) (c *Cluster, a, b, victim *Node, enforced map[string]bool) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: seed})
	a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, vm := range vms {
		insertVM(t, a, vm, victim.Name)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)

	checkers := map[string]*health.Checker{}
	for i, n := range c.Nodes {
		if err := mkdirAll(filepath.Dir(markerBase(c, n))); err != nil {
			t.Fatalf("mkdir markers for %s: %v", n.Name, err)
		}
		chk := health.NewChecker(n.Name, n.PKIDir, n.DB)
		chk.SetPeerPinger(n.Server.PeerCapabilities)
		chk.SetActivationMarker(markerBase(c, n))
		checkers[n.Name] = chk
		// The daemon's wiring (daemon.go): the flag, the certificate column's
		// emission gate on the durable latch, and the server gate.
		n.Server.SetRecoveryClaimEnforce(loadEnforcement(t, n, enforcement[i]).RecoveryClaim)
		n.DB.SetRecoveryClaimGate(func() bool { return chk.DurablyLatched(capabilities.RecoveryClaimV1) })
		n.DB.SetClaimIncarnationGate(func() bool { return true })
		n.Server.SetGate(configuredClaimsGate{chk: chk})
	}
	enforced = map[string]bool{}
	for _, n := range c.Nodes {
		enforced[n.Name] = n.Server.RecoveryClaimEnforced(ctx)
	}

	c.Kill(victim)
	c.SetLinkFaultBoth(a, b, slowLink)
	PublishHealth(t, a, victim.Name, 5, clock.Now())
	PublishHealth(t, b, victim.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)
	return c, a, b, victim, enforced
}

// TestFleet_TwoCoordinators_DefaultConfig_AtMostOneOwner: the #250 scenario
// (failover_two_coordinators_test.go) on a cluster configured the way a
// default install is — no enforcement.recovery_claim key on any host. The
// token latches, both coordinators tick inside one replication window, and
// the workload runs exactly once; the loser wrote no pending row and no proof
// naming itself.
//
// Mutation: drop RecoveryClaim from LoadConfig's preset — no node advertises
// recovery_claim_v1, nothing latches, and the scenario goes red (first on the
// latch, and without that assertion, on two running copies).
func TestFleet_TwoCoordinators_DefaultConfig_AtMostOneOwner(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _, enforced := configuredClaimFleet(t, clock, 2650, nil, "vm-victim")
	for name, on := range enforced {
		if !on {
			t.Fatalf("%s does not enforce recovery claims with no enforcement.recovery_claim key in its config "+
				"(recovery_claim_v1 did not latch): %v", name, enforced)
		}
	}

	for _, n := range []*Node{a, b} {
		if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{
			Name: "load-" + n.Name, HostName: n.Name, Spec: `{}`, State: "running",
			CPUActual: 16, MemActual: 65536,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM load on %s: %v", n.Name, err)
		}
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
	for _, n := range []*Node{a, b} {
		if err := corrosion.UpdateVMState(ctx, n.DB, "load-"+n.Name, "stopped", ""); err != nil {
			t.Fatalf("stop load on %s: %v", n.Name, err)
		}
	}

	cs := c.NewCoordinators(clock)
	for _, coord := range cs.ByNode {
		coord.Gate = quorateGate{}
	}
	cs.Tick(ctx, a, b)
	for _, n := range []*Node{a, b} {
		claimReconciler(t, n).ReconcileOnce(ctx)
	}

	var owners, views []string
	for _, n := range []*Node{a, b} {
		vm := vmOn(t, n, "vm-victim")
		state, _ := n.Virt.DomainState("vm-victim")
		views = append(views, fmt.Sprintf("%s: replica says host=%s state=%s proof=%q; libvirt=%q",
			n.Name, vm.HostName, vm.State, vm.PendingActionID, state))
		if state == string(libvirtfake.StateRunning) {
			owners = append(owners, n.Name)
		}
	}
	detail := fmt.Sprintf("fences=%+v\n  %s", cs.Fences(), strings.Join(views, "\n  "))
	if len(owners) != 1 {
		t.Fatalf("%d writable owners of vm-victim (%s) on a default-config cluster, want exactly one\n  %s",
			len(owners), strings.Join(owners, ", "), detail)
	}
	loser := a
	if owners[0] == a.Name {
		loser = b
	}
	if vm := vmOn(t, loser, "vm-victim"); vm.HostName == loser.Name {
		t.Errorf("the loser %s's replica points vm-victim at itself: %+v\n  %s", loser.Name, vm, detail)
	}
	if ids := proofsNaming(t, loser, "vm-victim", loser.Name); len(ids) != 0 {
		t.Errorf("the loser %s holds proof(s) naming itself as the destination: %v\n  %s", loser.Name, ids, detail)
	}
}

// TestFleet_RecoveryClaim_ExplicitFalseOnOneHostKeepsTheLegacyPath: the kill
// switch survives the new default. One host says
// `enforcement.recovery_claim: false`; it withholds recovery_claim_v1, so the
// token latches nowhere, no node enforces claims, and a failed host's VM is
// recovered exactly as before claims — an uncertified proof, run once.
//
// Mutation: make LoadConfig's preset override an explicit false — the token
// latches on every node and the first assertion goes red.
func TestFleet_RecoveryClaim_ExplicitFalseOnOneHostKeepsTheLegacyPath(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	// b, a survivor, opts out.
	c, a, b, _, enforced := configuredClaimFleet(t, clock, 2651, map[int]string{
		1: "enforcement:\n  recovery_claim: false\n",
	}, "vm-legacy")
	for name, on := range enforced {
		if on {
			t.Fatalf("%s enforces recovery claims although %s set enforcement.recovery_claim: false: %v",
				name, b.Name, enforced)
		}
	}

	cs := c.NewCoordinators(clock)
	coord := cs.ByNode[a.Name]
	coord.Gate = quorateGate{}
	cs.Tick(ctx, a)
	vm := vmOn(t, a, "vm-legacy")
	if vm.PendingActionID == "" {
		t.Fatalf("the coordinator minted no reschedule with claims off: %+v", vm)
	}
	pr, ok, err := corrosion.GetActionProof(ctx, a.DB, vm.PendingActionID)
	if err != nil || !ok || pr.ClaimCertificate != "" {
		t.Fatalf("want an uncertified proof on the legacy path, got %+v ok=%v err=%v", pr, ok, err)
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	for _, n := range []*Node{a, b} {
		claimReconciler(t, n).ReconcileOnce(ctx)
	}
	var running []string
	for _, n := range []*Node{a, b} {
		if st, _ := n.Virt.DomainState("vm-legacy"); st == string(libvirtfake.StateRunning) {
			running = append(running, n.Name)
		}
	}
	if len(running) != 1 || running[0] != pr.DestHost {
		t.Fatalf("vm-legacy runs on %v, want exactly once on %s", running, pr.DestHost)
	}
}
