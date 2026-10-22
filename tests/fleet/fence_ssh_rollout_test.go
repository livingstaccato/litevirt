package fleet

import (
	"context"
	"slices"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/daemon"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/fencessh"
)

func fenceSSHUsedOn(t *testing.T, n *Node) bool {
	return featureUsedOn(t, n, capabilities.Release202612V1, string(capabilities.FeatureFenceSSH))
}

// TestFleet_FenceSSH_LegacyEverywhereKeepsTheReleaseUnused: with
// enforcement.fence_ssh: legacy on every host, release_2026_12_v1 latches but
// no host publishes a row, so fence_ssh stays unused and a rollback below the
// release stays possible; every fence takes the legacy path, unpinned, as
// before. Once one host leaves legacy and publishes, a legacy host fences it
// pinned.
//
// Mutation: let legacy mode publish (sync) — the feature is used, red.
func TestFleet_FenceSSH_LegacyEverywhereKeepsTheReleaseUnused(t *testing.T) {
	ctx := context.Background()
	modes := map[string]string{"node-0": fencessh.ModeLegacy, "node-1": fencessh.ModeLegacy, "node-2": fencessh.ModeLegacy}
	c, fs := fenceSSHFleetWith(t, 3, 2621, func(string) bool { return true }, func(n string) string { return modes[n] })
	publishAndRender(t, c, fs)
	for _, n := range c.Nodes {
		if fenceSSHUsedOn(t, n) {
			t.Fatalf("%s: fence_ssh is used although every host is on legacy", n.Name)
		}
		if rows, _ := corrosion.ListHostFenceSSH(ctx, n.DB); len(rows) != 0 {
			t.Fatalf("%s holds %d fence ssh rows", n.Name, len(rows))
		}
		if q := daemon.BootRollbackCheck(ctx, t.TempDir(), n.DB); len(q) != 0 {
			t.Fatalf("%s: a rollback check quarantines %v with nothing used", n.Name, q)
		}
	}
	if sf := fs["node-0"].agent.FenceConfig(ctx, "node-2"); sf.Refusal != "" || sf.Path != fence.SSHPathLegacy {
		t.Fatalf("legacy fence of node-2 = %+v, want the legacy path", sf)
	}
	modes["node-2"] = fencessh.ModeAuto
	publishAndRender(t, c, fs)
	if sf := fs["node-0"].agent.FenceConfig(ctx, "node-2"); sf.Refusal != "" || sf.Path != fence.SSHPathPinned {
		t.Fatalf("legacy fence of a host that published = %+v, want pinned", sf)
	}
}

// TestFleet_FenceSSH_AnOldNodeHoldsTheReleaseOff: one host still on the
// previous build (modelled as one advertising nothing, as an older or
// quarantined node does to this token): release_2026_12_v1 does not latch, no
// host publishes, nothing is used, and every fence takes the legacy path,
// unpinned, exactly as before the upgrade.
func TestFleet_FenceSSH_AnOldNodeHoldsTheReleaseOff(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2622,
		HostCertIPs: []string{fenceSSHIP(0), fenceSSHIP(1), fenceSSHIP(2)}})
	gates := gateAll(t, c)
	wireReleaseFeatures(t, c, gates)
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.FailoverScopeV1) {
			t.Fatalf("%s: failover_scope_v1 did not latch", n.Name)
		}
	}
	old := c.Nodes[2]
	old.Server.SetWALQuarantined(func() bool { return true })
	fs := map[string]*fenceSSHNode{}
	for i, n := range c.Nodes[:2] {
		if gates[n.Name].Enforced(ctx, capabilities.Release202612V1) {
			t.Fatalf("%s: release_2026_12_v1 latched across %s, which runs the previous build", n.Name, old.Name)
		}
		fs[n.Name] = newFenceSSHNode(t, n, fenceSSHIP(i), func(string) bool { return true },
			func(string) string { return fencessh.ModeAuto })
	}
	syncAll(t, fs["node-0"], fs["node-1"])
	c.WaitConverged(t, convergeTimeout, c.Nodes[0], c.Nodes[1])
	syncAll(t, fs["node-0"], fs["node-1"])
	for _, n := range c.Nodes[:2] {
		if fenceSSHUsedOn(t, n) {
			t.Fatalf("%s: fence_ssh used before the release latched", n.Name)
		}
		if rows, _ := corrosion.ListHostFenceSSH(ctx, n.DB); len(rows) != 0 {
			t.Fatalf("%s holds %d fence ssh rows before the release latched", n.Name, len(rows))
		}
	}
	for _, target := range []string{"node-1", "node-2"} {
		if sf := fs["node-0"].agent.FenceConfig(ctx, target); sf.Refusal != "" || sf.Path != fence.SSHPathLegacy {
			t.Fatalf("fence of %s mid-roll = %+v, want the legacy path, unpinned", target, sf)
		}
	}
}

// TestFleet_FenceSSH_ReadmittedHostStartsAgain: node-3 accepted the managed
// key, is removed with `lv host rm --dead`, and its machine is rebuilt and
// admitted again under the same name with a new certificate. The removal
// retired its row everywhere; the new machine's first row, whose sshd does
// not accept the key, carries no ever_accepting from the machine before it,
// so its peers fence it pinned, not over a managed key it never accepted.
func TestFleet_FenceSSH_ReadmittedHostStartsAgain(t *testing.T) {
	ctx := context.Background()
	c, fs, gates := fenceSSHFleetGates(t, 4, 2623)
	publishAndRender(t, c, fs)
	a, d := c.Nodes[0], c.Nodes[3]
	if r, ok, _ := corrosion.GetHostFenceSSH(ctx, a.DB, d.Name); !ok || !r.EverAccepting {
		t.Fatalf("fixture: %s's row on %s = %+v", d.Name, a.Name, r)
	}
	genesisByTick(t, c, a)
	enableRecoveryClaims(t, c)
	c.Kill(d)
	if err := corrosion.InsertFenceLog(ctx, a.DB, corrosion.FenceLogRecord{ID: "confirm-" + d.Name, HostName: d.Name,
		Method: "manual", Result: "manual-confirmed", Detail: "operator powered it off"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatal(err)
	}
	withOperatorPKI(t, a)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	survivors := c.Nodes[:3]
	eventually(t, convergeTimeout, "the removal to retire node-3's row on every survivor", func() bool {
		for _, n := range survivors {
			r, ok, err := corrosion.GetHostFenceSSH(ctx, n.DB, d.Name)
			if err != nil || !ok || !r.Deleted {
				return false
			}
		}
		return true
	})

	serial := rebuildWithEmptyDB(t, c, d, a)
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{Name: d.Name, Address: d.Address, CertSerial: serial}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}
	bootRebuiltNode(t, d, serial)
	convergeByAntiEntropy(t, c, 2*convergeTimeout)
	// The rebuilt daemon's release gate, as the daemon wires it.
	g := gateFor(t, c, d)
	gates[d.Name] = g
	d.DB.SetClusterPolicyGate(func() bool { return g.DurablyLatched(capabilities.FailoverScopeV1) })
	g.SetReleaseUseConfirmer(d.Server.PeerHoldsReleaseFeatureUse)
	d.Server.SetReleaseFeatureGate(g)
	for _, tok := range []string{capabilities.FailoverScopeV1, capabilities.Release202612V1} {
		eventually(t, convergeTimeout, d.Name+" to latch "+tok, func() bool { return g.Enforced(ctx, tok) })
	}
	nd := newFenceSSHNode(t, d, fenceSSHIP(3), func(string) bool { return false }, func(string) string { return fencessh.ModeAuto })
	syncAll(t, nd)
	eventually(t, convergeTimeout, "the new machine's row to reach "+a.Name, func() bool {
		r, ok, err := corrosion.GetHostFenceSSH(ctx, a.DB, d.Name)
		return err == nil && ok && !r.Deleted && r.FencePubkeys == nd.ownKey(t)
	})
	r, _, _ := corrosion.GetHostFenceSSH(ctx, a.DB, d.Name)
	if r.EverAccepting || r.Accepting {
		t.Fatalf("the re-admitted machine's row = accepting %v ever %v, want neither", r.Accepting, r.EverAccepting)
	}
	if sf := fs[a.Name].agent.FenceConfig(ctx, d.Name); sf.Refusal != "" || sf.Path != fence.SSHPathPinned {
		t.Fatalf("fence of the re-admitted %s = %+v, want pinned", d.Name, sf)
	}
}

// TestFleet_FenceSSH_RollbackBelowAfterUseQuarantines: once every host has
// published, fence_ssh is used, and a host rolled back to a build that cannot
// keep its data quarantines at boot rather than run over rows it would drop.
// Modelled with this binary declaring no fence_ssh (a build of the release
// from before the feature; the rule a build below the token follows is the
// same use record).
func TestFleet_FenceSSH_RollbackBelowAfterUseQuarantines(t *testing.T) {
	ctx := context.Background()
	c, fs := fenceSSHFleet(t, 3, 2624)
	publishAndRender(t, c, fs)
	n := c.Nodes[1]
	if !fenceSSHUsedOn(t, n) {
		t.Fatal("fixture: fence_ssh is not used after every host published")
	}
	set := map[capabilities.Feature]capabilities.FeatureInfo{}
	for _, f := range capabilities.Features() {
		if f != capabilities.FeatureFenceSSH {
			info, _ := capabilities.LookupFeature(f)
			set[f] = info
		}
	}
	restore := capabilities.OverrideFeaturesForTest(set)
	q := daemon.BootRollbackCheck(ctx, t.TempDir(), n.DB)
	restore()
	if !slices.ContainsFunc(q, func(s string) bool { return strings.Contains(s, "release_2026_12_v1") }) {
		t.Fatalf("a rollback that cannot keep fence_ssh quarantines %v, want release_2026_12_v1", q)
	}
}
