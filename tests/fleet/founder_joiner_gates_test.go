// Fleet scenario: the gates a founder's half-admitted second host reaches.
//
// fix/founder-admits-second-host let a founder that has never had a peer
// vouch for its own joining host's admission and remove it
// (grpcapi.clusterOfOneBut). The other gates that let a replica that never
// caught up through only when it is alone still counted that joining row as a
// peer, so from `lv host add`'s admission until the new host's daemon booted —
// for good, when its setup failed — the founder refused every workload
// mutation and its reconciler's stop sync, and deferred its genesis firewall
// seeds. A host that is still joining has never booted on this admission: it
// has written nothing, so the founder's replica cannot be behind it.
//
// The lease mint keeps the refusal: a joining host is a voter, so the founder
// alone is no voter majority.
package fleet

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// halfAdmittedFounder is a founder whose `lv host add` of node-1 failed in
// setup, which leaves node-1 admitted (joining) and never booted.
func halfAdmittedFounder(t *testing.T, seed int64) (*Cluster, *Node, *Node, pb.LiteVirtClient) {
	t.Helper()
	ctx := context.Background()
	c, founder := newFounder(t, seed)
	operatorPKICopy(t, founder)
	m := newMachine(t, c, "node-1", "127.0.0.2")
	cl := c.SelfClient(founder)
	target := &cli.LocalAddTarget{Root: t.TempDir(), PKIDir: m.PKIDir, Binary: fakeBinary(t),
		FailSetup: errors.New("setup failed (fleet)")}
	t.Cleanup(cli.UseMachinesForTests(filepath.Join(t.TempDir(), "no-daemon-config.yaml"),
		map[string]*cli.LocalAddTarget{m.Address: target}))
	if err := cli.HostAddOn(ctx, cl, target, m.Name, m.Address); err == nil {
		t.Fatal("an add whose setup fails succeeded")
	}
	h, err := corrosion.GetHost(ctx, founder.DB, m.Name)
	if err != nil || h == nil || h.State != corrosion.HostStateJoining {
		t.Fatalf("the founder's row of %s = %+v (%v), want joining", m.Name, h, err)
	}
	if ok, _ := founder.DB.ReplicaCaughtUp(); ok {
		t.Fatal("fixture: the founder's replica is caught up; the gates below would not be asked")
	}
	return c, founder, m, cl
}

// TestFleet_FounderWithAJoiningHost: a founder holding its own half-admitted
// second host still mutates its workloads and records its genesis firewall
// seeds, and still mints no lease term. Every other peer — a gossip member, a
// host that has booted, any host that is not joining — still holds every gate.
//
// Mutations (internal/corrosion/cluster_of_one.go): drop the joining-host
// exception, and the workload, stop-sync and seed subtests go red; drop its
// gossip check, its state check, or let any other host through, and the
// matching negative goes red; give LeaseMintClearance the exception, and the
// lease subtest goes red.
func TestFleet_FounderWithAJoiningHost(t *testing.T) {
	ctx := context.Background()
	_, founder, m, cl := halfAdmittedFounder(t, 5201)
	founder.DB.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.InsertVM(ctx, founder.DB, corrosion.VMRecord{
		Name: "vm-a", HostName: founder.Name, State: "stopped", Spec: `{"name":"vm-a"}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	label := func(v string) error {
		_, err := cl.SetVMLabels(ctx, &pb.SetVMLabelsRequest{Name: "vm-a", Labels: map[string]string{"tier": v}})
		return err
	}
	trusted := func() (bool, string) {
		return corrosion.ReplicaTrusted(ctx, founder.DB, founder.Name, founder.DB.ReplicaCaughtUp)
	}
	seedEnforcement := func() (string, error) {
		return corrosion.SeedFirewallEnforcement(ctx, founder.DB, corrosion.FirewallEnforce, founder.Name)
	}
	seedSynflood := func() (bool, error) {
		return corrosion.SeedFirewallSynflood(ctx, founder.DB,
			capabilities.GrantForTest(t, capabilities.FeatureFirewallSynflood), founder.Name)
	}
	// stillGated: every gate holds, and no seed is written.
	stillGated := func(t *testing.T, what string) {
		t.Helper()
		if err := label("refused"); err == nil || !strings.Contains(err.Error(), "has not caught up") {
			t.Errorf("%s: a workload mutation = %v, want refused: the replica has not caught up", what, err)
		}
		if ok, _ := trusted(); ok {
			t.Errorf("%s: the replica is trusted (the reconciler's stop sync would publish from it)", what)
		}
		if mode, err := seedEnforcement(); err != nil || mode != "" {
			t.Errorf("%s: the enforcement seed wrote %q (%v), want nothing", what, mode, err)
		}
		if wrote, err := seedSynflood(); err != nil || wrote {
			t.Errorf("%s: the SYN-flood seed wrote (%v, %v), want nothing", what, wrote, err)
		}
	}

	t.Run("a gossip peer holds every gate", func(t *testing.T) {
		founder.DB.SetMembersForTests(func() []corrosion.PeerInfo {
			return []corrosion.PeerInfo{{Name: "node-9", Addr: "127.0.0.9:7946"}}
		})
		defer founder.DB.SetMembersForTests(func() []corrosion.PeerInfo { return nil })
		stillGated(t, "with a gossip peer")
	})
	// A joiner's first boot write records it 'upgrading' (hostboot), then
	// 'active' once its daemon serves.
	for _, state := range []string{"upgrading", "active"} {
		t.Run("a host whose daemon has booted holds every gate/"+state, func(t *testing.T) {
			if err := corrosion.UpdateHostState(ctx, founder.DB, m.Name, state); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := corrosion.UpdateHostState(ctx, founder.DB, m.Name, corrosion.HostStateJoining); err != nil {
					t.Fatal(err)
				}
			}()
			stillGated(t, "with "+m.Name+" "+state)
		})
	}
	t.Run("another host beside the joining one holds every gate", func(t *testing.T) {
		if err := corrosion.InsertHost(ctx, founder.DB, corrosion.HostRecord{
			Name: "node-2", Address: "127.0.0.3", State: "maintenance"}); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if _, err := founder.DB.DB().Exec(`DELETE FROM hosts WHERE name = 'node-2'`); err != nil {
				t.Fatal(err)
			}
		}()
		stillGated(t, "with node-2 in maintenance")
	})
	t.Run("the lease mint is still refused", func(t *testing.T) {
		ok, why := founder.Server.LeaseMintClearance(ctx, corrosion.LeaseMintRequest{
			Key: "failover", Term: 1 << 40, Holder: founder.Name, Takeover: true})
		if ok || !strings.Contains(why, "not caught up") {
			t.Fatalf("LeaseMintClearance = (%v, %q), want refused: %s is a voter, so %s alone is no majority",
				ok, why, m.Name, founder.Name)
		}
		// The refusal names the joining host and the way out of a failed add.
		for _, want := range []string{"only peers are " + m.Name, "still joining", "lv host rm " + m.Name} {
			if !strings.Contains(why, want) {
				t.Errorf("the lease refusal %q does not say %q", why, want)
			}
		}
	})

	t.Run("workload mutations are let through", func(t *testing.T) {
		if err := label("ok"); err != nil {
			t.Fatalf("a workload mutation on the founder with only %s joining: %v", m.Name, err)
		}
	})
	t.Run("the reconciler trusts the replica", func(t *testing.T) {
		if ok, why := trusted(); !ok {
			t.Fatalf("ReplicaTrusted with only %s joining: %s", m.Name, why)
		}
	})
	t.Run("the genesis firewall seeds are recorded", func(t *testing.T) {
		if mode, err := seedEnforcement(); err != nil || mode != corrosion.FirewallEnforce {
			t.Errorf("the enforcement seed = %q, %v; want enforce", mode, err)
		}
		if wrote, err := seedSynflood(); err != nil || !wrote {
			t.Errorf("the SYN-flood seed = %v, %v; want written", wrote, err)
		}
	})
}
