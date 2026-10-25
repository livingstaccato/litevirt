package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// trustSSHPoweroffOn sets host's litevirt.trust_ssh_poweroff through by's
// SetHostLabels, as `lv host config --trust-ssh-poweroff` does, and waits for
// it to reach every node in wait (all of them when none is given).
func trustSSHPoweroffOn(t *testing.T, c *Cluster, by, host *Node, wait ...*Node) {
	t.Helper()
	if _, err := c.SelfClient(by).SetHostLabels(context.Background(), &pb.SetHostLabelsRequest{
		Name: host.Name, Labels: map[string]string{corrosion.LabelTrustSSHPoweroff: "true"}}); err != nil {
		t.Fatalf("trust a confirmed SSH power-off of %s: %v", host.Name, err)
	}
	c.WaitConverged(t, convergeTimeout, wait...)
}

// TestFleet_TrustSSHPoweroff: a coordinator's SSH power-off of node-2, which
// the remote shell confirmed over node-2's pinned key, does not recover
// node-2's VM by default: the VM stays on every replica and the stall alert
// names it and the way out. Once an operator sets the trust on ANOTHER node
// (the setting replicates, so every coordinator reads it), the next fence
// recovers it. With the trust on, a fence that reached a different machine
// (a host-key mismatch) still holds.
//
// Mutations: holdUntrustedSSH passes every confirmed power-off — the default
// case recovers, red; trustedSSH ignores the setting (never trusts) — the
// trusted case stays held, red. The mismatch case holds by construction: a
// host-key mismatch is never a success (fence's
// TestFenceSSH_HostKeyMismatchIsTheWrongHost pins that), and only a success is
// ever trusted.
func TestFleet_TrustSSHPoweroff(t *testing.T) {
	for _, tc := range []struct {
		name    string
		trust   bool
		result  fence.Result
		recover bool
	}{
		{"default holds", false, fence.Result{Method: "ssh", Success: true, Detail: "litevirt-fence-armed [path=managed]"}, false},
		{"trusted recovers", true, fence.Result{Method: "ssh", Success: true, Detail: "litevirt-fence-armed [path=managed]"}, true},
		{"trusted, host-key mismatch holds", true, fence.Result{Method: "ssh", WrongHost: true,
			Detail: "Host key verification failed. [path=managed] (the host key did not match: a different machine answered at this address)"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			clock := NewVirtualClock(time.Now().UTC())
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 2811})
			a, b, victim := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: victim.Name, FenceStrategy: "ssh"}); err != nil {
				t.Fatal(err)
			}
			insertVM(t, a, "vm-trust", victim.Name)
			c.WaitConverged(t, convergeTimeout)
			if tc.trust {
				trustSSHPoweroffOn(t, c, b, victim) // set on b, read by a's coordinator
				if h, _ := corrosion.GetHost(ctx, a.DB, victim.Name); h == nil || h.Labels[corrosion.LabelTrustSSHPoweroff] != "true" {
					t.Fatalf("the trust set on %s did not reach %s: %+v", b.Name, a.Name, h)
				}
			}
			c.Isolate(victim)
			runStart := clock.Now()
			PublishHealthRun(t, a, victim.Name, 5, runStart, clock.Now())
			PublishHealthRun(t, b, victim.Name, 5, runStart, clock.Now())
			c.WaitConverged(t, convergeTimeout, a, b)

			cs := c.NewCoordinators(clock)
			var reasons []string
			for _, n := range c.Nodes {
				cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result { return tc.result })
				cs.ByNode[n.Name].OnRecoveryStalled = func(host, _, reason string, _ int, _ time.Time) {
					if host == victim.Name {
						reasons = append(reasons, reason)
					}
				}
			}
			cs.Tick(ctx, a)
			for i := 0; i < 4; i++ {
				clock.Advance(20 * time.Second)
				now := clock.Now()
				PublishHealthRun(t, a, victim.Name, 6+i, runStart, now)
				PublishHealthRun(t, b, victim.Name, 6+i, runStart, now)
				c.WaitConverged(t, convergeTimeout, a, b)
				cs.Tick(ctx, a)
			}
			c.WaitConverged(t, convergeTimeout, a, b)
			for _, n := range []*Node{a, b} {
				vm := vmOn(t, n, "vm-trust")
				moved := vm != nil && vm.HostName != victim.Name
				if moved != tc.recover {
					t.Fatalf("vm-trust on %s's replica = %+v, want moved=%v", n.Name, vm, tc.recover)
				}
			}
			if tc.recover {
				return
			}
			if len(reasons) == 0 {
				t.Fatal("no stall alert named the held host")
			}
			last := reasons[len(reasons)-1]
			for _, want := range []string{"held: vm/vm-trust", "lv host fence-confirm " + victim.Name, "ipmi or redfish"} {
				if !strings.Contains(last, want) {
					t.Fatalf("stall reason %q does not name %q", last, want)
				}
			}
		})
	}
}
