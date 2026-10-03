// Fleet scenarios: one unplaceable workload on a failed host must not strand
// the rest (kvm003 drill 6, main-8d1e56dc).
//
// placement.SelectBatch failed the WHOLE batch on one VM whose compose
// `placement.host` named a host that could not take it, and the coordinator
// then left every VM of the failed host where it was — every tick. On the lab
// pp4, still pinned to node-4 after drill 3 had recovered it elsewhere,
// stranded pp3 on node-3; s5, pinned to node-5, stranded o4 on node-4.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// pinnedVMSpec is a restart-any VM whose compose placement pins it to host.
func pinnedVMSpec(host string) string {
	return `{"on_host_failure":"restart-any","placement":{"host":"` + host + `"}}`
}

// failoverSkips returns the failover.skip audit details n holds for vm.
func failoverSkips(t *testing.T, n *Node, vm string) []string {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT detail FROM audit_log WHERE action = 'failover.skip' AND target = ?`, vm)
	if err != nil {
		t.Fatalf("%s: read audit_log: %v", n.Name, err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.String("detail"))
	}
	return out
}

// TestFleet_FailoverPlacesWhatItCanAroundAnUnplaceablePin: d fails holding
// "free" (no constraints) and "pinned", whose spec pins it to p. p cannot take
// it. "free" must be recovered, and "pinned" left on d with a failover.skip
// audit row naming it and the pin — once, not on every tick.
//
//   - pin-to-witness: p is a witness, which never hosts workloads.
//   - pin-to-down-host: p is fenced (the drill's case: node-4 was down).
//
// Mutation: restore the batch abort for a bad pin in placement.SelectBatch —
// both arms go red: "free" stays on d.
func TestFleet_FailoverPlacesWhatItCanAroundAnUnplaceablePin(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed int64
		// downPin: p is fenced rather than a witness.
		downPin bool
	}{
		{name: "pin-to-witness", seed: 3201},
		{name: "pin-to-down-host", seed: 3202, downPin: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: tc.seed})
			a, b, p, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
			insertVM(t, a, "free", d.Name)
			insertVMSpec(t, a, "pinned", d.Name, pinnedVMSpec(p.Name))
			c.WaitConverged(t, convergeTimeout)
			if tc.downPin {
				setHostState(t, c, p, "fenced")
			} else {
				// Through the RPC, so the write replicates in its ledgered shape.
				if _, err := c.SelfClient(a).ConfigureHost(ctx, &pb.ConfigureHostRequest{Name: p.Name, Role: "witness"}); err != nil {
					t.Fatalf("make %s a witness: %v", p.Name, err)
				}
				c.WaitConverged(t, convergeTimeout)
			}
			c.Kill(d)

			clock := NewVirtualClock(time.Now().UTC())
			cs := c.NewCoordinators(clock)
			for _, o := range []*Node{a, b, p} {
				PublishHealth(t, o, d.Name, streakSince(time.Minute), clock.Now())
			}
			c.WaitConverged(t, convergeTimeout, a, b)

			for i := 0; i < 3; i++ {
				cs.Tick(ctx, a)
				clock.Advance(contentionPoll)
				for _, o := range []*Node{a, b} {
					PublishHealth(t, o, d.Name, streakSince(time.Minute)+i+1, clock.Now())
				}
			}

			if got := vmOn(t, a, "free").HostName; got == d.Name {
				t.Fatalf("\"free\" is still on %s: one VM's unplaceable pin stranded every VM of the failed host", d.Name)
			}
			if got := vmOn(t, a, "pinned").HostName; got != d.Name {
				t.Fatalf("\"pinned\" moved to %s, a host its pin to %s does not allow", got, p.Name)
			}
			skips := failoverSkips(t, a, "pinned")
			if len(skips) != 1 || !strings.Contains(skips[0], p.Name) {
				t.Fatalf("want exactly one failover.skip for \"pinned\" naming its pin %s, got %q", p.Name, skips)
			}
			if skips := failoverSkips(t, a, "free"); len(skips) != 0 {
				t.Fatalf("\"free\" was reported unplaceable: %q", skips)
			}
		})
	}
}

// insertVMSpec is insertVM with an explicit spec.
func insertVMSpec(t *testing.T, n *Node, name, host, spec string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, Spec: spec, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s on %s: %v", name, n.Name, err)
	}
}
