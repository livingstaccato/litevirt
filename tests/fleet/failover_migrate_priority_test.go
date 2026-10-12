// Fleet scenario: compose `migrate.priority` orders failover recovery.
//
// The value was parsed into the VM spec and stored, and nothing read it: the
// coordinator recovered a failed host's VMs in name order, so when survivors
// could hold only some of them, the ones that got capacity were whichever
// sorted first, whatever priority the operator gave them.
package fleet

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_FailoverPlacesHigherMigratePriorityFirst: d fails holding two
// VMs of the same size, and the survivors have room for exactly one of them.
// "aa-low" (priority 0) sorts first by name; "zz-high" (priority 100) must be
// the one recovered, and "aa-low" left on d, reported unplaceable — priority
// orders the work, it does not make room that is not there.
//
// A third VM, "mm-none", has no migrate section at all and the same priority
// as "aa-low" (the default 0); it is small enough to fit beside "zz-high"
// and must be recovered too, showing ties are still placed, not starved.
//
// It runs twice: on the legacy path, and with recovery claims enforced, where
// each reschedule is decided by a voter-majority certificate before its proof
// is written — priority must survive that path too, and the claim must still
// be what authorises the move (zz-high's proof carries a certificate).
//
// Mutation: drop the SortVMsByMigratePriority call in recoverWorkloads —
// both arms go red: "aa-low" takes the only room and "zz-high" stays on d.
func TestFleet_FailoverPlacesHigherMigratePriorityFirst(t *testing.T) {
	for _, tc := range []struct {
		name   string
		seed   int64
		claims bool
	}{
		{name: "legacy", seed: 4471},
		{name: "recovery-claims", seed: 4472, claims: true},
	} {
		t.Run(tc.name, func(t *testing.T) { failoverPriorityScenario(t, tc.seed, tc.claims) })
	}
}

func failoverPriorityScenario(t *testing.T, seed int64, claims bool) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: seed})
	a, b, p, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]

	// a can hold one 40 GiB VM (64 GiB less the default 5% / 1 GiB reserve
	// leaves ~62 GiB); b and p hold none.
	setHostCapacity(t, c, a.Name, 32, 65536)
	setHostCapacity(t, c, b.Name, 32, 1024)
	setHostCapacity(t, c, p.Name, 32, 1024)

	for _, vm := range []struct {
		name, spec string
		mem        int
	}{
		{"aa-low", `{"on_host_failure":"restart-any","migrate":{"priority":0}}`, 40000},
		{"mm-none", `{"on_host_failure":"restart-any"}`, 2048},
		{"zz-high", `{"on_host_failure":"restart-any","migrate":{"priority":100}}`, 40000},
	} {
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
			Name: vm.name, HostName: d.Name, Spec: vm.spec, State: "running",
			CPUActual: 2, MemActual: vm.mem,
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
	}
	c.WaitConverged(t, convergeTimeout)
	if claims {
		genesisByTick(t, c, a)
		enableRecoveryClaims(t, c)
	}
	c.Kill(d)

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	if claims {
		cs.ByNode[a.Name].Gate = quorateGate{}
	}
	for _, o := range []*Node{a, b, p} {
		PublishHealth(t, o, d.Name, streakSince(time.Minute), clock.Now())
	}
	c.WaitConverged(t, convergeTimeout, a, b, p)

	for i := 0; i < 3; i++ {
		cs.Tick(ctx, a)
		clock.Advance(contentionPoll)
		for _, o := range []*Node{a, b, p} {
			PublishHealth(t, o, d.Name, streakSince(time.Minute)+i+1, clock.Now())
		}
	}

	where := func() string {
		return fmt.Sprintf("aa-low=%s mm-none=%s zz-high=%s fences=%+v",
			vmOn(t, a, "aa-low").HostName, vmOn(t, a, "mm-none").HostName, vmOn(t, a, "zz-high").HostName, cs.Fences())
	}
	if len(cs.Fences()) == 0 {
		t.Fatalf("setup: %s was never fenced, so nothing was recovered: %s", d.Name, where())
	}
	if got := vmOn(t, a, "zz-high").HostName; got != a.Name {
		t.Fatalf("zz-high (migrate.priority 100) is on %s, want %s, the only host with room: "+
			"a lower-priority VM took the capacity first (%s)", got, a.Name, where())
	}
	if got := vmOn(t, a, "aa-low").HostName; got != d.Name {
		t.Fatalf("aa-low is on %s; there was room for only one 40 GiB VM and zz-high outranks it (%s)", got, where())
	}
	if skips := failoverSkips(t, a, "aa-low"); len(skips) != 1 {
		t.Fatalf("want one failover.skip for aa-low, which no survivor could hold, got %q (%s)", skips, where())
	}
	if got := vmOn(t, a, "mm-none").HostName; got != a.Name {
		t.Fatalf("mm-none (no migrate section, fits beside zz-high) is on %s, want %s (%s)", got, a.Name, where())
	}
	if claims {
		if pr, cert := pendingCert(t, a, "zz-high"); pr.DestHost != a.Name || cert.Key.Attempt != 0 {
			t.Fatalf("zz-high's certified proof sends it to %s at attempt %d, want %s at attempt 0", pr.DestHost, cert.Key.Attempt, a.Name)
		}
	}
}
