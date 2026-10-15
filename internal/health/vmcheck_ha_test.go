package health

import (
	"encoding/json"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func disarmHA(t *testing.T, db *corrosion.Client) {
	t.Helper()
	db.SetClusterPolicyGate(func() bool { return true })
	if _, err := corrosion.SetHAPolicy(t.Context(), db, capabilities.GrantForTest(t, capabilities.FeatureHADisarm),
		corrosion.HADisarmed, "maintenance", "alice", ""); err != nil {
		t.Fatal(err)
	}
}

// While cluster HA is disarmed, a healthcheck's restart (and migrate) is
// downgraded to an alert, with an event saying so.
//
// Mutation: drop the downgrade — the VM is restarted and this goes red.
func TestVMCheck_HealthActionIsAnAlertWhileDisarmed(t *testing.T) {
	f := newGraceFixture(t, restartCheck)
	bus := events.NewBus()
	ch, unsub := bus.Subscribe()
	defer unsub()
	f.v.SetEventBus(bus)
	disarmHA(t, f.db)
	f.probe.set(false, "tcp 10.0.0.9:81: connection refused")

	f.v.SweepOnce(f.ctx)
	if n := f.starts(); n != 0 {
		t.Fatalf("a failing VM was restarted %d times while HA is disarmed", n)
	}
	seen := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for !(seen["vm.health.downgraded"] && seen["vm.health.alert"]) {
		select {
		case e := <-ch:
			seen[e.Action] = true
		case <-deadline:
			t.Fatalf("events %v, want vm.health.downgraded and vm.health.alert", seen)
		}
	}
}

// The restart POLICY still restarts a crashed VM on its own host.
func TestVMCheck_RestartPolicyRunsWhileDisarmed(t *testing.T) {
	db := testLogicDB(t)
	ctx := t.Context()
	disarmHA(t, db)
	spec, _ := json.Marshal(&pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "always", Delay: "0s"}})
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node1", Spec: string(spec),
		State: "error", StateDetail: crashedDetail}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.DefineStoppedDomain("web", "52:54:00:aa:bb:02")
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	v.virt = fake
	vm, _ := corrosion.GetVM(ctx, db, "web")
	v.maybeRestartVM(ctx, *vm, time.Now())
	started := false
	for _, e := range fake.EventLog() {
		if e.Op == "start" && e.Domain == "web" {
			started = true
		}
	}
	if !started {
		t.Fatal("the restart policy did not restart the crashed VM on its host while HA is disarmed")
	}
}
