package fleet

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A healthcheck target is resolved against the VM's address before it is
// probed (the lab failure: `target: "22"` was dialled literally on the owner
// host, could never pass, and the default restart action restarted a healthy
// VM). This runs a real deploy, so the target travels the real path — compose
// file → validation → stored VM spec → the owner's VMChecker — and the
// scripted transport sees exactly what the real one would dial.

const composeDependsBarePort = `name: dep

images:
  test:
    source: file:///dev/null

vms:
  db:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    healthcheck:
      type: tcp
      target: "5432"
      interval: 1ms
      retries: 1
      action: restart
  app:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    depends-on:
      db:
        condition: vm_healthy
`

// targetProbe passes only a probe of want, and records every target it saw.
type targetProbe struct {
	mu   sync.Mutex
	want string
	seen []string
}

func (p *targetProbe) fn(_ context.Context, _ corrosion.VMRecord, hc *pb.HealthCheckSpec) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.seen = append(p.seen, hc.Target)
	if hc.Target == p.want {
		return true, ""
	}
	return false, "tcp " + hc.Target + ": connection refused"
}

func (p *targetProbe) targets() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func TestFleet_ComposeBarePortTargetProbesTheVMAddress(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(3 * time.Second)

	fp := startVMChecks(t, node)
	tp := &targetProbe{want: "10.1.2.3:5432"}
	fp.checker.SetProbeFunc(tp.fn)
	fp.checker.SetNICIPDiscovery(func(string) string { return "" }) // no ARP / leases on a test host

	// db has no NIC, so no address: its probe cannot run. The wait on it
	// times out SAYING so, and the transport is never called with a
	// target it could not dial.
	msgs := deployCollect(t, ctx, client, composeDependsBarePort)
	p := errorPhaseFor(msgs, "db") // the wait is reported against the VM waited on
	if p == nil {
		t.Fatalf("the vm_healthy wait on a db with no address did not fail; got %v", msgs)
	}
	if !strings.Contains(p.Error, "no address known") {
		t.Errorf("wait error %q does not say no address is known for db", p.Error)
	}
	if got := tp.targets(); len(got) != 0 {
		t.Errorf("the probe transport ran without an address, with targets %v", got)
	}
	db, err := corrosion.GetVM(ctx, node.DB, "db")
	if err != nil || db == nil || db.State != "running" {
		t.Fatalf("db = %+v err=%v, want running", db, err)
	}
	if h, _ := health.EvaluateVMHealth(ctx, node.DB, db); h.Verdict != health.VerdictUnknown {
		t.Errorf("db verdict with no address = %+v, want unknown", h)
	}

	// db gets an address. The bare port is now probed AT it and passes.
	if err := corrosion.InsertInterface(ctx, node.DB, corrosion.InterfaceRecord{
		VMName: "db", NetworkName: "lan", Ordinal: 0, MAC: "52:54:00:12:34:56", IP: "10.1.2.3",
	}); err != nil {
		t.Fatalf("give db an address: %v", err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		db, _ = corrosion.GetVM(ctx, node.DB, "db")
		h, herr := health.EvaluateVMHealth(ctx, node.DB, db)
		if herr == nil && h.Satisfied {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("db never became healthy once it had an address: %+v %v (targets seen %v)", h, herr, tp.targets())
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := tp.targets()
	if len(got) == 0 {
		t.Fatal("the probe never ran after db got an address")
	}
	for _, tg := range got {
		if tg != "10.1.2.3:5432" {
			t.Errorf("transport saw target %q, want 10.1.2.3:5432 (bare port resolved against db's address)", tg)
		}
	}
}

// A target the checker could not interpret is refused at deploy time, before
// any VM exists.
func TestFleet_ComposeUninterpretableHealthcheckTargetIsRefused(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	yaml := strings.Replace(composeDependsBarePort, `target: "5432"`, `target: "postgres"`, 1)
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err == nil {
		_, err = stream.Recv()
	}
	if err == nil || !strings.Contains(err.Error(), "vms.db.healthcheck.target") {
		t.Fatalf("deploy with tcp target %q: err=%v, want a healthcheck validation error", "postgres", err)
	}
	if db, _ := corrosion.GetVM(ctx, node.DB, "db"); db != nil {
		t.Errorf("db was created (state %s) from a file that failed validation", db.State)
	}
}
