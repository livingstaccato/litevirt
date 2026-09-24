package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The rolling strategy recreates each VM and then waits `health-wait` for it
// to be healthy before moving on. That wait used to ask waitForCondition for a
// condition it did not know ("healthy:<dur>"), so it matched nothing, ignored
// health-wait, and spun the default five minutes before failing — every rolling
// update of a perfectly healthy VM failed.

const composeRolling = `name: hb

images:
  test:
    source: file:///dev/null

vms:
  hb-1:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
    update:
      strategy: rolling
      health-wait: 2s
`

// deployRolling runs a deploy and returns every progress message plus the
// stream's terminal error (nil on a clean end). A failed rolling update ends
// the stream with an error, unlike a per-action failure.
func deployRolling(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string, budget time.Duration) ([]*pb.DeployProgress, error) {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err != nil {
		t.Fatalf("DeployStack: %v", err)
	}
	var out []*pb.DeployProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		out = append(out, p)
	}
}

func rollingUpdateOf(yaml string) string {
	return strings.Replace(yaml, "    cpu: 1\n", "    cpu: 2\n", 1)
}

func TestFleet_ComposeRollingUpdateOfHealthyVMCompletes(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	if msgs, err := deployRolling(t, ctx, client, composeRolling, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}

	start := time.Now()
	msgs, err := deployRolling(t, ctx, client, rollingUpdateOf(composeRolling), 20*time.Second)
	if err != nil {
		t.Fatalf("rolling update of a healthy VM failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
	}
	sawRolling, sawDone := false, false
	for _, p := range msgs {
		if p.Phase == "rolling-update" {
			sawRolling = true
		}
		if p.Phase == "error" {
			t.Errorf("error phase during a healthy rolling update: %s %s", p.VmName, p.Error)
		}
		if p.Phase == "done" && p.VmName == "hb-1" {
			sawDone = true
		}
	}
	if !sawRolling {
		t.Fatalf("deploy did not take the rolling path; got %v", msgs)
	}
	if !sawDone {
		t.Errorf("hb-1 never reported done; got %v", msgs)
	}
	// Promptly: the VM is running as soon as it is recreated, so the wait must
	// not come near health-wait, let alone the old five-minute default.
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("rolling update of a healthy VM took %s", d)
	}
	vm, gerr := corrosion.GetVM(ctx, node.DB, "hb-1")
	if gerr != nil || vm == nil {
		t.Fatalf("hb-1 missing after the update: vm=%v err=%v", vm, gerr)
	}
	if !strings.Contains(vm.Spec, `"cpu":2`) {
		t.Errorf("hb-1 was not updated: spec %s", vm.Spec)
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "active" {
		t.Errorf("stack state after a clean rolling update = %q, want active", got)
	}
}

func TestFleet_ComposeRollingUpdateOfNeverHealthyVMFailsWithinHealthWait(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	if msgs, err := deployRolling(t, ctx, client, composeRolling, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}

	// The recreated hb-1 comes up reported unhealthy and stays that way — the
	// one signal the vm_healthy condition refuses on besides "not running".
	if err := node.DB.Execute(ctx, `CREATE TRIGGER test_hb1_never_healthy AFTER INSERT ON vms
		WHEN NEW.name = 'hb-1'
		BEGIN UPDATE vms SET state_detail = 'unhealthy' WHERE name = NEW.name; END`); err != nil {
		t.Fatalf("install never-healthy trigger: %v", err)
	}

	start := time.Now()
	msgs, err := deployRolling(t, ctx, client, rollingUpdateOf(composeRolling), 20*time.Second)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("rolling update of a VM that never became healthy succeeded; got %v", msgs)
	}
	if strings.Contains(err.Error(), "DeadlineExceeded") || ctx.Err() != nil {
		t.Fatalf("rolling update hung until the client gave up: %v", err)
	}
	// Bounded by health-wait (2s) plus one poll interval, not the old default.
	if elapsed > 8*time.Second {
		t.Errorf("failed health wait took %s; health-wait is 2s", elapsed)
	}
	for _, want := range []string{"hb-1", "health", "2s"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("deploy error %q does not mention %q", err, want)
		}
	}
	p := errorPhaseFor(msgs, "hb-1")
	if p == nil {
		t.Fatalf("no error phase for hb-1; got %v", msgs)
	}
	if !strings.Contains(p.Error, "healthy") {
		t.Errorf("hb-1 error phase %q does not say it never became healthy", p.Error)
	}
}
