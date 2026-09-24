package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A blue-green update creates <vm>-green, then deletes the old (blue) VM. The
// delete's error used to be discarded and the VM reported "cutover complete",
// so a blue that was never removed — still running, still holding its disks —
// left the stack reading as fully converged.

const composeBlueGreen = `name: hb

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
      strategy: blue-green
`

func TestFleet_ComposeBlueGreenFailedBlueDeleteLeavesStackDegraded(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	if msgs, err := deployRolling(t, ctx, client, composeBlueGreen, 20*time.Second); err != nil {
		t.Fatalf("setup deploy: %v (%v)", err, msgs)
	}

	barVMDelete(t, ctx, node.DB, "hb-1")
	msgs, err := deployRolling(t, ctx, client, rollingUpdateOf(composeBlueGreen), 20*time.Second)
	if err != nil {
		// The green side is serving: this is not a failed cutover.
		t.Fatalf("blue-green update ended the stream with an error: %v (%v)", err, msgs)
	}
	sawRolling := false
	for _, p := range msgs {
		if p.Phase == "rolling-update" {
			sawRolling = true
		}
		if p.Phase == "done" && p.Detail == "cutover complete" {
			t.Errorf("%s reported cutover complete although the blue hb-1 was not removed", p.VmName)
		}
	}
	if !sawRolling {
		t.Fatalf("deploy did not take the rolling path; got %v", msgs)
	}
	p := errorPhaseFor(msgs, "hb-1")
	if p == nil {
		t.Fatalf("failed delete of the blue hb-1 sent no error phase; got %v", msgs)
	}
	if !strings.Contains(p.Error, "operation is in progress") {
		t.Errorf("error phase for hb-1 = %q, want the delete failure", p.Error)
	}

	if vm, err := corrosion.GetVM(ctx, node.DB, "hb-1-green"); err != nil || vm == nil {
		t.Fatalf("the green hb-1-green is not there: vm=%v err=%v", vm, err)
	}
	if vm, err := corrosion.GetVM(ctx, node.DB, "hb-1"); err != nil || vm == nil {
		t.Fatalf("the blue hb-1 row is gone although its delete was refused: vm=%v err=%v", vm, err)
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "degraded" {
		t.Errorf("stack state after a blue that was not removed = %q, want degraded", got)
	}
	if res, detail := lastAuditResult(t, ctx, node.DB, "stack.deploy", "hb"); res != "error" {
		t.Errorf("stack.deploy audit result = %q (%s), want error", res, detail)
	} else if !strings.Contains(detail, "hb-1") {
		t.Errorf("stack.deploy audit detail %q does not name the VM whose blue was not removed", detail)
	}
}
