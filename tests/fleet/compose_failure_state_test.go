package fleet

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// These scenarios drive the real DeployStack RPC against an in-process node and
// inject a per-VM failure through the libvirt fake. A per-action failure is
// reported as an "error" progress message and the stream still ends OK, so the
// only durable evidence of it is the stack record and the audit row — which
// must not claim the stack is "active" / the deploy "ok" when it is not.

const composeFailOne = `name: hb

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
`

const composeFailTwo = `name: hb

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
  hb-2:
    image: test
    cpu: 1
    memory: 512
    placement:
      host: node-0
`

func newComposeFailNode(t *testing.T) (*Cluster, *Node, pb.LiteVirtClient) {
	t.Helper()
	c := New(t, Options{Nodes: 1})
	node := c.Nodes[0]
	ctx := context.Background()
	if err := node.DB.Execute(ctx,
		`INSERT INTO images (name, format, source_url, checksum, size_bytes, created_at, updated_at)
		 VALUES ('test', 'qcow2', 'file:///dev/null', 'deadbeef', 1024, datetime('now'), datetime('now'))`); err != nil {
		t.Fatalf("seed image: %v", err)
	}
	if err := writeEmptyImageFile(node.Server.ImagePathForTests("test")); err != nil {
		t.Fatalf("stage image file: %v", err)
	}
	return c, node, c.SelfClient(node)
}

// deployCollect runs a real (non-dry-run) deploy and returns every progress
// message. The stream must end OK: per-action failures are reported in-band.
func deployCollect(t *testing.T, ctx context.Context, client pb.LiteVirtClient, yaml string) []*pb.DeployProgress {
	t.Helper()
	dctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	stream, err := client.DeployStack(dctx, &pb.DeployStackRequest{ComposeYaml: yaml})
	if err != nil {
		t.Fatalf("DeployStack: %v", err)
	}
	var out []*pb.DeployProgress
	for {
		p, err := stream.Recv()
		if err == io.EOF {
			return out
		}
		if err != nil {
			t.Fatalf("DeployStack stream: %v", err)
		}
		out = append(out, p)
	}
}

func errorPhaseFor(msgs []*pb.DeployProgress, vm string) *pb.DeployProgress {
	for _, p := range msgs {
		if p.Phase == "error" && p.VmName == vm {
			return p
		}
	}
	return nil
}

func stackState(t *testing.T, ctx context.Context, db *corrosion.Client, name string) string {
	t.Helper()
	st, err := corrosion.GetStack(ctx, db, name)
	if err != nil {
		t.Fatalf("GetStack(%s): %v", name, err)
	}
	if st == nil {
		t.Fatalf("stack %q has no record", name)
	}
	return st.State
}

// lastAuditResult returns the result of the newest audit row for action/target.
func lastAuditResult(t *testing.T, ctx context.Context, db *corrosion.Client, action, target string) (result, detail string) {
	t.Helper()
	rows, err := db.Query(ctx,
		`SELECT result, detail FROM audit_log WHERE action = ? AND target = ? ORDER BY timestamp DESC, rowid DESC LIMIT 1`,
		action, target)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if len(rows) == 0 {
		t.Fatalf("no %s audit row for %q", action, target)
	}
	return rows[0].String("result"), rows[0].String("detail")
}

// barVMDelete makes DeleteVM refuse vm the way it does for real: an in-flight
// operation holds the VM-wide mutation barrier. (A libvirt undefine failure is
// not a usable injection — DeleteVM logs it and carries on.)
func barVMDelete(t *testing.T, ctx context.Context, db *corrosion.Client, vm string) {
	t.Helper()
	if err := db.Execute(ctx, `UPDATE vms SET active_operation_id = 'op-injected' WHERE name = ?`, vm); err != nil {
		t.Fatalf("set mutation barrier on %s: %v", vm, err)
	}
}

// A deploy whose only create is refused must not be recorded as an active
// stack or audited "ok" — and re-running it once the cause is gone must retry
// the create rather than read the stack as up to date.
func TestFleet_ComposeFailedCreateLeavesStackDegradedAndRetries(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	node.Virt.FailDefineDomain = func(string) error { return errors.New("injected: define refused") }
	msgs := deployCollect(t, ctx, client, composeFailOne)
	if errorPhaseFor(msgs, "hb-1") == nil {
		t.Fatalf("no error phase for hb-1; got %v", msgs)
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "degraded" {
		t.Errorf("stack state after a failed create = %q, want %q", got, "degraded")
	}
	if res, detail := lastAuditResult(t, ctx, node.DB, "stack.deploy", "hb"); res != "error" {
		t.Errorf("stack.deploy audit result = %q (%s), want %q", res, detail, "error")
	} else if !strings.Contains(detail, "hb-1") {
		t.Errorf("stack.deploy audit detail %q does not name the failed VM", detail)
	}

	// The cause is fixed: the next plan must still create hb-1.
	node.Virt.FailDefineDomain = nil
	planned := false
	for _, op := range dryRunPlan(t, ctx, client, composeFailOne) {
		if op.VmName == "hb-1" && op.Phase == string(compose.OpCreate) {
			planned = true
		}
	}
	if !planned {
		t.Fatal("re-run after a failed create did not plan the create again")
	}
	msgs = deployCollect(t, ctx, client, composeFailOne)
	if p := errorPhaseFor(msgs, "hb-1"); p != nil {
		t.Fatalf("retry deploy failed: %s", p.Error)
	}
	if vm, err := corrosion.GetVM(ctx, node.DB, "hb-1"); err != nil || vm == nil {
		t.Fatalf("hb-1 not created by the retry: vm=%v err=%v", vm, err)
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "active" {
		t.Errorf("stack state after a clean retry = %q, want %q", got, "active")
	}
	if res, _ := lastAuditResult(t, ctx, node.DB, "stack.deploy", "hb"); res != "ok" {
		t.Errorf("stack.deploy audit result after a clean retry = %q, want ok", res)
	}
}

// A scale-down delete that fails used to be a slog.Warn followed by "done", so
// neither the CLI nor the stack record could see it.
func TestFleet_ComposeFailedScaleDownDeleteIsReported(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	msgs := deployCollect(t, ctx, client, composeFailTwo)
	for _, vm := range []string{"hb-1", "hb-2"} {
		if p := errorPhaseFor(msgs, vm); p != nil {
			t.Fatalf("setup deploy failed for %s: %s", vm, p.Error)
		}
	}

	barVMDelete(t, ctx, node.DB, "hb-2")
	msgs = deployCollect(t, ctx, client, composeFailOne)
	if errorPhaseFor(msgs, "hb-2") == nil {
		t.Fatalf("failed scale-down delete of hb-2 sent no error phase; got %v", msgs)
	}
	for _, p := range msgs {
		if p.Phase == "done" && p.VmName == "hb-2" {
			t.Error("failed delete of hb-2 was also reported done")
		}
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "degraded" {
		t.Errorf("stack state after a failed delete = %q, want degraded", got)
	}
}

// An inline (recreate) update whose delete fails must be reported, and must not
// go on to create over a VM that was never torn down.
func TestFleet_ComposeFailedUpdateDeleteIsReported(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	msgs := deployCollect(t, ctx, client, composeFailOne)
	if p := errorPhaseFor(msgs, "hb-1"); p != nil {
		t.Fatalf("setup deploy failed: %s", p.Error)
	}

	barVMDelete(t, ctx, node.DB, "hb-1")
	eventsBefore := len(node.Virt.EventLog())
	edited := strings.Replace(composeFailOne, "    cpu: 1\n", "    cpu: 2\n", 1)
	msgs = deployCollect(t, ctx, client, edited)
	p := errorPhaseFor(msgs, "hb-1")
	if p == nil {
		t.Fatalf("failed update-delete of hb-1 sent no error phase; got %v", msgs)
	}
	if !strings.Contains(p.Error, "operation is in progress") {
		t.Errorf("error phase for hb-1 = %q, want the delete failure", p.Error)
	}
	for _, e := range node.Virt.EventLog()[eventsBefore:] {
		if e.Domain == "hb-1" && e.Op == "define" {
			t.Error("update went on to define hb-1 after its delete failed")
		}
	}
	// CreateVM refuses a name that still exists, so a create attempted after
	// the failed delete shows up only as a second error for the same VM.
	nErr := 0
	for _, m := range msgs {
		if m.Phase == "error" && m.VmName == "hb-1" {
			nErr++
		}
	}
	if nErr != 1 {
		t.Errorf("hb-1 reported %d errors, want 1 — the recreate must stop at the failed delete", nErr)
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "degraded" {
		t.Errorf("stack state after a failed update = %q, want degraded", got)
	}
}

// A depends-on wait that fails was logged and ignored ("continuing"), and the
// VM was reported done. It is a failed action.
func TestFleet_ComposeFailedDependsOnWaitIsReported(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()
	node.Server.SetDependsOnWaitTimeoutForTests(time.Nanosecond)

	yaml := composeFailTwo + "    depends-on: [hb-1]\n"
	msgs := deployCollect(t, ctx, client, yaml)
	p := errorPhaseFor(msgs, "hb-1")
	if p == nil {
		t.Fatalf("timed-out depends-on wait on hb-1 sent no error phase; got %v", msgs)
	}
	if !strings.Contains(p.Error, "timeout") {
		t.Errorf("error phase for hb-1 = %q, want the wait timeout", p.Error)
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "degraded" {
		t.Errorf("stack state after a failed wait = %q, want degraded", got)
	}
}

// The rolling-update path (any non-recreate strategy; all-at-once here, which
// has no health wait) has its own scale-down loop; a failed delete there
// must be reported the same way.
func TestFleet_ComposeFailedRollingScaleDownDeleteIsReported(t *testing.T) {
	_, node, client := newComposeFailNode(t)
	ctx := context.Background()

	rolling := strings.Replace(composeFailTwo, "  hb-1:\n    image: test\n",
		"  hb-1:\n    update:\n      strategy: all-at-once\n    image: test\n", 1)
	msgs := deployCollect(t, ctx, client, rolling)
	for _, vm := range []string{"hb-1", "hb-2"} {
		if p := errorPhaseFor(msgs, vm); p != nil {
			t.Fatalf("setup deploy failed for %s: %s", vm, p.Error)
		}
	}

	// One update (so the rolling path runs) plus one scale-down delete.
	next := strings.Replace(composeFailOne, "  hb-1:\n    image: test\n    cpu: 1\n",
		"  hb-1:\n    update:\n      strategy: all-at-once\n    image: test\n    cpu: 2\n", 1)
	if next == composeFailOne {
		t.Fatal("fixture edit did not apply")
	}
	barVMDelete(t, ctx, node.DB, "hb-2")
	msgs = deployCollect(t, ctx, client, next)
	sawRolling := false
	for _, p := range msgs {
		if p.Phase == "rolling-update" {
			sawRolling = true
		}
		if p.Phase == "done" && p.VmName == "hb-2" {
			t.Error("failed delete of hb-2 was also reported done")
		}
	}
	if !sawRolling {
		t.Fatalf("deploy did not take the rolling path; got %v", msgs)
	}
	if errorPhaseFor(msgs, "hb-2") == nil {
		t.Fatalf("failed rolling scale-down delete of hb-2 sent no error phase; got %v", msgs)
	}
	if got := stackState(t, ctx, node.DB, "hb"); got != "degraded" {
		t.Errorf("stack state after a failed rolling delete = %q, want degraded", got)
	}
}
