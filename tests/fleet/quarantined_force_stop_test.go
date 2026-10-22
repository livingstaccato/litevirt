package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// `lv stop --force` on a node in write quarantine (VERIFY bug 11, M3; the
// owner's ruling of 2026-10-21). The stop cannot record "operator-stop" on
// the row, and an unrecorded kill is undone by the restart policy once the
// quarantine lifts. So the forced stop first writes a durable marker under
// the node's data_dir, then kills; every local start honours the marker;
// once the quarantine lifts the node replays the stop into the row through
// the ordinary stop record and removes the marker. No marker, no kill.

const qfsQuarantine = "rolled back below latched token(s): test"

// The evaluator and code of operator_stop_marker_corrupt (package health),
// spelled out so the file builds against a binary without them.
const (
	qfsCorruptEvaluator = "operator_stop_marker"
	qfsCorruptCode      = "operator_stop_marker_corrupt"
)

// qfsVM creates web on n, restart policy always and onboot, running.
func qfsVM(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	if _, err := c.SelfClient(n).CreateVM(context.Background(), &pb.CreateVMRequest{Spec: &pb.VMSpec{
		Name: name, Cpu: 1, MemoryMib: 512, Onboot: true,
		Placement: &pb.PlacementSpec{Host: n.Name},
		Restart:   &pb.RestartPolicy{Condition: "always", Delay: "1ms"},
	}}); err != nil {
		t.Fatalf("CreateVM %s: %v", name, err)
	}
	if st, _ := n.Virt.RawState(name); st != libvirtfake.StateRunning {
		t.Fatalf("after CreateVM %s is %q, want running", name, st)
	}
}

// qfsOps counts libvirt ops on name since event index from.
func qfsOps(n *Node, name string, from int) map[string]int {
	out := map[string]int{}
	for _, e := range n.Virt.EventLog()[from:] {
		if e.Domain == name {
			out[e.Op]++
		}
	}
	return out
}

// qfsPasses runs what the node runs on its own, count times: the reconciler
// pass and the restart-policy sweep, both built fresh, as after a daemon
// restart (only what is on disk survives).
func qfsPasses(t *testing.T, n *Node, count int) {
	t.Helper()
	ctx := context.Background()
	r := n.Reconciler()
	checker := newRestartChecker(t, n)
	for i := 0; i < count; i++ {
		r.ReconcileOnce(ctx)
		checker.SweepOnce(ctx)
	}
}

func qfsRow(t *testing.T, n *Node, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), n.DB, name)
	if err != nil {
		t.Fatalf("GetVM %s: %v", name, err)
	}
	return vm
}

// qfsKilled gives name libvirt's own reason for a destroyed domain, which
// the fake leaves unset: the reason the restart policy restarts.
func qfsKilled(n *Node, name string) { n.Virt.SetStateReason(name, "destroyed") }

func qfsMarker(n *Node, name string) string {
	return filepath.Join(n.FW.DataDir, "operator-stops", name+".json")
}

// The forced stop kills the guest under quarantine; a daemon restart, its
// onboot pass and the restart policy leave it down; `lv start` is refused
// while the quarantine holds; once it lifts the stop is recorded as the
// operator's and the marker removed, and only then does `lv start` start
// it. A forced stop without quarantine is unchanged: recorded at once, no
// marker.
//
// Red on 884306b75: the forced stop is refused (FailedPrecondition) and the
// guest left running.
//
// Mutation, the replay (ReplayOperatorStopMarkers does nothing): the row is
// never recorded operator-stop and the marker stays: red.
func TestFleet_QuarantinedForceStop_KillsHoldsAndReplays(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qfsVM(t, c, n, "web")
	qfsVM(t, c, n, "db")

	// Without quarantine: as before.
	if _, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "db", Force: true}); err != nil {
		t.Fatalf("StopVM --force db without quarantine: %v", err)
	}
	if vm := qfsRow(t, n, "db"); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Errorf("db without quarantine: row %s/%q, want stopped/operator-stop", vm.State, vm.StateDetail)
	}
	if _, err := os.Stat(qfsMarker(n, "db")); !os.IsNotExist(err) {
		t.Errorf("a forced stop without quarantine wrote a marker: %v", err)
	}

	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	before := len(n.Virt.EventLog())
	out, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true})
	if err != nil {
		t.Fatalf("StopVM --force under write quarantine: %v, want it to stop the guest", err)
	}
	if out.State != pb.VMState_VM_STOPPED || !strings.Contains(out.StateDetail, "write quarantine") {
		t.Errorf("answer %v/%q, want stopped, saying the stop is recorded on this host only", out.State, out.StateDetail)
	}
	if ops := qfsOps(n, "web", before); ops["destroy"] != 1 {
		t.Errorf("libvirt ops on web: %v, want one destroy", ops)
	}
	if st, _ := n.Virt.RawState("web"); st == libvirtfake.StateRunning {
		t.Fatalf("web still runs after a forced stop")
	}
	qfsKilled(n, "web")
	// Read as a file, not through the package: the test also runs, red,
	// on a build that has no marker.
	var m struct{ Host, Incarnation string }
	if b, err := os.ReadFile(qfsMarker(n, "web")); err != nil || json.Unmarshal(b, &m) != nil {
		t.Fatalf("marker: %v, want one", err)
	}
	if row := qfsRow(t, n, "web"); m.Incarnation != row.CreatedAt || m.Host != n.Name {
		t.Errorf("marker %+v, want host %s incarnation %s", m, n.Name, row.CreatedAt)
	}

	// A daemon restart under quarantine: fresh reconciler, its onboot pass,
	// fresh restart policy. Nothing starts web.
	r := n.Reconciler()
	r.StartOnbootVMs(ctx)
	qfsPasses(t, n, 3)
	_, err = c.SelfClient(n).StartVM(ctx, &pb.StartVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "write quarantine") {
		t.Errorf("StartVM under quarantine with the marker: %v, want FailedPrecondition naming the quarantine", err)
	}
	if ops := qfsOps(n, "web", before); ops["start"] != 0 {
		t.Fatalf("web started while the marker held it: %v", ops)
	}

	// The quarantine lifts: the stop is recorded as the operator's.
	n.DB.SetWriteQuarantine(nil)
	qfsPasses(t, n, 3)
	if vm := qfsRow(t, n, "web"); vm.State != "stopped" || vm.StateDetail != "operator-stop" {
		t.Errorf("web after the lift: %s/%q, want stopped/operator-stop", vm.State, vm.StateDetail)
	}
	if _, err := os.Stat(qfsMarker(n, "web")); !os.IsNotExist(err) {
		t.Errorf("the marker outlived its replay: %v", err)
	}
	if ops := qfsOps(n, "web", before); ops["start"] != 0 {
		t.Errorf("the forced stop was undone after the lift: %v", ops)
	}
	if _, err := c.SelfClient(n).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM after the replay: %v", err)
	}
	if st, _ := n.Virt.RawState("web"); st != libvirtfake.StateRunning {
		t.Errorf("web after lv start: %q, want running", st)
	}
}

// A marker that cannot be written refuses the forced stop: the guest is
// never killed without one.
//
// Red on 884306b75: the refusal there does not say the marker could not be
// written (it refuses every forced stop).
//
// Mutation, refuse-on-unwritable (a marker write error ignored): the guest
// is destroyed: red.
func TestFleet_QuarantinedForceStop_RefusedWhenMarkerUnwritable(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qfsVM(t, c, n, "web")
	// A file where the marker directory goes: every marker write fails, as
	// on a full or failing data_dir.
	if err := os.WriteFile(filepath.Join(n.FW.DataDir, "operator-stops"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	before := len(n.Virt.EventLog())
	_, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "could not be written") {
		t.Errorf("StopVM --force with an unwritable marker: %v, want FailedPrecondition saying the record could not be written", err)
	}
	if ops := qfsOps(n, "web", before); ops["destroy"] != 0 {
		t.Errorf("libvirt ops on web: %v, want none", ops)
	}
	if st, _ := n.Virt.RawState("web"); st != libvirtfake.StateRunning {
		t.Errorf("web is %q, want running", st)
	}
}

// A marker that does not parse fails closed: once the quarantine lifts it
// is not replayed, nothing starts the VM, `lv start` is refused, and
// operator_stop_marker_corrupt is raised. A recorded `lv stop` is the
// remedy: it removes the marker, and `lv start` starts the VM.
//
// Red on 884306b75: the forced stop is refused.
//
// Mutation, the honour check (OperatorStopHold reports no hold): the
// reconciler records an out-of-band destroy and the restart policy starts
// web: red.
func TestFleet_QuarantinedForceStop_CorruptMarkerFailsClosed(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qfsVM(t, c, n, "web")
	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	before := len(n.Virt.EventLog())
	if _, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM --force under quarantine: %v", err)
	}
	qfsKilled(n, "web")
	if err := os.WriteFile(qfsMarker(n, "web"), []byte(`{"version":1,"vm":"web","ho`), 0o600); err != nil {
		t.Fatal(err)
	}
	n.DB.SetWriteQuarantine(nil)
	qfsPasses(t, n, 3)
	if ops := qfsOps(n, "web", before); ops["start"] != 0 {
		t.Fatalf("web started with a corrupt marker: %v", ops)
	}
	if vm := qfsRow(t, n, "web"); vm.State == "stopped" && vm.StateDetail == "operator-stop" {
		t.Errorf("a corrupt marker was replayed: %s/%q", vm.State, vm.StateDetail)
	}
	cond, ok, err := corrosion.GetHealthCondition(ctx, n.DB, qfsCorruptEvaluator, qfsCorruptCode, "vm", "web")
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || cond.Severity != corrosion.SeverityCritical {
		t.Errorf("operator_stop_marker_corrupt: ok=%v %+v err=%v, want open and critical", ok, cond, err)
	}
	_, err = c.SelfClient(n).StartVM(ctx, &pb.StartVMRequest{Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("StartVM with a corrupt marker: %v, want FailedPrecondition saying it cannot be read", err)
	}

	// The remedy: a recorded stop, then a start.
	if _, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StopVM web (the remedy): %v", err)
	}
	if _, err := os.Stat(qfsMarker(n, "web")); !os.IsNotExist(err) {
		t.Errorf("the recorded stop left the corrupt marker: %v", err)
	}
	qfsPasses(t, n, 1)
	if cond, ok, _ := corrosion.GetHealthCondition(ctx, n.DB, qfsCorruptEvaluator, qfsCorruptCode, "vm", "web"); ok && cond.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("operator_stop_marker_corrupt still open once the marker is gone")
	}
	if _, err := c.SelfClient(n).StartVM(ctx, &pb.StartVMRequest{Name: "web"}); err != nil {
		t.Fatalf("StartVM after the remedy: %v", err)
	}
}

// The quarantine lifts after the VM was deleted (a tombstone replicated
// while the node could not write): the marker is removed, nothing is
// recorded or started.
//
// Red on 884306b75: the forced stop is refused.
func TestFleet_QuarantinedForceStop_VMGoneWhenQuarantineLifts(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qfsVM(t, c, n, "web")
	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	before := len(n.Virt.EventLog())
	if _, err := c.SelfClient(n).StopVM(ctx, &pb.StopVMRequest{Name: "web", Force: true}); err != nil {
		t.Fatalf("StopVM --force under quarantine: %v", err)
	}
	qfsKilled(n, "web")
	n.DB.SetWriteQuarantine(nil)
	if err := corrosion.DeleteVM(ctx, n.DB, "web"); err != nil {
		t.Fatal(err)
	}
	qfsPasses(t, n, 2)
	if _, err := os.Stat(qfsMarker(n, "web")); !os.IsNotExist(err) {
		t.Errorf("the marker of a deleted VM stays: %v", err)
	}
	if vm := qfsRow(t, n, "web"); vm != nil {
		t.Errorf("the deleted VM's row is back: %+v", vm)
	}
	if ops := qfsOps(n, "web", before); ops["start"] != 0 {
		t.Errorf("libvirt ops on web: %v, want no start", ops)
	}
}
