package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// `lv ct stop --force` on a node in write quarantine: the container analogue
// of `lv stop --force` (quarantined_force_stop_test.go). The stop cannot
// record "operator-stop" on the container's row, and an unrecorded stop is
// undone by the restart policy. So the forced stop first writes a durable
// marker under the node's data_dir, then stops; every local start honours
// it; once the quarantine lifts the node replays the stop into the row and
// removes the marker. A plain `lv ct stop` there is refused, naming --force.

// qcsForceField is StopContainerRequest.force's field number. The request
// is built from the wire, so the file builds (and runs, red) on a binary
// whose request has no such field: a server that does not know it ignores
// it.
const qcsForceField = 4

func qcsStopReq(t *testing.T, host, name string, force bool) *pb.StopContainerRequest {
	t.Helper()
	req := &pb.StopContainerRequest{HostName: host, Name: name}
	if !force {
		return req
	}
	b, err := proto.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	b = protowire.AppendTag(b, qcsForceField, protowire.VarintType)
	b = protowire.AppendVarint(b, 1)
	out := &pb.StopContainerRequest{}
	if err := proto.Unmarshal(b, out); err != nil {
		t.Fatal(err)
	}
	return out
}

// qcsContainer creates name on n, restart policy always, and starts it.
func qcsContainer(t *testing.T, c *Cluster, n *Node, name string) {
	t.Helper()
	ctx := context.Background()
	cl := c.SelfClient(n)
	if _, err := cl.CreateContainer(ctx, &pb.CreateContainerRequest{
		HostName: n.Name, Name: name, Template: "download", Distro: "alpine", Release: "3.21",
		Arch: "amd64", MemoryMib: 256, Restart: &pb.RestartPolicy{Condition: "always", Delay: "1ms"},
	}); err != nil {
		t.Fatalf("CreateContainer %s: %v", name, err)
	}
	if _, err := cl.StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: name}); err != nil {
		t.Fatalf("StartContainer %s: %v", name, err)
	}
	if st := n.CT.State(name); st != "running" {
		t.Fatalf("after start %s is %q, want running", name, st)
	}
}

// qcsSweeps runs the node's container checker (the restart engine), built
// fresh as after a daemon restart, and its reconciler pass (which replays
// the markers), count times.
func qcsSweeps(t *testing.T, n *Node, count int) {
	t.Helper()
	ctx := context.Background()
	cc := health.NewContainerChecker(n.Name, n.DB, n.CT.LXC())
	cc.SetDaemonDirs(n.FW.DataDir, "") // as the daemon wires it
	cc.SetContainerLock(n.Server.TryLockContainer)
	r := n.Reconciler()
	for i := 0; i < count; i++ {
		r.ReconcileOnce(ctx)
		cc.SweepOnce(ctx)
	}
}

func qcsRow(t *testing.T, n *Node, name string) *corrosion.ContainerRecord {
	t.Helper()
	ct, err := corrosion.GetContainer(context.Background(), n.DB, n.Name, name)
	if err != nil || ct == nil {
		t.Fatalf("GetContainer %s: %+v %v", name, ct, err)
	}
	return ct
}

func qcsMarker(n *Node, name string) string {
	return filepath.Join(n.FW.DataDir, "ct-operator-stops", name+".json")
}

func qcsCount(calls []string, name string) int {
	k := 0
	for _, c := range calls {
		if c == name {
			k++
		}
	}
	return k
}

// Through a peer that is not quarantined: a plain stop is refused naming
// --force and nothing is stopped; the forced stop stops the container and
// leaves a marker; the restart policy, a fresh checker and `lv ct start`
// leave it down while the quarantine holds; once it lifts the stop is
// recorded as the operator's and the marker removed, and `lv ct start`
// starts it again.
//
// Red on 7a902203c: the plain stop is not refused (it stops the container,
// then fails to record it: Internal), and the force flag is unknown there.
func TestFleet_QuarantinedContainerForceStop_StopsHoldsAndReplays(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	entry, owner := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	// The entry waits to see a forwarded stop or start on its own replica.
	laggingPump(t, c, owner, entry, 10*time.Millisecond)
	qcsContainer(t, c, owner, "web")
	cl := c.SelfClient(entry)

	owner.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	stopsBefore := qcsCount(owner.CT.StopCalls(), "web")
	_, err := cl.StopContainer(ctx, qcsStopReq(t, owner.Name, "web", false))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("plain StopContainer under write quarantine: %v, want FailedPrecondition naming --force", err)
	}
	if st := owner.CT.State("web"); st != "running" || qcsCount(owner.CT.StopCalls(), "web") != stopsBefore {
		t.Fatalf("a refused stop touched the runtime: state %q, stop calls %v", st, owner.CT.StopCalls())
	}

	// The row is not written under quarantine, so an entry that waited to
	// see it stopped would wait out its whole visibility timeout (15s): the
	// owner says the stop is recorded on itself only.
	began := time.Now()
	if _, err := cl.StopContainer(ctx, qcsStopReq(t, owner.Name, "web", true)); err != nil {
		t.Fatalf("forced StopContainer under write quarantine: %v, want it to stop the container", err)
	}
	if took := time.Since(began); took > 10*time.Second {
		t.Errorf("the forced stop through %s took %v: it waited for a row the quarantine does not write", entry.Name, took)
	}
	if st := owner.CT.State("web"); st != "stopped" {
		t.Fatalf("web after the forced stop: %q, want stopped", st)
	}
	var m struct {
		Container, Host, Incarnation string
		OwnerEpoch                   int64 `json:"owner_epoch"`
	}
	if b, err := os.ReadFile(qcsMarker(owner, "web")); err != nil || json.Unmarshal(b, &m) != nil {
		t.Fatalf("marker: %v, want one", err)
	}
	row := qcsRow(t, owner, "web")
	if m.Container != "web" || m.Host != owner.Name || m.Incarnation != row.CreatedAt || m.OwnerEpoch != row.OwnerEpoch {
		t.Errorf("marker %+v, want web on %s incarnation %s epoch %d", m, owner.Name, row.CreatedAt, row.OwnerEpoch)
	}
	if row.State != "running" {
		t.Errorf("row %s under quarantine; the test expects it unwritten (running)", row.State)
	}

	startsBefore := qcsCount(owner.CT.StartCalls(), "web")
	qcsSweeps(t, owner, 3)
	_, err = cl.StartContainer(ctx, &pb.StartContainerRequest{HostName: owner.Name, Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "still in write quarantine") {
		t.Errorf("StartContainer under quarantine with the marker: %v, want FailedPrecondition naming the quarantine", err)
	}
	if k := qcsCount(owner.CT.StartCalls(), "web") - startsBefore; k != 0 || owner.CT.State("web") != "stopped" {
		t.Fatalf("web started %d time(s) while the marker held it (state %q)", k, owner.CT.State("web"))
	}

	// The quarantine lifts: the stop is recorded as the operator's.
	owner.DB.SetWriteQuarantine(nil)
	qcsSweeps(t, owner, 3)
	if row := qcsRow(t, owner, "web"); row.State != "stopped" || row.StateDetail != "operator-stop" {
		t.Errorf("web after the lift: %s/%q, want stopped/operator-stop", row.State, row.StateDetail)
	}
	if _, err := os.Stat(qcsMarker(owner, "web")); !os.IsNotExist(err) {
		t.Errorf("the marker outlived its replay: %v", err)
	}
	if k := qcsCount(owner.CT.StartCalls(), "web") - startsBefore; k != 0 {
		t.Errorf("the forced stop was undone after the lift: %d start(s)", k)
	}
	if _, err := cl.StartContainer(ctx, &pb.StartContainerRequest{HostName: owner.Name, Name: "web"}); err != nil {
		t.Fatalf("StartContainer after the replay: %v", err)
	}
	if st := owner.CT.State("web"); st != "running" {
		t.Errorf("web after lv ct start: %q, want running", st)
	}
}

// A marker made under one ownership of the container is not replayed over
// a later one: the owner epoch moved meanwhile, so the marker is dropped,
// nothing records the stop, and the marker holds nothing.
//
// Red on 7a902203c: the forced stop is not made (no force flag there).
//
// Mutation, the replay's epoch drop (the guarded write refuses instead):
// the marker outlives the replay: red.
func TestFleet_QuarantinedContainerForceStop_StaleMarkerNotReplayed(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qcsContainer(t, c, n, "web")

	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	if _, err := c.SelfClient(n).StopContainer(ctx, qcsStopReq(t, n.Name, "web", true)); err != nil {
		t.Fatalf("forced StopContainer under write quarantine: %v", err)
	}
	if _, err := os.Stat(qcsMarker(n, "web")); err != nil {
		t.Fatalf("marker: %v, want one", err)
	}
	n.DB.SetWriteQuarantine(nil)
	// A later ownership of the same row: it left and came back.
	before := qcsRow(t, n, "web")
	if err := localExec(ctx, n.DB, `UPDATE containers SET owner_epoch = ? WHERE host_name = ? AND name = ?`,
		before.OwnerEpoch+2, n.Name, "web"); err != nil {
		t.Fatal(err)
	}
	// One replay, before anything else runs: the marker is dropped there,
	// not left for a later pass to find the container running again.
	n.Reconciler().ReconcileOnce(ctx)
	if _, err := os.Stat(qcsMarker(n, "web")); !os.IsNotExist(err) {
		t.Errorf("the stale marker was not dropped by the replay: %v", err)
	}
	qcsSweeps(t, n, 3)
	row := qcsRow(t, n, "web")
	if row.StateDetail == "operator-stop" {
		t.Errorf("the stop was recorded over a later ownership: %s/%q", row.State, row.StateDetail)
	}
	// It holds nothing: the later ownership's restart policy runs.
	if st := n.CT.State("web"); st != "running" {
		t.Errorf("web under the later ownership: %q, want restarted by its policy (the stale marker held it)", st)
	}
}

// A marker that cannot be written refuses the forced stop: the container is
// never stopped without one.
//
// Red on 7a902203c: the stop goes ahead without any marker.
func TestFleet_QuarantinedContainerForceStop_RefusedWhenMarkerUnwritable(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qcsContainer(t, c, n, "web")
	if err := os.WriteFile(filepath.Join(n.FW.DataDir, "ct-operator-stops"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	_, err := c.SelfClient(n).StopContainer(ctx, qcsStopReq(t, n.Name, "web", true))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "left running") {
		t.Errorf("forced stop with an unwritable marker: %v, want FailedPrecondition saying it is left running", err)
	}
	if st := n.CT.State("web"); st != "running" {
		t.Errorf("web: %q, want left running", st)
	}
}

// `lv ct start` once the quarantine has lifted, before any reconcile pass:
// it records the forced stop first, then starts the container.
//
// Red on 7a902203c: the forced stop is not made (no force flag there).
//
// Mutation, StartContainer's marker gate (no replay first): the start is
// refused by the runtime-start backstop: red.
func TestFleet_QuarantinedContainerForceStop_StartAfterLiftRecordsTheStopFirst(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qcsContainer(t, c, n, "web")
	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	if _, err := c.SelfClient(n).StopContainer(ctx, qcsStopReq(t, n.Name, "web", true)); err != nil {
		t.Fatalf("forced StopContainer under write quarantine: %v", err)
	}
	n.DB.SetWriteQuarantine(nil)
	if _, err := c.SelfClient(n).StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: "web"}); err != nil {
		t.Fatalf("StartContainer after the lift: %v", err)
	}
	if st := n.CT.State("web"); st != "running" {
		t.Errorf("web: %q, want running", st)
	}
	if _, err := os.Stat(qcsMarker(n, "web")); !os.IsNotExist(err) {
		t.Errorf("the marker outlived the start: %v", err)
	}
	rows, err := n.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'ct.stop' AND target = 'web' AND result = 'ok'`)
	if err != nil {
		t.Fatal(err)
	}
	recorded := false
	for _, r := range rows {
		recorded = recorded || strings.Contains(r.String("detail"), "recorded once it lifted")
	}
	if !recorded {
		t.Errorf("no ct.stop audit row records the forced stop: %+v", rows)
	}
}

// A container marker that cannot be read fails closed: the restart policy
// does not start the container, `lv ct start` is refused, and
// operator_stop_marker_corrupt is raised for the container. A recorded
// `lv ct stop` is the remedy.
//
// Red on 7a902203c: the marker is not read there; the restart policy starts
// the container.
//
// Mutation, the checker's hold (containerOperatorStopHeld reports none):
// the restart policy starts web: red.
func TestFleet_QuarantinedContainerForceStop_CorruptMarkerFailsClosed(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qcsContainer(t, c, n, "web")
	// Down without a recorded stop (as after a forced stop whose marker
	// was then damaged).
	if err := n.CT.StopContainer(ctx, "web", 0); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(qcsMarker(n, "web")), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(qcsMarker(n, "web"), []byte(`{"version":1,"container":"web","ho`), 0o600); err != nil {
		t.Fatal(err)
	}
	startsBefore := qcsCount(n.CT.StartCalls(), "web")
	qcsSweeps(t, n, 3)
	if k := qcsCount(n.CT.StartCalls(), "web") - startsBefore; k != 0 {
		t.Fatalf("web started %d time(s) with a corrupt marker", k)
	}
	cond, ok, err := corrosion.GetHealthCondition(ctx, n.DB, qfsCorruptEvaluator, qfsCorruptCode, "container", "web")
	if err != nil || !ok || cond.Lifecycle == corrosion.ConditionResolved || cond.Severity != corrosion.SeverityCritical {
		t.Errorf("operator_stop_marker_corrupt for container/web: ok=%v %+v err=%v, want open and critical", ok, cond, err)
	}
	_, err = c.SelfClient(n).StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("StartContainer with a corrupt marker: %v, want FailedPrecondition saying it cannot be read", err)
	}

	// The remedy: a recorded stop, then a start.
	if _, err := c.SelfClient(n).StopContainer(ctx, qcsStopReq(t, n.Name, "web", false)); err != nil {
		t.Fatalf("StopContainer web (the remedy): %v", err)
	}
	if _, err := os.Stat(qcsMarker(n, "web")); !os.IsNotExist(err) {
		t.Errorf("the recorded stop left the corrupt marker: %v", err)
	}
	qcsSweeps(t, n, 1)
	if cond, ok, _ := corrosion.GetHealthCondition(ctx, n.DB, qfsCorruptEvaluator, qfsCorruptCode, "container", "web"); ok && cond.Lifecycle != corrosion.ConditionResolved {
		t.Errorf("operator_stop_marker_corrupt still open once the marker is gone")
	}
	if _, err := c.SelfClient(n).StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: "web"}); err != nil {
		t.Fatalf("StartContainer after the remedy: %v", err)
	}
}

// `lv ct start` of a container no marker holds, on a node in write
// quarantine: refused before anything changes (the start could not be
// recorded), naming the quarantine and its remedy.
//
// Red on fc53141a7: a stopped row is answered Internal by the capacity
// reservation's refused write (no remedy); a row still recorded running
// whose container went down (db) skips admission, so the runtime starts it
// and only then does the running write fail (Internal): it runs unrecorded.
//
// Mutation, the refusal removed: the same, red.
func TestFleet_QuarantinedContainerStart_RefusedBeforeAnythingChanges(t *testing.T) {
	c := New(t, Options{Nodes: 1})
	n := c.Nodes[0]
	ctx := context.Background()
	qcsContainer(t, c, n, "web")
	if _, err := c.SelfClient(n).StopContainer(ctx, qcsStopReq(t, n.Name, "web", false)); err != nil {
		t.Fatalf("StopContainer: %v", err)
	}
	qcsContainer(t, c, n, "db")
	if err := n.CT.StopContainer(ctx, "db", 0); err != nil { // down, its row still running
		t.Fatal(err)
	}
	n.DB.SetWriteQuarantine(func() string { return qfsQuarantine })
	dbStarts := qcsCount(n.CT.StartCalls(), "db")
	_, err := c.SelfClient(n).StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: "db"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "write quarantine") {
		t.Errorf("StartContainer db under write quarantine: %v, want FailedPrecondition naming the quarantine", err)
	}
	if k := qcsCount(n.CT.StartCalls(), "db") - dbStarts; k != 0 || n.CT.State("db") != "stopped" {
		t.Errorf("db was started unrecorded under quarantine: %d start(s), state %q", k, n.CT.State("db"))
	}
	startsBefore := qcsCount(n.CT.StartCalls(), "web")
	_, err = c.SelfClient(n).StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: "web"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "write quarantine") ||
		!strings.Contains(err.Error(), "reseed") || !strings.Contains(err.Error(), "nothing was changed") {
		t.Errorf("StartContainer under write quarantine: %v, want FailedPrecondition naming the quarantine and its remedy", err)
	}
	if k := qcsCount(n.CT.StartCalls(), "web") - startsBefore; k != 0 || n.CT.State("web") != "stopped" {
		t.Errorf("the refused start touched the runtime: %d start(s), state %q", k, n.CT.State("web"))
	}
	if row := qcsRow(t, n, "web"); row.State != "stopped" || row.StateDetail != "operator-stop" {
		t.Errorf("row %s/%q, want unchanged stopped/operator-stop", row.State, row.StateDetail)
	}
	n.DB.SetWriteQuarantine(nil)
	if _, err := c.SelfClient(n).StartContainer(ctx, &pb.StartContainerRequest{HostName: n.Name, Name: "web"}); err != nil {
		t.Fatalf("StartContainer after the lift: %v", err)
	}
}
