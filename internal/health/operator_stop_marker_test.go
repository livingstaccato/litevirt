package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A marker holds only its own host's VM of its own incarnation; one that
// does not parse, or is of another version, or names another VM, holds its
// VM and says it is corrupt. A temp file a crash left is not a marker.
//
// Red on 884306b75: does not compile.
//
// Mutation, the honour check (OperatorStopHold reports no hold): red.
func TestOperatorStopMarker_HoldsItsIncarnationAndFailsClosed(t *testing.T) {
	dir := t.TempDir()
	vm := &corrosion.VMRecord{Name: "web", CreatedAt: "2026-10-21T10:00:00Z"}
	if why, _ := OperatorStopHold(dir, "node-a", vm); why != "" {
		t.Fatalf("no marker: held (%s)", why)
	}
	if err := WriteOperatorStopMarker(dir, OperatorStopMarker{VM: "web", Host: "node-a", Incarnation: vm.CreatedAt, StoppedAt: "t"}); err != nil {
		t.Fatal(err)
	}
	if why, corrupt := OperatorStopHold(dir, "node-a", vm); why == "" || corrupt {
		t.Errorf("own marker: held=%q corrupt=%v, want held", why, corrupt)
	}
	if why, _ := OperatorStopHold(dir, "node-b", vm); why != "" {
		t.Errorf("another host's marker holds: %s", why)
	}
	if why, _ := OperatorStopHold(dir, "node-a", &corrosion.VMRecord{Name: "web", CreatedAt: "2026-10-22T00:00:00Z"}); why != "" {
		t.Errorf("a marker holds a new incarnation of the name: %s", why)
	}
	// B1: the same incarnation owned again under a later generation (it
	// left this host and came back) is not held.
	if why, _ := OperatorStopHold(dir, "node-a", &corrosion.VMRecord{Name: "web", CreatedAt: vm.CreatedAt, OwnerEpoch: 3}); why != "" {
		t.Errorf("a marker holds a later ownership of its incarnation: %s", why)
	}
	if err := os.WriteFile(filepath.Join(OperatorStopMarkerDir(dir), ".web.tmp-1"), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if names, err := ListOperatorStopMarkers(dir); err != nil || len(names) != 1 || names[0] != "web" {
		t.Errorf("ListOperatorStopMarkers = %v, %v, want [web]", names, err)
	}

	p, _ := OperatorStopMarkerPath(dir, "web")
	for name, body := range map[string]string{
		"truncated":     `{"version":1,"vm":"web","ho`,
		"other version": `{"version":2,"vm":"web","host":"node-a","incarnation":"2026-10-21T10:00:00Z"}`,
		"other vm":      `{"version":1,"vm":"db","host":"node-a","incarnation":"2026-10-21T10:00:00Z"}`,
		"no host":       `{"version":1,"vm":"web","incarnation":"2026-10-21T10:00:00Z"}`,
	} {
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := ReadOperatorStopMarker(dir, "web"); !errors.Is(err, ErrOperatorStopMarkerCorrupt) {
			t.Errorf("%s: read err %v, want corrupt", name, err)
		}
		// Whatever host or incarnation asks: it cannot be told whose it is.
		if why, corrupt := OperatorStopHold(dir, "node-b", &corrosion.VMRecord{Name: "web", CreatedAt: "x"}); why == "" || !corrupt {
			t.Errorf("%s: held=%q corrupt=%v, want held and corrupt", name, why, corrupt)
		}
	}
	if err := RemoveOperatorStopMarker(dir, "web"); err != nil {
		t.Fatal(err)
	}
	if why, _ := OperatorStopHold(dir, "node-a", vm); why != "" {
		t.Errorf("removed marker still holds: %s", why)
	}
}

// A marker that cannot be written is an error, and nothing is left behind
// that reads as a marker.
func TestWriteOperatorStopMarker_Unwritable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(OperatorStopMarkerDir(dir), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteOperatorStopMarker(dir, OperatorStopMarker{VM: "web", Host: "a", Incarnation: "i"}); err == nil {
		t.Fatal("a marker write into an unusable directory succeeded")
	}
}

// What a forced stop under quarantine leaves on a host: the row still says
// what it said, the domain is shut off with libvirt's reason destroyed. With
// the marker, the reconciler records no out-of-band stop and the restart
// policy does not start the VM; without it, both act as before.
//
// Red on 884306b75: does not compile.
//
// Mutation, the honour checks (operatorStopHeld and the stop-sync skip
// report no hold): the marked VMs are synced and started: red.
func TestOperatorStopMarker_ReconcilerAndRestartPolicyHonourIt(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	fake := libvirtfake.New()
	dataDir := t.TempDir()
	spec, _ := json.Marshal(&pb.VMSpec{Restart: &pb.RestartPolicy{Condition: "always", Delay: "1ms"}})
	for _, vm := range []struct{ name, state, detail string }{
		{"held-run", "running", ""}, {"free-run", "running", ""},
		{"held-stop", "stopped", "stopped/out-of-band-destroy"}, {"free-stop", "stopped", "stopped/out-of-band-destroy"},
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: vm.name, HostName: "node-a", State: vm.state, StateDetail: vm.detail, Spec: string(spec),
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM %s: %v", vm.name, err)
		}
		if err := fake.DefineDomain(`<domain type='kvm'><name>` + vm.name + `</name></domain>`); err != nil {
			t.Fatal(err)
		}
		fake.SetStateReason(vm.name, "destroyed")
	}
	for _, name := range []string{"held-run", "held-stop"} {
		row, err := corrosion.GetVM(ctx, db, name)
		if err != nil || row == nil {
			t.Fatal(err)
		}
		if err := WriteOperatorStopMarker(dataDir, OperatorStopMarker{VM: name, Host: "node-a", Incarnation: corrosion.IncarnationOf(row.CreatedAt)}); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReconciler("node-a", dataDir, db, fake)
	r.ReconcileOnce(ctx)
	for name, want := range map[string]string{"held-run": "running", "free-run": "stopped"} {
		if row, _ := corrosion.GetVM(ctx, db, name); row.State != want {
			t.Errorf("%s after the reconciler: %s/%q, want %s", name, row.State, row.StateDetail, want)
		}
	}
	v := NewVMChecker("node-a", dataDir, db, nil)
	v.SetBackend(fake)
	v.SweepOnce(ctx)
	started := map[string]bool{}
	for _, e := range fake.EventLog() {
		if e.Op == "start" {
			started[e.Domain] = true
		}
	}
	if started["held-stop"] || started["held-run"] {
		t.Errorf("a VM its marker holds was started: %v", started)
	}
	if !started["free-stop"] {
		t.Errorf("the unmarked VM was not restarted (the test does not reach the restart): %v", started)
	}
}

// The rename that makes a marker visible is made durable by an fsync of its
// directory, after the rename.
//
// Red on 195477326: does not compile (operatorStopSyncDir is new).
// Mutation: the directory fsync after the rename dropped — red.
func TestWriteOperatorStopMarker_FsyncsTheDirectoryAfterTheRename(t *testing.T) {
	dir := t.TempDir()
	final, _ := OperatorStopMarkerPath(dir, "web")
	synced := false
	prev := operatorStopSyncDir
	operatorStopSyncDir = func(d string) error {
		if d == OperatorStopMarkerDir(dir) {
			if _, err := os.Stat(final); err == nil {
				synced = true
			}
		}
		return prev(d)
	}
	t.Cleanup(func() { operatorStopSyncDir = prev })
	if err := WriteOperatorStopMarker(dir, OperatorStopMarker{VM: "web", Host: "a", Incarnation: "i"}); err != nil {
		t.Fatal(err)
	}
	if !synced {
		t.Error("the marker directory was not fsynced after the rename")
	}
}

// A health-check restart (healthRestart, which every health restart and the
// restart policy run under the VM lock) does not start a VM its marker holds,
// nor destroy it first.
//
// Mutation: the healthRestart gate dropped —
// web is destroyed and started: red.
func TestHealthRestart_HonoursOperatorStopMarker(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	fake := libvirtfake.New()
	dataDir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node-a", State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(`<domain type='kvm'><name>web</name></domain>`); err != nil {
		t.Fatal(err)
	}
	row, err := corrosion.GetVM(ctx, db, "web")
	if err != nil || row == nil {
		t.Fatal(err)
	}
	if err := WriteOperatorStopMarker(dataDir, OperatorStopMarker{VM: "web", Host: "node-a",
		Incarnation: corrosion.IncarnationOf(row.CreatedAt), OwnerEpoch: row.OwnerEpoch}); err != nil {
		t.Fatal(err)
	}
	v := NewVMChecker("node-a", dataDir, db, nil)
	v.SetBackend(fake)
	_, started, _ := v.healthRestart(ctx, *row, "health check restart", nil)
	if started {
		t.Error("a health restart started a VM its marker holds")
	}
	for _, e := range fake.EventLog() {
		if e.Domain == "web" && (e.Op == "start" || e.Op == "destroy") {
			t.Errorf("health restart of a held VM: libvirt %s", e.Op)
		}
	}
}

// A marker waiting for its replay names its row's owner epoch; the owner-epoch
// backfill (0 to 1) would move it from under the marker, and the VM would no
// longer be held. The backfill waits while the replay reports a marker
// pending, and runs once none is.
//
// Red on 195477326: does not compile (the replay hook reports nothing).
// Mutation: the backfill run regardless — the row graduates while pending:
// red; the wait not logged — red.
func TestReconciler_OwnerEpochBackfillWaitsForPendingMarkers(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "web", HostName: "node-a", State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	epoch := func() int64 {
		row, err := corrosion.GetVM(ctx, db, "web")
		if err != nil || row == nil {
			t.Fatal(err)
		}
		return row.OwnerEpoch
	}
	if epoch() != 0 {
		t.Skip("setup: InsertVM no longer writes a pre-epoch row")
	}
	r := NewReconciler("node-a", t.TempDir(), db, libvirtfake.New())
	r.SetOwnerEpochBackfill(true)
	pending := true
	r.SetOperatorStopReplay(func(context.Context) bool { return pending })
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	operatorStopBackfillWait.mu.Lock()
	operatorStopBackfillWait.last = time.Time{}
	operatorStopBackfillWait.mu.Unlock()
	r.ReconcileOnce(ctx)
	if e := epoch(); e != 0 {
		t.Errorf("the backfill graduated a row (epoch %d) while a marker waited for its replay", e)
	}
	if !strings.Contains(buf.String(), "owner-epoch backfill waits") {
		t.Errorf("the backfill's wait was not logged:\n%s", buf.String())
	}
	pending = false
	r.ReconcileOnce(ctx)
	if e := epoch(); e == 0 {
		t.Errorf("the backfill did not run once no marker was pending")
	}
}
