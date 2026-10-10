package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// replNotifyServer is a server whose replication.* notifications land in rec.
func replNotifyServer(t *testing.T) (*Server, *hookRecorder) {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	rec := &hookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n notify.Notification
		_ = json.NewDecoder(r.Body).Decode(&n)
		rec.mu.Lock()
		rec.got = append(rec.got, n)
		rec.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	if err := corrosion.InsertNotificationTarget(ctx, s.db, corrosion.NotificationTarget{ID: "t1", Name: "hook", Type: "webhook", Config: string(cfg), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertNotificationRoute(ctx, s.db, corrosion.NotificationRoute{ID: "r1", EventPattern: "replication.*", TargetID: "t1", MinSeverity: "info", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	return s, rec
}

func auditCount(t *testing.T, s *Server, action string) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT COUNT(*) AS n FROM audit_log WHERE action = ?`, action)
	if err != nil || len(rows) != 1 {
		t.Fatalf("count audit rows: %v", err)
	}
	return int(rows[0].Int64("n"))
}

// settled waits long enough for any in-flight webhook delivery and returns
// what arrived.
func settled(rec *hookRecorder) []string {
	time.Sleep(300 * time.Millisecond)
	return rec.kinds()
}

// I4: a target that stays down is reported once when it goes down, then at most
// hourly, and once when it comes back; audit rows only on the transitions.
func TestReplicationOutcome_ReportsTransitionsNotTicks(t *testing.T) {
	s, rec := replNotifyServer(t)
	ctx := context.Background()
	sched := corrosion.BackupScheduleRecord{VMName: corrosion.ContainerScheduleKey("_default", "web"), Repo: "dr", TargetHost: "host-b"}
	down := &replTargetDownError{host: "host-b"}
	for i := 0; i < 12; i++ { // an hour of */5 ticks
		s.replicationOutcome(ctx, sched, "container", "web", "_default", "host-b", "dr", "", down)
	}
	if got := settled(rec); len(got) != 1 || got[0] != "replication.failed/warn" {
		t.Fatalf("a target down for 12 ticks notified %v, want one warning", got)
	}
	if n := auditCount(t, s, "ct.replicate"); n != 1 {
		t.Fatalf("%d audit rows for one outage, want 1", n)
	}
	// An hour on, the same failure is re-notified once, with no audit row.
	st := s.replState(sched)
	s.replRuns.mu.Lock()
	st.lastNotified = time.Now().Add(-replRenotifyEvery - time.Minute)
	s.replRuns.mu.Unlock()
	s.replicationOutcome(ctx, sched, "container", "web", "_default", "host-b", "dr", "", down)
	s.replicationOutcome(ctx, sched, "container", "web", "_default", "host-b", "dr", "", down)
	if got := settled(rec); len(got) != 2 {
		t.Fatalf("after an hour: %v, want exactly one more notification", got)
	}
	if n := auditCount(t, s, "ct.replicate"); n != 1 {
		t.Fatalf("a continuing failure wrote audit rows: %d", n)
	}
	// Another kind of failure is a transition.
	s.replicationOutcome(ctx, sched, "container", "web", "_default", "host-b", "dr", "", status.Error(codes.Internal, "disk full"))
	// Recovery is a transition; further successes are not.
	for i := 0; i < 3; i++ {
		s.replicationOutcome(ctx, sched, "container", "web", "_default", "host-b", "dr", "ok", nil)
	}
	got := settled(rec)
	if len(got) != 4 || got[2] != "replication.failed/error" || got[3] != "replication.recovered/info" {
		t.Fatalf("notifications %v, want a new error class and one recovery", got)
	}
	if n := auditCount(t, s, "ct.replicate"); n != 3 {
		t.Fatalf("%d audit rows, want 3 (down, new class, recovered)", n)
	}
}

// A daemon that restarts during an outage the schedule row already records does
// not page again on its first tick.
func TestReplicationOutcome_ARestartDoesNotRepeatARecordedFailure(t *testing.T) {
	s, rec := replNotifyServer(t)
	sched := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", TargetHost: "host-b", LastRunErr: "replica target host \"host-b\" is not active"}
	s.replicationOutcome(context.Background(), sched, "vm", "web", "_default", "host-b", "dr", "", &replTargetDownError{host: "host-b"})
	if got := settled(rec); len(got) != 0 {
		t.Fatalf("a failure recorded before the restart was re-notified: %v", got)
	}
}

// M1 + I2: a run that finds the workload on its own replica target is never a
// success and does not replicate; while the move's switch is on its way it is
// skipped quietly, and past the grace it is reported as suspended, once.
func TestReplicationOutcome_OwnTargetIsSuspendedQuietlyThenReported(t *testing.T) {
	s, rec := replNotifyServer(t)
	ctx := context.Background()
	sched := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", TargetHost: s.hostName}
	for i := 0; i < 3; i++ {
		err := s.suspendedOnOwnTarget(sched, "vm", "web")
		if !errors.Is(err, errReplicationSuspended) {
			t.Fatalf("own-target run: %v", err)
		}
		s.replicationOutcome(ctx, sched, "vm", "web", "_default", s.hostName, "dr", "", err)
	}
	if got := settled(rec); len(got) != 0 {
		t.Fatalf("a run inside the grace notified %v", got)
	}
	st := s.replState(sched)
	s.replRuns.mu.Lock()
	st.ownTargetSince = time.Now().Add(-replSuspendGrace - time.Minute)
	s.replRuns.mu.Unlock()
	for i := 0; i < 3; i++ {
		s.replicationOutcome(ctx, sched, "vm", "web", "_default", s.hostName, "dr", "", s.suspendedOnOwnTarget(sched, "vm", "web"))
	}
	if got := settled(rec); len(got) != 1 || got[0] != "replication.suspended/warn" {
		t.Fatalf("past the grace: %v, want one suspended warning", got)
	}
}

// The VM runner never replicates onto the VM's own host, and says so.
func TestRunReplication_VMOnItsOwnTargetIsSuspended(t *testing.T) {
	f := newPoolFixture(t)
	sched := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", TargetHost: f.s.hostName}
	if err := f.s.RunReplication(context.Background(), sched, time.Now()); !errors.Is(err, errReplicationSuspended) {
		t.Fatalf("a VM schedule targeting the VM's own host: %v, want suspended", err)
	}
	if recs := f.s.replicaRecordsOn(context.Background(), "dr", f.s.hostName, "a", "web"); len(recs) != 0 {
		t.Fatalf("a replica was written beside the disk it protects: %+v", recs)
	}
}

// I9: an incremental run forks from the replica its checkpoint continues, and
// from no other. After a reversal the checkpoint can name a run whose replica
// the target does not hold (the new owner ran once to itself, or another period
// left a newer raw replica there): the run is then a full push, never the dirty
// extents since one checkpoint grafted onto another run's file.
func TestReplicateIncremental_ForksOnlyFromTheReplicaItsCheckpointContinues(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, "web")
	sched := corrosion.BackupScheduleRecord{VMName: "web", Repo: "dr", Type: "replication", TargetPool: "dr", KeepReplicas: 5, Incremental: true}
	data := make([]byte, 4<<20)
	run := func(ts string) *fakeBackupSource {
		replicaPeersMemos.Delete(f.s)
		setEveryHostListsReplicas(t, f.s, true)
		rd := &fakeBackupReader{data: data, extents: [][2]int64{{0, 1 << 20}}, incr: true}
		src := &fakeBackupSource{full: &fakeBackupReader{data: data, extents: [][2]int64{{0, int64(len(data))}}}, incr: rd}
		f.s.SetBackupSource(src)
		if err := f.s.replicateIncremental(ctx, sched, vm, &disks[0], f.s.hostName, ts); err != nil {
			t.Fatalf("run %s: %v", ts, err)
		}
		return src
	}
	if src := run("20261001-000000"); src.lastParentCP != "" {
		t.Fatalf("the first run has no anchor, yet forked from %q", src.lastParentCP)
	}
	// The anchor now names a run whose replica this target never received.
	if err := corrosion.SetReplicationCheckpoint(ctx, f.s.db, "web", "dr", replCheckpointName(disks[0].DiskName, "20261001-050000")); err != nil {
		t.Fatal(err)
	}
	if src := run("20261001-060000"); src.lastParentCP != "" {
		t.Fatalf("forked from checkpoint %q onto a replica it does not continue", src.lastParentCP)
	}
	// The anchor that run recorded names its own replica: incremental again.
	if src := run("20261001-070000"); src.lastParentCP != replCheckpointName(disks[0].DiskName, "20261001-060000") {
		t.Fatalf("a run whose base is its checkpoint's own replica did not fork from it: parent %q", src.lastParentCP)
	}
}

// M6: a replica that a set-aside disk copy is layered on (the overlay a
// --no-localize promotion booted, set aside by a later failover) is that copy's
// data: pruning keeps it.
func TestPruneRecordedReplicas_KeepsWhatASetAsideCopyIsLayeredOn(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	var files []string
	for _, ts := range []string{"20261001-000000", "20261001-010000", "20261001-020000"} {
		rec := newReplicaRecord("a", "web", "1", "web/dr", ts, "qcow2")
		p, err := publishRecordedReplica(ctx, f.dr, rec, func(tmp string) error {
			_ = os.Remove(tmp) // the image is created, never over a file
			return qcow2.Create(tmp, 1<<20, nil)
		})
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	disksDir := filepath.Join(f.s.dataDir, "disks")
	if err := os.MkdirAll(disksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(disksDir, "web-root.qcow2.superseded-20261002T000000.000000000Z")
	if err := qcow2.CreateWithBacking(copyPath, files[0], 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	n, err := f.s.pruneRecordedReplicas(ctx, "dr", "a", "web", "1", "web/dr", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(files[0]); err != nil {
		t.Fatalf("the replica a set-aside copy is layered on was pruned (%d deleted): %v", n, err)
	}
	if _, err := os.Stat(files[1]); err == nil {
		t.Fatal("a replica nothing uses was kept past keep_replicas")
	}
}

// I3, VM: the target refuses a replica from a host its own view says is not the
// VM's owner now: fenced, not the row's host, or at an owner epoch the row has
// moved past.
func TestAdmitVMReplicaSource_RefusesAStaleOrFencedSource(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	seedActiveHost(t, f.s, f.s.hostName, true)
	seedActiveHost(t, f.s, "host-old", true)
	push := func(source string, epoch int64) error {
		c := metadata.NewIncomingContext(mtlsAdminCtx(source), metadata.Pairs(replicaSourceMD, source, replicaEpochMD, strconv.FormatInt(epoch, 10)))
		return f.s.admitVMReplicaSource(c, "a", "web")
	}
	if err := push(f.s.hostName, 0); err != nil {
		t.Fatalf("the owner's own push: %v", err)
	}
	if err := push("host-old", 0); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a push from a host the VM's row is not on: %v", err)
	}
	if err := f.s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 4 WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	if err := push(f.s.hostName, 3); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a push at an owner epoch the row has moved past: %v", err)
	}
	if err := corrosion.UpdateHostState(ctx, f.s.db, "host-old", "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := push("host-old", 9); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a push from a fenced host: %v", err)
	}
}

// I2: a VM schedule naming the VM's own host for host-local storage would never
// run (the runner refuses to put a replica beside the disk it protects), so it
// is refused when it is made; with no target host the local pool is still used
// when no peer has it.
func TestCreateReplicationSchedule_OwnHostLocalPoolIsRefused(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{HostName: s.hostName, Name: "local-pool", Driver: "local", State: "active"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateReplicationSchedule(ctx, &pb.CreateReplicationScheduleRequest{
		Scope: "vm", VmName: "vm1", TargetPool: "local-pool", TargetHost: s.hostName, Cron: "0 0 * * *",
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an explicit own-host target on host-local storage: got %v, want InvalidArgument", err)
	}
	if _, err := s.CreateReplicationSchedule(ctx, &pb.CreateReplicationScheduleRequest{
		Scope: "vm", VmName: "vm1", TargetPool: "local-pool", Cron: "0 0 * * *",
	}); err != nil {
		t.Fatalf("no target host (the local pool when no peer has one): %v", err)
	}
}

// M6, the pool's top level: replicas written before the replica area are pruned
// by name, and keep what a set-aside copy is layered on just the same.
func TestPruneTopLevelReplicas_KeepsWhatASetAsideCopyIsLayeredOn(t *testing.T) {
	f := newPoolFixture(t)
	ctx := context.Background()
	vm, _ := corrosion.GetVM(ctx, f.s.db, "web")
	var files []string
	for _, ts := range []string{"20261001-000000", "20261001-010000", "20261001-020000"} {
		p := filepath.Join(f.dr, legacyReplicaName("web", "1", ts, "qcow2"))
		if err := qcow2.Create(p, 1<<20, nil); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	disksDir := filepath.Join(f.s.dataDir, "disks")
	if err := os.MkdirAll(disksDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(filepath.Join(disksDir, "web-root.qcow2.superseded-20261002T000000.000000000Z"), files[0], 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	f.s.pruneTopLevelReplicas(ctx, f.dr, replicaKeyOf(vm, "1"), 1)
	if _, err := os.Stat(files[0]); err != nil {
		t.Fatalf("the top-level replica a set-aside copy is layered on was pruned: %v", err)
	}
	if _, err := os.Stat(files[1]); err == nil {
		t.Fatal("a top-level replica nothing uses was kept past keep")
	}
}
