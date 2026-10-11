package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedMarkedReplica is seedReplica with the record's not-point-in-time mark.
func seedMarkedReplica(t *testing.T, poolDir, vm, disk, taken string) string {
	t.Helper()
	rec := newReplicaRecord("", vm, disk, vm+"/test", taken, "qcow2")
	rec.NotPointInTime = true
	if _, err := publishRecordedReplica(context.Background(), poolDir, rec, func(tmp string) error {
		return os.WriteFile(tmp, make([]byte, 7), 0o600)
	}); err != nil {
		t.Fatalf("seed replica %s: %v", rec.File, err)
	}
	return rec.File
}

// pitPromoteVM gives vm a root disk on a dead host, an auto-promote
// replication schedule into a local "dr" pool, and returns the pool dir.
func pitPromoteVM(t *testing.T, s *Server, vm, spec string) string {
	t.Helper()
	ctx := context.Background()
	src := filepath.Join(t.TempDir(), "root.qcow2")
	if err := os.WriteFile(src, []byte("live disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
		Name: vm, HostName: "dead-host", State: "running", Spec: spec,
	}, nil, []corrosion.DiskRecord{{
		VMName: vm, HostName: "dead-host", DiskName: "root", Path: src, StorageType: "dir",
	}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, corrosion.BackupScheduleRecord{
		VMName: vm, Repo: "dr", Type: "replication", TargetPool: "dr",
		TargetHost: s.hostName, Cron: "0 * * * *", KeepReplicas: 3, AutoPromote: true,
	}); err != nil {
		t.Fatal(err)
	}
	return replicaPoolDir(t, s, "dr")
}

func stamp(ago time.Duration) string {
	return time.Now().Add(-ago).UTC().Format("20060102-150405")
}

// The record's mark reaches a peer's listing (ListReplicas, PushReplica) and
// back. Mutation "mark dropped on the wire": replicaRecordFromPB does not
// read NotPointInTime — red.
func TestReplicaRecord_NotPointInTimeRoundTrips(t *testing.T) {
	r := newReplicaRecord("", "web", "root", "web/dr", "20261010-120000", "qcow2")
	r.NotPointInTime = true
	got, err := replicaRecordFromPB(r.toPB())
	if err != nil || !got.NotPointInTime {
		t.Fatalf("round trip = %+v, %v; the mark was lost", got, err)
	}
}

// Automatic promotion never takes a not-point-in-time replica while a
// point-in-time one exists, even an older one.
//
// Mutation "auto ignores the mark": promoteResolvedIn chooses with
// skipNotPIT false when automated — red.
func TestAutoPromote_PrefersAPointInTimeReplica(t *testing.T) {
	s := testServer(t)
	dir := pitPromoteVM(t, s, "db-1", `{}`)
	older := stamp(2 * time.Hour)
	seedReplica(t, dir, "", "db-1", "root", older, "qcow2", 7)
	seedMarkedReplica(t, dir, "db-1", "root", stamp(10*time.Minute))

	vm, _ := corrosion.GetVM(context.Background(), s.db, "db-1")
	_, reps, _, err := s.findReplicaHostPIT(context.Background(), &pb.PromoteReplicaRequest{VmName: "db-1"}, vm, "root", "dr", s.hostName, true)
	if err != nil || len(reps) != 1 || !strings.Contains(reps[0], older) {
		t.Fatalf("point-in-time choice = %v, %v; want only the older point-in-time replica", reps, err)
	}

	err = s.AutoPromoteReplica(context.Background(), "db-1", "", 0)
	if errors.Is(err, errReplicaNotPointInTime) || (err != nil && strings.Contains(err.Error(), "NOT point-in-time")) {
		t.Errorf("auto-promote went for the not-point-in-time replica: %v", err)
	}
}

// With only not-point-in-time replicas, automatic promotion holds the VM by
// default: an error the coordinator falls back on, an event (shown by
// InspectVM), a notification naming the manual command, and the replica left
// as it was.
//
// Mutation "auto promotes the only copy": holdNotPointInTime is skipped when
// no point-in-time replica exists — red. Mutation "held reason not shown":
// vmToProto does not set FailoverHeld — red.
func TestAutoPromote_HoldsWhenTheOnlyReplicaIsNotPointInTime(t *testing.T) {
	s := testServer(t)
	seen := seenNotifications(s)
	dir := pitPromoteVM(t, s, "db-2", `{}`)
	file := seedMarkedReplica(t, dir, "db-2", "root", stamp(10*time.Minute))
	path := filepath.Join(replicaOwnerDir(dir, "", "db-2"), file)
	before, _ := os.ReadFile(path)

	err := s.AutoPromoteReplica(context.Background(), "db-2", "", 0)
	if !errors.Is(err, errReplicaNotPointInTime) {
		t.Fatalf("AutoPromoteReplica = %v, want errReplicaNotPointInTime", err)
	}
	if !strings.Contains(err.Error(), "lv replication promote db-2") || !strings.Contains(err.Error(), "--accept-not-point-in-time") {
		t.Errorf("the hold does not name the manual command: %v", err)
	}
	if !slices.Contains(pitEventTypes(t, s, "db-2"), vmEventFailoverHeld) {
		t.Errorf("no held event: %v", pitEventTypes(t, s, "db-2"))
	}
	if !hasNotification(seen, "replication.promote_held") {
		t.Error("no held notification")
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != string(before) {
		t.Errorf("the replica was touched: %v", err)
	}
	pbVM, err := s.vmToProto(context.Background(), "db-2")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(pbVM.FailoverHeld, "not point-in-time") {
		t.Errorf("inspect shows failover_held %q, want the held reason", pbVM.FailoverHeld)
	}
}

// The per-VM opt-in lets automatic promotion use a not-point-in-time replica
// when it is the only one. A VM without the label is held (above).
//
// Mutation "opt-in ignored": vmAllowsAutoPromoteNotPIT returns false — red.
func TestAutoPromote_OptedInVMPromotesTheOnlyNotPointInTimeReplica(t *testing.T) {
	s := testServer(t)
	dir := pitPromoteVM(t, s, "db-3", `{"labels":{"`+corrosion.LabelAutoPromoteNotPointInTime+`":"true"}}`)
	seedMarkedReplica(t, dir, "db-3", "root", stamp(10*time.Minute))

	err := s.AutoPromoteReplica(context.Background(), "db-3", "", 0)
	if errors.Is(err, errReplicaNotPointInTime) || (err != nil && strings.Contains(err.Error(), "NOT point-in-time")) {
		t.Errorf("an opted-in VM was held: %v", err)
	}
}

// A manual promotion of a not-point-in-time replica warns and names the
// flag; with the flag it goes ahead. Works whatever the per-VM option says.
//
// Mutation "manual ignores the mark": the accept check is removed — red.
func TestManualPromote_NotPointInTimeNeedsTheAcceptFlag(t *testing.T) {
	s := testServer(t)
	dir := pitPromoteVM(t, s, "db-4", `{}`)
	seedMarkedReplica(t, dir, "db-4", "root", stamp(10*time.Minute))
	vm, _ := corrosion.GetVM(context.Background(), s.db, "db-4")
	noop := func(*pb.PromoteReplicaProgress) error { return nil }

	err := s.promoteResolved(context.Background(), &pb.PromoteReplicaRequest{VmName: "db-4", Force: true}, vm, false, noop)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--accept-not-point-in-time") {
		t.Fatalf("manual promote without the flag = %v, want a FailedPrecondition naming --accept-not-point-in-time", err)
	}
	err = s.promoteResolved(context.Background(), &pb.PromoteReplicaRequest{VmName: "db-4", Force: true, AcceptNotPointInTime: true}, vm, false, noop)
	if err != nil && strings.Contains(err.Error(), "NOT point-in-time") {
		t.Errorf("manual promote with the flag still refused: %v", err)
	}
}

// main's runner-named mirror of a marked replica (the same bytes at the
// pool's top level) is marked too: the mark cannot be dodged by its name.
//
// Mutation "mirror unmarked": findReplicaHostPIT does not mark top-level
// names by the record's time — red.
func TestFindReplicaHost_TopLevelMirrorOfAMarkedReplicaIsMarked(t *testing.T) {
	s := testServer(t)
	dir := pitPromoteVM(t, s, "db-5", `{}`)
	taken := stamp(10 * time.Minute)
	seedMarkedReplica(t, dir, "db-5", "root", taken)
	mirror := legacyReplicaName("db-5", "root", taken, "qcow2")
	if err := os.WriteFile(filepath.Join(dir, mirror), make([]byte, 7), 0o600); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(context.Background(), s.db, "db-5")
	_, reps, marks, err := s.findReplicaHostPIT(context.Background(), &pb.PromoteReplicaRequest{VmName: "db-5"}, vm, "root", "dr", s.hostName, false)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(reps, mirror) {
		t.Skipf("the top-level mirror is not a candidate here (%v)", reps)
	}
	if !marks[mirror] {
		t.Errorf("the mirror %s of a not-point-in-time replica is not marked: %v", mirror, marks)
	}
}
