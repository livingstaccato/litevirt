package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

func newReplicaRepo(t *testing.T) *pbsstore.Repo {
	t.Helper()
	r, err := pbsstore.Init(filepath.Join(t.TempDir(), "repo"))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// replicaManifest builds a container manifest. mark nil makes it a backup.
func replicaManifest(name, ts, project, owner string, mark *containerReplicaMark) *pbsstore.Manifest {
	spec := containerBackupSpec{Name: name, Project: project, Replica: mark,
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{OwnerID: owner})}
	b, _ := json.Marshal(spec)
	return &pbsstore.Manifest{VMName: name, DiskName: containerBackupDisk, Timestamp: ts, ContainerSpecJSON: string(b)}
}

func put(t *testing.T, r *pbsstore.Repo, m *pbsstore.Manifest) {
	t.Helper()
	if err := r.PutManifest(m); err != nil {
		t.Fatal(err)
	}
}

func timestampsOf(t *testing.T, r *pbsstore.Repo, name string) map[string]bool {
	t.Helper()
	ms, err := r.ManifestsFor(context.Background(), name, containerBackupDisk)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, m := range ms {
		out[m.Timestamp] = true
	}
	return out
}

func mk(stream, source string, epoch int64, keep int) *containerReplicaMark {
	return &containerReplicaMark{Stream: stream, Source: source, Epoch: epoch, Keep: keep}
}

func TestAdmitContainerReplica_RefusesAnEarlierGeneration(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-b", 3, 0)))
	err := admitContainerReplica(context.Background(), r,
		replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-a", 2, 0)))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an earlier ownership generation must be refused even with a newer timestamp, got %v", err)
	}
}

func TestAdmitContainerReplica_RefusesAnOlderCopyFromTheSameSource(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 0)))
	err := admitContainerReplica(context.Background(), r,
		replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 0)))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an older copy from the same generation and source must be refused, got %v", err)
	}
}

func TestAdmitContainerReplica_AdmitsNewerAndOtherStreams(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 0)))
	ctx := context.Background()
	for name, m := range map[string]*pbsstore.Manifest{
		"newer same generation": replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 0)),
		"later generation":      replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", mk("s", "host-b", 4, 0)),
		"another stream":        replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", mk("other", "host-a", 1, 0)),
		"another lineage":       replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o2", mk("s", "host-a", 1, 0)),
		"another project":       replicaManifest("web", "2026-01-01T00:00:00Z", "prod", "o1", mk("s", "host-a", 1, 0)),
		"a backup":              replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", nil),
	} {
		if err := admitContainerReplica(ctx, r, m); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestSettleContainerReplicas_KeepsTheNewestN(t *testing.T) {
	r := newReplicaRepo(t)
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z", "2026-01-04T00:00:00Z"} {
		put(t, r, replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", 3, 2)))
	}
	newest := replicaManifest("web", "2026-01-04T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 2))
	settleContainerReplicas(context.Background(), r, newest)
	got := timestampsOf(t, r, "web")
	if len(got) != 2 || !got["2026-01-04T00:00:00Z"] || !got["2026-01-03T00:00:00Z"] {
		t.Fatalf("want the newest 2 kept, got %v", got)
	}
}

func TestSettleContainerReplicas_NeverTouchesABackupOrAnotherContainersReplica(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", nil))                         // a backup
	put(t, r, replicaManifest("web", "2026-01-01T01:00:00Z", "_default", "o2", mk("s", "host-a", 1, 1)))     // another lineage
	put(t, r, replicaManifest("web", "2026-01-01T02:00:00Z", "prod", "o1", mk("s", "host-a", 1, 1)))         // another project
	put(t, r, replicaManifest("web", "2026-01-01T03:00:00Z", "_default", "o1", mk("other", "host-a", 1, 1))) // another stream
	put(t, r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", 5, 1)))
	settleContainerReplicas(context.Background(), r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", 5, 1)))
	if got := timestampsOf(t, r, "web"); len(got) != 5 {
		t.Fatalf("only this stream's own superseded replicas may go; got %v", got)
	}
}

func TestSettleContainerReplicas_SupersededGenerationsAndSourcesGo(t *testing.T) {
	r := newReplicaRepo(t)
	// Earlier generation from the same host, and the same generation from another
	// host (the container moved): both superseded whatever their timestamps say.
	put(t, r, replicaManifest("web", "2026-02-01T00:00:00Z", "_default", "o1", mk("s", "host-a", 2, 0)))
	put(t, r, replicaManifest("web", "2026-02-02T00:00:00Z", "_default", "o1", mk("s", "host-c", 3, 0)))
	put(t, r, replicaManifest("web", "2026-01-05T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 0)))
	settleContainerReplicas(context.Background(), r, replicaManifest("web", "2026-01-05T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 0)))
	got := timestampsOf(t, r, "web")
	if len(got) != 1 || !got["2026-01-05T00:00:00Z"] {
		t.Fatalf("a replica of an earlier generation, or of another source at this one, must go regardless of clocks; got %v", got)
	}
}

func TestSettleContainerReplicas_KeepZeroKeepsEverythingCurrent(t *testing.T) {
	r := newReplicaRepo(t)
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"} {
		put(t, r, replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", 3, 0)))
	}
	settleContainerReplicas(context.Background(), r, replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-a", 3, 0)))
	if got := timestampsOf(t, r, "web"); len(got) != 3 {
		t.Fatalf("keep 0 keeps all, got %v", got)
	}
}

func seedCTRow(t *testing.T, s *Server, host, name, project, onFail string) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: host, Name: name, State: "running", Image: "alpine", Project: project, OnHostFailure: onFail,
	}); err != nil {
		t.Fatal(err)
	}
}

func seedActiveHost(t *testing.T, s *Server, name string, lxc bool) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: name, Address: "10.0.0.2", State: "active"}); err != nil {
		t.Fatal(err)
	}
	v := "false"
	if lxc {
		v = "true"
	}
	if err := corrosion.SetHostLabel(ctx, s.db, name, corrosion.LabelLXCCapable, v); err != nil {
		t.Fatal(err)
	}
}

func ctSchedReq(name, host, repo string) *pb.CreateReplicationScheduleRequest {
	return &pb.CreateReplicationScheduleRequest{
		VmName: name, Scope: "container", Cron: "0 * * * *", TargetHost: host, TargetPool: repo, Enabled: true, KeepReplicas: 2,
	}
}

func TestCreateContainerReplicationSchedule_UnverifiableRepoIsNotStored(t *testing.T) {
	s := testServer(t)
	seedActiveHost(t, s, "host-b", true)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	// The target host is remote; the repo probe needs a peer, which this unit
	// test has none of: an unreachable peer must refuse rather than store.
	_, err := s.CreateReplicationSchedule(adminCtx(), ctSchedReq("web", "host-b", "dr"))
	if err == nil {
		t.Fatal("a schedule whose target repo cannot be verified must not be stored")
	}
	rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 0 {
		t.Fatalf("a refused schedule was stored: %+v", rows)
	}
}

func TestCreateContainerReplicationSchedule_Refusals(t *testing.T) {
	s := testServer(t)
	seedActiveHost(t, s, "host-b", true)
	seedActiveHost(t, s, "host-nolxc", false)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	seedCTRow(t, s, "test-host", "plain", "_default", "")
	ctx := adminCtx()
	cases := []struct {
		name string
		req  *pb.CreateReplicationScheduleRequest
		want codes.Code
	}{
		{"onto its own host", ctSchedReq("web", "test-host", "dr"), codes.InvalidArgument},
		{"missing target host", ctSchedReq("web", "", "dr"), codes.InvalidArgument},
		{"missing repo", ctSchedReq("web", "host-b", ""), codes.InvalidArgument},
		{"unknown container", ctSchedReq("ghost", "host-b", "dr"), codes.NotFound},
		{"target cannot run containers", ctSchedReq("web", "host-nolxc", "dr"), codes.FailedPrecondition},
		{"unknown target host", ctSchedReq("web", "nowhere", "dr"), codes.FailedPrecondition},
	}
	inc := ctSchedReq("web", "host-b", "dr")
	inc.Incremental = true
	cases = append(cases, struct {
		name string
		req  *pb.CreateReplicationScheduleRequest
		want codes.Code
	}{"incremental is a VM-disk notion", inc, codes.InvalidArgument})
	ap := ctSchedReq("plain", "host-b", "dr")
	ap.AutoPromote = true
	cases = append(cases, struct {
		name string
		req  *pb.CreateReplicationScheduleRequest
		want codes.Code
	}{"auto-promote needs a failover policy", ap, codes.FailedPrecondition})
	for _, c := range cases {
		_, err := s.CreateReplicationSchedule(ctx, c.req)
		if status.Code(err) != c.want {
			t.Errorf("%s: got %v, want code %v", c.name, err, c.want)
		}
	}
}

func TestContainerReplicationSchedule_ListAndDeleteUseTheContainerName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	rec := corrosion.BackupScheduleRecord{
		VMName: corrosion.ContainerScheduleKey("web"), ProjectName: "_default", Scope: "container",
		Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b",
	}
	if err := corrosion.UpsertBackupSchedule(context.Background(), s.db, rec); err != nil {
		t.Fatal(err)
	}
	resp, err := s.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
	if err != nil || len(resp.Schedules) != 1 {
		t.Fatalf("list: %v %v", resp, err)
	}
	if got := resp.Schedules[0]; got.VmName != "web" || got.Scope != "container" {
		t.Fatalf("a container schedule must list as its container, got vm %q scope %q", got.VmName, got.Scope)
	}
	// Removable though its container is gone: the row carries its own project.
	if _, err := s.DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{VmName: "web", Scope: "container", TargetPool: "dr"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 0 {
		t.Fatalf("schedule not removed: %+v", rows)
	}
}

func TestRunContainerReplication_RefusesItsOwnHostAndAnInactiveTarget(t *testing.T) {
	s := testServer(t)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	seedActiveHost(t, s, "host-b", true)
	base := corrosion.BackupScheduleRecord{
		VMName: corrosion.ContainerScheduleKey("web"), ProjectName: "_default", Scope: "container",
		Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr",
	}
	self := base
	self.TargetHost = "test-host"
	if err := s.runContainerReplication(context.Background(), self, time.Now()); err == nil {
		t.Fatal("a replica onto the container's own host protects nothing and must be refused")
	}
	gone := base
	gone.TargetHost = "ghost"
	if err := s.runContainerReplication(context.Background(), gone, time.Now()); err == nil {
		t.Fatal("an unknown target host must be refused")
	}
	// Not ours: another host's container is that host's scheduler's to run.
	other := base
	other.VMName = corrosion.ContainerScheduleKey("elsewhere")
	other.TargetHost = "host-b"
	if err := s.runContainerReplication(context.Background(), other, time.Now()); err != nil {
		t.Fatalf("a container this host does not hold is not an error: %v", err)
	}
}

// Reversing a schedule onto the host a workload left puts new replicas there; it
// must never replace a copy that host already holds. A replica is published
// no-clobber, so a second write of the same replica fails and the first stands.
func TestPublishRecordedReplica_NeverReplacesAnExistingReplica(t *testing.T) {
	dir := t.TempDir()
	rec := newReplicaRecord("_default", "web", "root", "sched", "20260101-000000", "qcow2")
	write := func(content string) func(string) error {
		return func(tmp string) error { return os.WriteFile(tmp, []byte(content), 0o644) }
	}
	path, err := publishRecordedReplica(context.Background(), dir, rec, write("the newer copy"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publishRecordedReplica(context.Background(), dir, rec, write("an older copy")); err == nil {
		t.Fatal("a second replica with the same name must be refused, not written over the first")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "the newer copy" {
		t.Fatalf("the existing replica was overwritten: %q", got)
	}
}
