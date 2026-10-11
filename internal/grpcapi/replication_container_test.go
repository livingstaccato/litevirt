package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
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
// A replica is captured at its timestamp unless capturedAs says otherwise.
func replicaManifest(name, ts, project, owner string, mark *containerReplicaMark) *pbsstore.Manifest {
	spec := containerBackupSpec{Name: name, Project: project, Replica: mark,
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{OwnerID: owner})}
	if mark != nil {
		spec.CapturedAt = ts
	}
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

// mk is a replica mark of segment (source, placement).
func mk(stream, source, placement string, keep int, bases ...replicaBase) *containerReplicaMark {
	return &containerReplicaMark{Stream: stream, Source: source, Placement: placement, Keep: keep, Bases: bases}
}

// capturedAs is m with its capture instant set to at.
func capturedAs(m *pbsstore.Manifest, at string) *pbsstore.Manifest {
	spec, _ := manifestSpec(m)
	spec.CapturedAt = at
	b, _ := json.Marshal(spec)
	m.ContainerSpecJSON = string(b)
	return m
}

// admitT runs admitContainerReplica on a server that holds no rows (the
// target's own view does not judge), as a replica namespace.
func admitT(t *testing.T, r *pbsstore.Repo, m *pbsstore.Manifest) error {
	t.Helper()
	s := testServer(t)
	for _, h := range []string{"host-a", "host-b", "host-d"} {
		seedActiveHost(t, s, h, true)
	}
	return s.admitContainerReplica(context.Background(), r, m, true, "")
}

func TestAdmitContainerReplica_RefusesAnOlderCopyOfTheSameSegment(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	err := admitT(t, r, replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("an older copy of the same segment must be refused, got %v", err)
	}
}

// A replica a held replica's provenance chain contains is older than it,
// whatever the clocks say: the newer copy is never replaced by an older one.
func TestAdmitContainerReplica_RefusesACopyAHeldReplicaContains(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1",
		mk("s", "host-d", "inc-d", 0, replicaBase{Source: "host-a", Placement: "inc-a", Taken: "2026-01-05T00:00:00Z"})))
	err := admitT(t, r, replicaManifest("web", "2026-01-04T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a replica the held one descends from must be refused, got %v", err)
	}
}

func TestAdmitContainerReplica_AdmitsNewerAndUnrelated(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	for name, m := range map[string]*pbsstore.Manifest{
		"newer same segment":           replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)),
		"another segment, no relation": replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", mk("s", "host-b", "inc-b", 0)),
		"another stream":               replicaManifest("web", "2026-01-01T01:00:00Z", "_default", "o1", mk("other", "host-a", "inc-a", 0)),
		"another lineage":              replicaManifest("web", "2026-01-01T02:00:00Z", "_default", "o2", mk("s", "host-a", "inc-a", 0)),
		"another project":              replicaManifest("web", "2026-01-01T03:00:00Z", "prod", "o1", mk("s", "host-a", "inc-a", 0)),
	} {
		if err := admitT(t, r, m); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A namespace takes replicas only, a replica goes only to a namespace, and a
// replica already held is never written over.
func TestAdmitContainerReplica_NamespaceAndNoClobber(t *testing.T) {
	s := testServer(t)
	seedActiveHost(t, s, "host-a", true)
	ctx := context.Background()
	r := newReplicaRepo(t)
	held := replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0))
	put(t, r, held)
	if err := s.admitContainerReplica(ctx, r, replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", nil), true, ""); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a backup into a replica namespace: got %v", err)
	}
	if err := s.admitContainerReplica(ctx, r, replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)), false, ""); status.Code(err) != codes.InvalidArgument {
		t.Errorf("a replica into a backup repo: got %v", err)
	}
	if err := s.admitContainerReplica(ctx, r, replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)), true, ""); status.Code(err) != codes.AlreadyExists {
		t.Errorf("a replica with a held replica's timestamp: got %v", err)
	}
	if err := s.admitContainerReplica(ctx, r, replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)), true, "host-z"); status.Code(err) != codes.PermissionDenied {
		t.Errorf("a replica pushed by a host other than its source: got %v", err)
	}
}

// The target judges a push by its own view of who owns the container: a
// fenced source, a row on another host, a later owner epoch or another row
// incarnation refuse it; a container it holds no row for is admitted.
func TestAdmitContainerReplica_RefusesAStaleOrFencedSource(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, h := range []string{"host-a", "host-d"} {
		seedActiveHost(t, s, h, true)
	}
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "running", Image: "alpine",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Placement: "inc-a"}),
	}); err != nil {
		t.Fatal(err)
	}
	r := newReplicaRepo(t)
	push := func(source, inc string, epoch int64, name string) error {
		m := mk("s", source, inc, 0)
		m.Epoch = epoch
		return s.admitContainerReplica(ctx, r, replicaManifest(name, time.Now().UTC().Format(time.RFC3339Nano), "_default", "o1", m), true, source)
	}
	if err := push("host-a", "inc-a", 0, "web"); err != nil {
		t.Fatalf("the owner's own replica: %v", err)
	}
	// A container that has just moved, seen from here: Aborted, which the
	// sender reports as a warning, not an error page (N7).
	if err := push("host-d", "inc-d", 0, "web"); status.Code(err) != codes.Aborted {
		t.Errorf("a replica from a host the row is not on: %v", err)
	}
	if err := push("host-a", "inc-old", 0, "web"); status.Code(err) != codes.Aborted {
		t.Errorf("a replica of an earlier placement: %v", err)
	}
	if err := s.db.Execute(ctx, `UPDATE containers SET owner_epoch = 3 WHERE host_name = 'host-a' AND name = 'web'`); err != nil {
		t.Fatal(err)
	}
	if err := push("host-a", "inc-a", 2, "web"); status.Code(err) != codes.Aborted {
		t.Errorf("a replica at an owner epoch the row has moved past: %v", err)
	}
	if err := push("host-d", "inc-d", 0, "unknown-here"); err != nil {
		t.Errorf("a container this host holds no row for is not judged: %v", err)
	}
	if err := corrosion.UpdateHostState(ctx, s.db, "host-a", "fenced"); err != nil {
		t.Fatal(err)
	}
	if err := push("host-a", "inc-a", 3, "web"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a replica from a fenced host: %v", err)
	}
}

func TestSettleContainerReplicas_KeepsTheNewestNOfTheSegment(t *testing.T) {
	r := newReplicaRepo(t)
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z", "2026-01-04T00:00:00Z"} {
		put(t, r, replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", "inc-a", 2)))
	}
	settleContainerReplicas(context.Background(), r, replicaManifest("web", "2026-01-04T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 2)))
	got := timestampsOf(t, r, "web")
	if len(got) != 2 || !got["2026-01-04T00:00:00Z"] || !got["2026-01-03T00:00:00Z"] {
		t.Fatalf("want the newest 2 kept, got %v", got)
	}
}

func TestSettleContainerReplicas_NeverTouchesABackupOrAnotherContainersReplica(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", nil))                               // a backup
	put(t, r, replicaManifest("web", "2026-01-01T01:00:00Z", "_default", "o2", mk("s", "host-a", "inc-a", 1)))     // another lineage
	put(t, r, replicaManifest("web", "2026-01-01T02:00:00Z", "prod", "o1", mk("s", "host-a", "inc-a", 1)))         // another project
	put(t, r, replicaManifest("web", "2026-01-01T03:00:00Z", "_default", "o1", mk("other", "host-a", "inc-a", 1))) // another stream
	put(t, r, replicaManifest("web", "2026-01-01T04:00:00Z", "_default", "", mk("s", "host-a", "inc-a", 1)))       // no lineage recorded
	m := replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 1))
	put(t, r, m)
	if aside := settleContainerReplicas(context.Background(), r, m); len(aside) != 0 {
		t.Fatalf("set aside another stream's or lineage's replicas: %v", aside)
	}
	if got := timestampsOf(t, r, "web"); len(got) != 6 {
		t.Fatalf("only this stream's own superseded replicas may go; got %v", got)
	}
}

// C1: the container came back up somewhere else, not from its replica (an image
// re-create, a backup, a placement that could not use the replica host), and the
// new owner's first replica arrives. Nothing proves the new data contains the
// earlier replicas, which are the newest copy of the container's data: they are
// set aside, reported once, and kept.
func TestSettleContainerReplicas_AnUnprovenEarlierSegmentIsSetAsideNotDeleted(t *testing.T) {
	r := newReplicaRepo(t)
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z"} {
		put(t, r, replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", "inc-a", 1)))
	}
	m := replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1", mk("s", "host-d", "inc-d", 1))
	put(t, r, m)
	aside := settleContainerReplicas(context.Background(), r, m)
	if got := timestampsOf(t, r, "web"); len(got) != 3 {
		t.Fatalf("an earlier segment's replicas were deleted without proof: %v", got)
	}
	if len(aside) != 2 {
		t.Fatalf("want both earlier replicas set aside (and reported), got %d", len(aside))
	}
	if _, ok := readSetAside(r, "web", "2026-01-01T01:00:00Z"); !ok {
		t.Fatal("no set-aside record")
	}
	m2 := replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-d", "inc-d", 1))
	put(t, r, m2)
	if again := settleContainerReplicas(context.Background(), r, m2); len(again) != 0 {
		t.Fatalf("a replica already set aside was reported again: %d", len(again))
	}
	got := timestampsOf(t, r, "web")
	if !got["2026-01-01T00:00:00Z"] || !got["2026-01-01T01:00:00Z"] || got["2026-01-02T00:00:00Z"] {
		t.Fatalf("keep applies within the new segment only; set-aside replicas stay: %v", got)
	}
}

// When the new data provably descends from an earlier replica (the restore laid
// it down from that replica, a migrate carried it), every replica of that segment
// taken at or before that point is contained in it and goes; a later one of the
// same segment is not contained and is set aside.
func TestSettleContainerReplicas_AProvenEarlierSegmentGoes(t *testing.T) {
	r := newReplicaRepo(t)
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "2026-01-01T02:00:00Z"} {
		put(t, r, replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	}
	m := replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1",
		mk("s", "host-d", "inc-d", 0, replicaBase{Source: "host-a", Placement: "inc-a", Taken: "2026-01-01T01:00:00Z"}))
	put(t, r, m)
	aside := settleContainerReplicas(context.Background(), r, m)
	got := timestampsOf(t, r, "web")
	if got["2026-01-01T00:00:00Z"] || got["2026-01-01T01:00:00Z"] {
		t.Fatalf("replicas the new data contains must go: %v", got)
	}
	if !got["2026-01-01T02:00:00Z"] || len(aside) != 1 || aside[0].Timestamp != "2026-01-01T02:00:00Z" {
		t.Fatalf("a replica taken after the point the new data descends from must be set aside: %v (aside %v)", got, aside)
	}
}

func TestSettleContainerReplicas_KeepZeroKeepsEverythingCurrent(t *testing.T) {
	r := newReplicaRepo(t)
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"} {
		put(t, r, replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	}
	settleContainerReplicas(context.Background(), r, replicaManifest("web", "2026-01-03T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	if got := timestampsOf(t, r, "web"); len(got) != 3 {
		t.Fatalf("keep 0 keeps all, got %v", got)
	}
}

// M7: a container deleted and re-created under its name without an owner_id is
// another container; the old one's replicas neither block nor are pruned by it.
func TestSameReplicaStream_NoRecordedLineageIsAnotherLineage(t *testing.T) {
	r := newReplicaRepo(t)
	put(t, r, replicaManifest("web", "2026-01-05T00:00:00Z", "_default", "", mk("s", "host-a", "inc-old", 0,
		replicaBase{Source: "host-a", Placement: "inc-new", Taken: "2026-02-01T00:00:00Z"})))
	if err := admitT(t, r, replicaManifest("web", "2026-01-06T00:00:00Z", "_default", "o-new", mk("s", "host-a", "inc-new", 0))); err != nil {
		t.Fatalf("an unrelated lineage's replica blocked a new container's: %v", err)
	}
}

// A replica namespace is a store of its own under the repo: a push named for it
// lands there, the repo's backup retention and a backup restore's search never
// see it, and a replica is never taken for a backup.
func TestReplicaNamespace_IsApartFromBackups(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	base := filepath.Join(t.TempDir(), "dr")
	br, err := pbsstore.Init(base)
	if err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"dr": base})
	ns, err := s.resolveRepoTarget(ctx, &pb.RepoTarget{RepoName: containerReplicaRepo("_default", "dr")})
	if err != nil {
		t.Fatal(err)
	}
	if ns.Root() == br.Root() || filepath.Dir(filepath.Dir(ns.Root())) != base {
		t.Fatalf("namespace root %q is not a store of its own under %q", ns.Root(), base)
	}
	put(t, br, replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", nil)) // the backup
	for _, ts := range []string{"2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z", "2026-01-04T00:00:00Z"} {
		put(t, ns, replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	}
	plan, err := pbsstore.PlanPrune(br, pbsstore.RetentionPolicy{KeepLast: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Keep) != 1 || plan.Keep[0].Timestamp != "2026-01-01T00:00:00Z" || len(plan.Delete) != 0 {
		t.Fatalf("keep_last=1 on the repo must keep its one backup, untouched by replicas: %+v", plan)
	}
	if _, ts, err := s.findLatestContainerBackupFor("web", nil); err != nil || ts != "2026-01-01T00:00:00Z" {
		t.Fatalf("a restore's newest backup = %q (%v), want the backup, never a replica", ts, err)
	}
	// Even a replica that found its way into a backup repo is not a backup.
	put(t, br, replicaManifest("web", "2026-01-09T00:00:00Z", "_default", "o1", mk("s", "host-a", "inc-a", 0)))
	if _, ts, _ := s.findLatestContainerBackupFor("web", nil); ts != "2026-01-01T00:00:00Z" {
		t.Fatalf("a replica in a backup repo was taken for a backup: %q", ts)
	}
	if path, err := s.resolveBackupRepoPath(ctx, containerReplicaRepo("_default", "dr")); err != nil || path != ns.Root() {
		t.Fatalf("a restore names the namespace by its wire name: %q %v", path, err)
	}
}

// A replica is laid down only by a failover coordinator's relocation; an
// operator restore and a cold migrate are refused.
func TestAdmitReplicaPromotion_OnlyAPeerRelocation(t *testing.T) {
	s := testServer(t)
	mark := mk("s", "host-a", "inc-a", 0)
	if err := s.admitReplicaPromotion(adminCtx(), &pb.RestoreContainerRequest{Name: "web", Timestamp: "2026-01-01T00:00:00Z"}, mark); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator restore of a replica: got %v", err)
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

// replicaPeer answers ListContainerReplicas as a target host on this build.
type replicaPeer struct {
	pb.LiteVirtClient
	err  error
	reps []*pb.ContainerReplica
}

func (p *replicaPeer) ListContainerReplicas(context.Context, *pb.ListContainerReplicasRequest, ...grpc.CallOption) (*pb.ListContainerReplicasResponse, error) {
	if p.err != nil {
		return nil, p.err
	}
	return &pb.ListContainerReplicasResponse{Replicas: p.reps}, nil
}

// openCTGate opens the release features on s, container_replication among
// them, as a latched release token's gate does in production.
func openCTGate(t *testing.T, s *Server) {
	t.Helper()
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
}

// putCTSchedule stores a container's schedule as its release gate lets it be
// written: through its writer, with the container_replication grant.
func putCTSchedule(t *testing.T, s *Server, rec corrosion.BackupScheduleRecord) {
	t.Helper()
	if err := corrosion.UpsertContainerReplicationSchedule(context.Background(), s.db,
		capabilities.GrantForTest(t, capabilities.FeatureContainerReplication), rec); err != nil {
		t.Fatal(err)
	}
}

// orderedFeatureGate is a passing release gate that notes, when the write
// runs, which feature it was for and whether the schedule row already existed.
type orderedFeatureGate struct {
	t        *testing.T
	s        *Server
	features *[]capabilities.Feature
	rowFirst *bool
}

func (g orderedFeatureGate) WithFeature(ctx context.Context, f capabilities.Feature,
	write func(context.Context, capabilities.FeatureGrant) error) error {
	*g.features = append(*g.features, f)
	if rows, _ := corrosion.ListBackupSchedules(ctx, g.s.db); len(rows) != 0 {
		*g.rowFirst = true
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g orderedFeatureGate) FeatureAvailable(capabilities.Feature) bool { return true }

// ctReleaseRefusal is the refusal of a container_replication write before the
// release token has latched.
const ctReleaseRefusal = "the cluster upgrade must finish first (container_replication needs " + capabilities.ReleaseToken + ")"

func TestCreateContainerReplicationSchedule_UnverifiableRepoIsNotStored(t *testing.T) {
	s := testServer(t)
	openCTGate(t, s)
	seedActiveHost(t, s, "host-b", true)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	for _, perr := range []error{status.Error(codes.Unavailable, "down"), status.Error(codes.Unimplemented, "old build")} {
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return &replicaPeer{err: perr}, func() {}, nil
		}
		if _, err := s.CreateReplicationSchedule(adminCtx(), ctSchedReq("web", "host-b", "dr")); err == nil {
			t.Fatalf("a schedule whose target repo cannot be verified (%v) must not be stored", perr)
		}
	}
	rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 0 {
		t.Fatalf("a refused schedule was stored: %+v", rows)
	}
}

// I8: until every host runs a release with container replication, no schedule
// row is written for an older daemon to skip, keep or mistake for a VM's.
func TestCreateContainerReplicationSchedule_RefusedBeforeTheReleaseFeature(t *testing.T) {
	s := testServer(t)
	seedActiveHost(t, s, "host-b", true)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &replicaPeer{}, func() {}, nil
	}
	_, err := s.CreateReplicationSchedule(adminCtx(), ctSchedReq("web", "host-b", "dr"))
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), ctReleaseRefusal) {
		t.Fatalf("no release gate must refuse the schedule with %q, got %v", ctReleaseRefusal, err)
	}
	// The gate's own refusal (the release token not latched) is returned as it is.
	closed := status.Error(codes.FailedPrecondition, ctReleaseRefusal+": not yet: host-b")
	s.SetReleaseFeatureGate(fakeFeatureGate{err: closed})
	if _, err := s.CreateReplicationSchedule(adminCtx(), ctSchedReq("web", "host-b", "dr")); !errors.Is(err, closed) {
		t.Fatalf("a closed release gate must refuse the schedule with its own reason, got %v", err)
	}
	if rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db); len(rows) != 0 {
		t.Fatalf("a schedule was stored with the gate closed: %+v", rows)
	}
	var features []capabilities.Feature
	rowFirst := false
	s.SetReleaseFeatureGate(orderedFeatureGate{t: t, s: s, features: &features, rowFirst: &rowFirst})
	if _, err := s.CreateReplicationSchedule(adminCtx(), ctSchedReq("web", "host-b", "dr")); err != nil {
		t.Fatalf("with the gate open: %v", err)
	}
	if rowFirst || !slices.Equal(features, []capabilities.Feature{capabilities.FeatureContainerReplication}) {
		t.Fatalf("the schedule row was written outside its release gate: gate calls %v, row before the gate %v", features, rowFirst)
	}
	if rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db); len(rows) != 1 {
		t.Fatalf("the schedule was not stored through the gate: %+v", rows)
	}
}

// Every container schedule row goes through the release gate's grant: the
// generic upsert refuses one, and the container writer refuses without the
// container_replication grant.
func TestContainerReplicationSchedule_WrittenOnlyWithTheGrant(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	rec := corrosion.BackupScheduleRecord{VMName: corrosion.ContainerScheduleKey("_default", "web"), ProjectName: "_default",
		Scope: "container", Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b"}
	if err := corrosion.UpsertBackupSchedule(ctx, s.db, rec); err == nil {
		t.Fatal("the generic schedule upsert wrote a container schedule without the release gate")
	}
	if err := corrosion.UpsertContainerReplicationSchedule(ctx, s.db, capabilities.FeatureGrant{}, rec); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("no grant: %v, want ErrNoFeatureGrant", err)
	}
	if err := corrosion.UpsertContainerReplicationSchedule(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureBackupZstd), rec); !errors.Is(err, capabilities.ErrNoFeatureGrant) {
		t.Fatalf("another feature's grant: %v, want ErrNoFeatureGrant", err)
	}
	if rows, _ := corrosion.ListBackupSchedules(ctx, s.db); len(rows) != 0 {
		t.Fatalf("a container schedule was stored without its grant: %+v", rows)
	}
	if err := corrosion.UpsertContainerReplicationSchedule(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureContainerReplication), rec); err != nil {
		t.Fatal(err)
	}
}

func TestCreateContainerReplicationSchedule_Refusals(t *testing.T) {
	s := testServer(t)
	openCTGate(t, s)
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &replicaPeer{}, func() {}, nil
	}
	seedActiveHost(t, s, "host-b", true)
	seedActiveHost(t, s, "host-nolxc", false)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	seedCTRow(t, s, "test-host", "plain", "_default", "")
	ctx := adminCtx()
	type tc struct {
		name string
		req  *pb.CreateReplicationScheduleRequest
		want codes.Code
	}
	cases := []tc{
		{"onto its own host", ctSchedReq("web", "test-host", "dr"), codes.InvalidArgument},
		{"missing target host", ctSchedReq("web", "", "dr"), codes.InvalidArgument},
		{"missing repo", ctSchedReq("web", "host-b", ""), codes.InvalidArgument},
		{"unknown container", ctSchedReq("ghost", "host-b", "dr"), codes.NotFound},
		{"target cannot run containers", ctSchedReq("web", "host-nolxc", "dr"), codes.FailedPrecondition},
		{"unknown target host", ctSchedReq("web", "nowhere", "dr"), codes.FailedPrecondition},
	}
	inc := ctSchedReq("web", "host-b", "dr")
	inc.Incremental = true
	cases = append(cases, tc{"incremental is a VM-disk notion", inc, codes.InvalidArgument})
	ap := ctSchedReq("plain", "host-b", "dr")
	ap.AutoPromote = true
	cases = append(cases, tc{"auto-promote needs a failover policy", ap, codes.FailedPrecondition})
	for _, c := range cases {
		_, err := s.CreateReplicationSchedule(ctx, c.req)
		if status.Code(err) != c.want {
			t.Errorf("%s: got %v, want code %v", c.name, err, c.want)
		}
	}
}

// I1: two projects' containers of one name replicating into one repo are two
// schedules; adding one never replaces the other's target or auto-promote.
func TestCreateContainerReplicationSchedule_TwoProjectsKeepTheirOwnSchedules(t *testing.T) {
	s := testServer(t)
	openCTGate(t, s)
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		return &replicaPeer{}, func() {}, nil
	}
	seedActiveHost(t, s, "host-b", true)
	seedActiveHost(t, s, "host-c", true)
	seedCTRow(t, s, "test-host", "web", "p1", "image-recreate")
	seedCTRow(t, s, "host-c", "web", "p2", "image-recreate")
	r1 := ctSchedReq("web", "host-b", "dr")
	r1.ProjectName, r1.AutoPromote = "p1", true
	if _, err := s.CreateReplicationSchedule(adminCtx(), r1); err != nil {
		t.Fatal(err)
	}
	r2 := ctSchedReq("web", "host-b", "dr")
	r2.ProjectName = "p2"
	if _, err := s.CreateReplicationSchedule(adminCtx(), r2); err != nil {
		t.Fatal(err)
	}
	rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 2 {
		t.Fatalf("want one schedule per project, got %+v", rows)
	}
	for _, r := range rows {
		if corrosion.ContainerScheduleIs(r, "p1", "web") && (!r.AutoPromote || r.ProjectName != "p1") {
			t.Fatalf("p2's add changed p1's schedule: %+v", r)
		}
	}
	// Without a project the delete is ambiguous; with one it removes only that one.
	if _, err := s.DeleteReplicationSchedule(adminCtx(), &pb.DeleteReplicationScheduleRequest{VmName: "web", Scope: "container", TargetPool: "dr"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("an ambiguous delete: got %v", err)
	}
	if _, err := s.DeleteReplicationSchedule(adminCtx(), &pb.DeleteReplicationScheduleRequest{VmName: "web", Scope: "container", TargetPool: "dr", ProjectName: "p2"}); err != nil {
		t.Fatal(err)
	}
	rows, _ = corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 1 || !corrosion.ContainerScheduleIs(rows[0], "p1", "web") {
		t.Fatalf("the delete removed the wrong schedule: %+v", rows)
	}
}

func TestContainerReplicationSchedule_ListAndDeleteUseTheContainerName(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	for _, key := range []string{corrosion.ContainerScheduleKey("_default", "web"), "@ct:legacy"} {
		name := "web"
		if key == "@ct:legacy" {
			name = "legacy"
		}
		rec := corrosion.BackupScheduleRecord{
			VMName: key, ProjectName: "_default", Scope: "container",
			Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b",
		}
		putCTSchedule(t, s, rec)
		resp, err := s.ListReplicationSchedules(ctx, &pb.ListReplicationSchedulesRequest{})
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, got := range resp.Schedules {
			if got.VmName == name && got.Scope == "container" {
				found = true
			}
		}
		if !found {
			t.Fatalf("a container schedule must list as its container %q: %+v", name, resp.Schedules)
		}
	}
	// Removable by name, or by the key a CLI sends, though the container is gone.
	if _, err := s.DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{VmName: "web", Scope: "container", TargetPool: "dr"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteReplicationSchedule(ctx, &pb.DeleteReplicationScheduleRequest{VmName: "@ct:legacy", Scope: "container", TargetPool: "dr"}); err != nil {
		t.Fatal(err)
	}
	rows, _ := corrosion.ListBackupSchedules(context.Background(), s.db)
	if len(rows) != 0 {
		t.Fatalf("schedule not removed: %+v", rows)
	}
}

func TestRunContainerReplication_RefusesItsOwnHostAndAnInactiveTarget(t *testing.T) {
	s := testServer(t)
	openCTGate(t, s)
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	seedActiveHost(t, s, "host-b", true)
	base := corrosion.BackupScheduleRecord{
		VMName: corrosion.ContainerScheduleKey("_default", "web"), ProjectName: "_default", Scope: "container",
		Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr",
	}
	self := base
	self.TargetHost = "test-host"
	if err := s.runContainerReplication(context.Background(), self, time.Now()); err == nil || !isSuspended(err) {
		t.Fatalf("a replica onto the container's own host protects nothing: it must be suspended, never a success: %v", err)
	}
	gone := base
	gone.TargetHost = "ghost"
	if err := s.runContainerReplication(context.Background(), gone, time.Now()); err == nil {
		t.Fatal("an unknown target host must be refused")
	}
	// Not ours: another host's container is that host's scheduler's to run.
	other := base
	other.VMName = corrosion.ContainerScheduleKey("_default", "elsewhere")
	other.TargetHost = "host-b"
	if err := s.runContainerReplication(context.Background(), other, time.Now()); err != nil {
		t.Fatalf("a container this host does not hold is not an error: %v", err)
	}
	// And nothing runs with the release feature closed.
	s.SetReleaseFeatureGate(nil)
	tb := base
	tb.TargetHost = "host-b"
	if err := s.runContainerReplication(context.Background(), tb, time.Now()); status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), ctReleaseRefusal) {
		t.Fatalf("a run with the release gate closed: %v, want %q", err, ctReleaseRefusal)
	}
}

func isSuspended(err error) bool { return errors.Is(err, errReplicationSuspended) }

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

// I3: failover promotes only a replica taken from the very row it relocates
// (its host and row incarnation) and not set aside. A newer replica a stale
// host pushed, one from an earlier segment, or a set-aside one is never chosen.
func TestContainerReplicaFor_PromotesOnlyTheRelocatingRowsReplica(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	now := time.Now().UTC()
	at := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339) }
	putCTSchedule(t, s, corrosion.BackupScheduleRecord{
		VMName: corrosion.ContainerScheduleKey("_default", "web"), ProjectName: "_default", Scope: "container",
		Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b", AutoPromote: true,
	})
	owner := &corrosion.ContainerRecord{HostName: "host-a", Name: "web", Project: "_default",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Placement: "p-a"})}
	capt := func(d time.Duration) string { return now.Add(-d).Format(time.RFC3339Nano) }
	peer := &replicaPeer{reps: []*pb.ContainerReplica{
		{Timestamp: at(50 * time.Minute), CapturedAt: capt(50 * time.Minute), Source: "host-a", Placement: "p-a"},                 // the one
		{Timestamp: at(40 * time.Minute), CapturedAt: capt(40 * time.Minute), Source: "host-x", Placement: "p-x"},                 // another segment
		{Timestamp: at(30 * time.Minute), CapturedAt: capt(30 * time.Minute), Source: "host-a", Placement: "p-old"},               // an earlier placement here
		{Timestamp: at(20 * time.Minute), CapturedAt: capt(20 * time.Minute), Source: "host-a", Placement: "p-a", SetAside: true}, // set aside
	}}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	rep, ok := s.containerReplicaFor(ctx, "web", owner, "host-b", now)
	if !ok || rep.Timestamp != at(50*time.Minute) || rep.Repo != containerReplicaRepo("_default", "dr") {
		t.Fatalf("promoted %+v (ok=%v), want the relocating row's own replica in the namespace", rep, ok)
	}
	if _, ok := s.containerReplicaFor(ctx, "web", nil, "host-b", now); ok {
		t.Fatal("with the relocating row unreadable nothing is promotable")
	}
}

// The provenance a restore recorded proves something only for the row that
// restore laid down: a later row (a re-create, another restore) gets nothing.
func TestContainerBases_OnlyForTheRowTheRestoreLaidDown(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	spec := containerBackupSpec{Source: "host-a", Placement: "p-a", CapturedAt: "2026-02-01T00:00:00Z",
		Bases: []replicaBase{{Source: "host-z", Placement: "inc-z", Taken: "2026-01-01T00:00:00Z"}}}
	s.recordContainerBases("_default", "web", "place-1", spec)
	row := func(p string) *corrosion.ContainerRecord {
		return &corrosion.ContainerRecord{Name: "web", Project: "_default",
			CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Placement: p})}
	}
	got := s.containerBases(row("place-1"))
	if len(got) != 2 || got[0] != (replicaBase{Source: "host-a", Placement: "p-a", Taken: "2026-02-01T00:00:00Z"}) {
		t.Fatalf("chain = %+v, want the archive's own point then the chain it carried", got)
	}
	// The container handed back to this host later (a relocate-recreate, a
	// re-key) is another placement: the old record proves nothing for it.
	if got := s.containerBases(row("place-2")); got != nil {
		t.Fatalf("another placement inherited the chain: %+v", got)
	}
	if got := s.containerBases(row("")); got != nil {
		t.Fatalf("a row with no placement inherited the chain: %+v", got)
	}
	// An archive whose capture is not known adds no point of its own.
	s.recordContainerBases("_default", "web", "place-3", containerBackupSpec{Source: "host-a", Placement: "p-a"})
	if got := s.containerBases(row("place-3")); len(got) != 0 {
		t.Fatalf("an archive with no capture instant proved something: %+v", got)
	}
}

// I3, sender: a host whose owner-epoch marker is ahead of the row it reads has a
// view behind the runtime it holds; it does not replicate.
func TestRunContainerReplication_RefusesWhenItsMarkerIsAhead(t *testing.T) {
	s := testServer(t)
	openCTGate(t, s)
	s.containersRoot = t.TempDir()
	seedCTRow(t, s, "test-host", "web", "_default", "image-recreate")
	seedActiveHost(t, s, "host-b", true)
	if err := health.WriteContainerOwnerEpochMarker(s.containersRoot, "web", 5); err != nil {
		t.Fatal(err)
	}
	sched := corrosion.BackupScheduleRecord{
		VMName: corrosion.ContainerScheduleKey("_default", "web"), ProjectName: "_default", Scope: "container",
		Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: "host-b",
	}
	err := s.runContainerReplication(context.Background(), sched, time.Now())
	if err == nil || !strings.Contains(err.Error(), "marker") {
		t.Fatalf("a run behind its own marker: %v, want refused", err)
	}
}

// N1: a container that returns to a host it once ran on (D, then A by an image
// re-create, then D again) is a new placement there. Its runs never trim the
// replicas of its first stay on D, the only copy of its data from before the
// loss, however many there are: keep_replicas trims one placement only.
func TestSettleContainerReplicas_AReturnToAFormerHostIsANewPlacement(t *testing.T) {
	r := newReplicaRepo(t)
	for _, ts := range []string{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "2026-01-01T02:00:00Z"} {
		put(t, r, replicaManifest("web", ts, "_default", "o1", mk("s", "host-d", "place-1", 2)))
	}
	for i, ts := range []string{"2026-02-01T00:00:00Z", "2026-02-01T01:00:00Z", "2026-02-01T02:00:00Z", "2026-02-01T03:00:00Z", "2026-02-01T04:00:00Z"} {
		m := replicaManifest("web", ts, "_default", "o1", mk("s", "host-d", "place-3", 2))
		put(t, r, m)
		settleContainerReplicas(context.Background(), r, m)
		got := timestampsOf(t, r, "web")
		for _, pre := range []string{"2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "2026-01-01T02:00:00Z"} {
			if !got[pre] {
				t.Fatalf("run %d: the pre-loss replica %s was trimmed by a later placement on the same host", i, pre)
			}
		}
	}
}

// keep_replicas never trims a set-aside replica, even one of the placement it
// trims, and a replica proven contained takes its set-aside record with it.
func TestSettleContainerReplicas_KeepNeverTrimsASetAsideReplica(t *testing.T) {
	r := newReplicaRepo(t)
	aside := replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", mk("s", "host-a", "p-a", 1))
	put(t, r, aside)
	b, _ := json.Marshal(setAsideRecord{Timestamp: aside.Timestamp, Reason: "test"})
	if err := os.MkdirAll(filepath.Dir(setAsidePath(r, "web", aside.Timestamp)), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(setAsidePath(r, "web", aside.Timestamp), b, 0o640); err != nil {
		t.Fatal(err)
	}
	for _, ts := range []string{"2026-01-02T00:00:00Z", "2026-01-03T00:00:00Z"} {
		m := replicaManifest("web", ts, "_default", "o1", mk("s", "host-a", "p-a", 1))
		put(t, r, m)
		settleContainerReplicas(context.Background(), r, m)
	}
	if !timestampsOf(t, r, "web")[aside.Timestamp] {
		t.Fatal("keep trimmed a set-aside replica")
	}
	// Proven contained by a later placement: it goes, and so does its record.
	m := replicaManifest("web", "2026-01-04T00:00:00Z", "_default", "o1",
		mk("s", "host-b", "p-b", 1, replicaBase{Source: "host-a", Placement: "p-a", Taken: "2026-01-05T00:00:00Z"}))
	put(t, r, m)
	settleContainerReplicas(context.Background(), r, m)
	if timestampsOf(t, r, "web")[aside.Timestamp] {
		t.Fatal("a set-aside replica proven contained was kept")
	}
	if _, err := os.Stat(setAsidePath(r, "web", aside.Timestamp)); err == nil {
		t.Fatal("the removed replica's set-aside record was left behind")
	}
}

// N2: a replica named for its scheduler tick but captured later is not
// "contained" in a point captured between the two.
func TestSettleContainerReplicas_ProofUsesTheCaptureNotTheName(t *testing.T) {
	r := newReplicaRepo(t)
	late := capturedAs(replicaManifest("web", "2026-01-01T10:00:00Z", "_default", "o1", mk("s", "host-a", "p-a", 0)), "2026-01-01T10:20:00Z")
	put(t, r, late)
	m := replicaManifest("web", "2026-01-02T00:00:00Z", "_default", "o1",
		mk("s", "host-b", "p-b", 0, replicaBase{Source: "host-a", Placement: "p-a", Taken: "2026-01-01T10:05:00Z"}))
	put(t, r, m)
	settleContainerReplicas(context.Background(), r, m)
	if !timestampsOf(t, r, "web")[late.Timestamp] {
		t.Fatal("a replica captured at 10:20 was deleted as contained in a point captured at 10:05")
	}
}

// N8 + N6: once no schedule replicates the container into this host and repo,
// its replicas here are orphans an operator may remove; while one does, only a
// set-aside replica goes. A forwarded removal is audited as the operator.
func TestRemoveContainerReplicas_OrphansAndTheOperatorsName(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	base := filepath.Join(t.TempDir(), "dr")
	if _, err := pbsstore.Init(base); err != nil {
		t.Fatal(err)
	}
	s.SetBackupRepos(map[string]string{"dr": base})
	ns, err := s.openReplicaNamespace(ctx, containerReplicaRepo("_default", "dr"), true)
	if err != nil {
		t.Fatal(err)
	}
	put(t, ns, replicaManifest("web", "2026-01-01T00:00:00Z", "_default", "o1", mk("s", "host-a", "p-a", 0)))
	sched := corrosion.BackupScheduleRecord{VMName: corrosion.ContainerScheduleKey("_default", "web"), ProjectName: "_default",
		Scope: "container", Repo: "dr", Cron: "0 * * * *", Enabled: true, Type: "replication", TargetPool: "dr", TargetHost: s.hostName}
	putCTSchedule(t, s, sched)
	pctx := metadata.NewIncomingContext(peerCtxFor(t, s, "entry-host"), metadata.Pairs(repairActorMDKey, "alice"))
	req := &pb.RemoveContainerReplicasRequest{Repo: "dr", Name: "web", Timestamps: []string{"2026-01-01T00:00:00Z"}}
	if _, err := s.RemoveContainerReplicas(pctx, req); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a scheduled, not set-aside replica: %v, want refused", err)
	}
	if err := corrosion.DeleteBackupSchedule(ctx, s.db, sched.VMName, "dr"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RemoveContainerReplicas(pctx, req); err != nil {
		t.Fatalf("an orphaned replica: %v", err)
	}
	if got := auditActor(t, s, "ct.replica.remove", "ok"); got != "alice" {
		t.Fatalf("the removal was audited as %q, want the operator alice", got)
	}
}

// m4 (re-review 2): the compare-and-set switch, and the placement mint of the
// same kind, are emitted only once the release token has durably latched here,
// read locally: every member answering this build's RPC is not enough (that
// was a probe, not a latch), and no peer is asked.
func TestRepointReady_FollowsTheReleaseLatch(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	seedActiveHost(t, s, "host-b", true)
	s.wireReplicationReleaseGates()
	asked := false
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
		asked = true
		return &replicaPeer{err: status.Error(codes.InvalidArgument, "name required")}, func() {}, nil
	}
	if s.repointReady(ctx) || s.db.RepointReady(ctx) {
		t.Fatal("no release gate: the switch must not be a compare-and-set")
	}
	s.SetReleaseFeatureGate(fakeFeatureGate{err: status.Error(codes.FailedPrecondition, ctReleaseRefusal)})
	if s.repointReady(ctx) || s.db.RepointReady(ctx) {
		t.Fatal("every member answers but the release token has not latched: the switch must not be a compare-and-set")
	}
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t, grant: true})
	if !s.repointReady(ctx) {
		t.Fatal("the release token has latched: the switch may be a compare-and-set")
	}
	if !s.db.RepointReady(ctx) {
		t.Fatal("the database client asks the server (the audited reversal paths use it)")
	}
	if asked {
		t.Fatal("readiness asked a peer; it reads the latch")
	}
}
