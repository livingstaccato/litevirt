package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

func secServer(t *testing.T) (*Server, *fakeCTRuntime) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	rt := &fakeCTRuntime{exportPayload: []byte("rootfs")}
	s.SetContainerRuntime(rt)
	return s, rt
}

func specOf(t *testing.T, s *Server, host, name string) corrosion.ContainerCreateSpec {
	t.Helper()
	row, err := corrosion.GetContainer(context.Background(), s.db, host, name)
	if err != nil || row == nil {
		t.Fatalf("row %s/%s: %v", host, name, err)
	}
	return corrosion.DecodeCreateSpec(row.CreateSpec)
}

// A new container is unprivileged, in a range of its own, with the default
// confinement; the range and confinement are recorded, and two containers
// never share a range — including one only another host's row records.
func TestCreateContainer_UnprivilegedByDefault(t *testing.T) {
	s, rt := secServer(t)
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-b", Name: "elsewhere", State: "stopped",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", IDMapBase: s.idmapSlotBase(s.idmapStartSlot())}),
	}); err != nil {
		t.Fatal(err)
	}
	var pbs []*pb.Container
	for _, n := range []string{"c1", "c2"} {
		ct, err := s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{Name: n, Template: "download", Distro: "alpine"})
		if err != nil {
			t.Fatal(err)
		}
		pbs = append(pbs, ct)
	}
	seen := map[int64]string{specOf(t, s, "host-b", "elsewhere").IDMapBase: "elsewhere"}
	for i, n := range []string{"c1", "c2"} {
		opts := rt.createCalls[i]
		spec := specOf(t, s, "host-a", n)
		if opts.IDMapBase == 0 || opts.IDMapBase != spec.IDMapBase || opts.Confinement != lxc.ConfinementDefault || spec.Confinement != lxc.ConfinementDefault {
			t.Fatalf("%s: runtime %+v, spec %+v", n, opts, spec)
		}
		if other, dup := seen[spec.IDMapBase]; dup {
			t.Fatalf("%s shares id range %d with %s", n, spec.IDMapBase, other)
		}
		seen[spec.IDMapBase] = n
		if pbs[i].Privileged || pbs[i].Confinement != lxc.ConfinementDefault || pbs[i].IdmapBase != spec.IDMapBase {
			t.Fatalf("%s reported as %+v", n, pbs[i])
		}
	}
}

// The opt-outs keep today's behaviour and are the admin's.
func TestCreateContainer_PrivilegedAndLegacyAreAdminOnly(t *testing.T) {
	s, rt := secServer(t)
	for _, req := range []*pb.CreateContainerRequest{
		{Name: "p1", Template: "download", Distro: "alpine", Privileged: true},
		{Name: "l1", Template: "download", Distro: "alpine", Confinement: lxc.ConfinementLegacy},
	} {
		if _, err := s.CreateContainer(ctOperatorCtx(), req); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("operator %+v: %v", req, err)
		}
	}
	if _, err := s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{Name: "x", Template: "download", Distro: "alpine", Confinement: "unconfined"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown confinement: %v", err)
	}
	if len(rt.createCalls) != 0 {
		t.Fatalf("runtime called: %+v", rt.createCalls)
	}
	ct, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{Name: "p1", Template: "download", Distro: "alpine", Privileged: true, Confinement: lxc.ConfinementLegacy})
	if err != nil {
		t.Fatal(err)
	}
	if o := rt.createCalls[0]; o.IDMapBase != 0 || o.Confinement != lxc.ConfinementLegacy {
		t.Fatalf("admin privileged legacy create: %+v", o)
	}
	if !ct.Privileged || ct.Confinement != lxc.ConfinementLegacy {
		t.Fatalf("reported as %+v", ct)
	}
}

// A container an earlier build created records nothing: it is privileged with
// legacy confinement, and reported so.
func TestContainer_PreFeatureRowReportsPrivileged(t *testing.T) {
	ct := toPbContainer(corrosion.ContainerRecord{Name: "old", CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download"})})
	if !ct.Privileged || ct.Confinement != lxc.ConfinementLegacy || ct.IdmapBase != 0 {
		t.Fatalf("pre-feature container reported as %+v", ct)
	}
}

func seedSecCT(t *testing.T, s *Server, rt *fakeCTRuntime, name, state string, spec corrosion.ContainerCreateSpec) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: name, State: state, Project: "acme", CreateSpec: corrosion.EncodeCreateSpec(spec),
	}); err != nil {
		t.Fatal(err)
	}
	if rt.stateByName == nil {
		rt.stateByName = map[string]string{}
	}
	rt.stateByName[name] = state
}

// lv ct convert --unprivileged moves a stopped privileged container into a
// fresh range and records it; a running one is refused; legacy is admin's.
func TestConvertContainer(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "old", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	seedSecCT(t, s, rt, "busy", "running", corrosion.ContainerCreateSpec{Template: "download"})

	if _, err := s.ConvertContainer(ctOperatorCtx(), &pb.ConvertContainerRequest{Name: "busy", Unprivileged: true}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("convert of a running container: %v", err)
	}
	if _, err := s.ConvertContainer(ctOperatorCtx(), &pb.ConvertContainerRequest{Name: "old", Confinement: lxc.ConfinementLegacy}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator convert to legacy: %v", err)
	}
	ct, err := s.ConvertContainer(ctOperatorCtx(), &pb.ConvertContainerRequest{Name: "old", Unprivileged: true, Confinement: lxc.ConfinementDefault})
	if err != nil {
		t.Fatal(err)
	}
	if len(rt.converts) != 1 || rt.converts[0].name != "old" || rt.converts[0].to.IDMap == nil || rt.converts[0].to.Confinement != lxc.ConfinementDefault {
		t.Fatalf("runtime converts = %+v", rt.converts)
	}
	spec := specOf(t, s, "host-a", "old")
	if spec.IDMapBase != rt.converts[0].to.IDMap.Base || spec.Confinement != lxc.ConfinementDefault || ct.Privileged {
		t.Fatalf("recorded %+v, reported %+v", spec, ct)
	}
}

// A clone keeps its source's privilege mode exactly: an unprivileged source's
// clone moves to a fresh range of its own, a privileged one stays privileged.
func TestCloneContainer_KeepsPrivilegeMode(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "u", "stopped", corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1_000_000_000, Confinement: lxc.ConfinementDefault})
	seedSecCT(t, s, rt, "p", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "u", Target: "u2", HostName: "host-a"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "p", Target: "p2", HostName: "host-a"}); err != nil {
		t.Fatal(err)
	}
	u2, p2 := specOf(t, s, "host-a", "u2"), specOf(t, s, "host-a", "p2")
	if u2.IDMapBase == 0 || u2.IDMapBase == 1_000_000_000 || u2.Confinement != lxc.ConfinementDefault {
		t.Fatalf("unprivileged clone spec %+v", u2)
	}
	if len(rt.converts) != 1 || rt.converts[0].name != "u2" || rt.converts[0].to.IDMap.Base != u2.IDMapBase {
		t.Fatalf("converts = %+v", rt.converts)
	}
	if p2.IDMapBase != 0 {
		t.Fatalf("privileged clone was given a range: %+v", p2)
	}
}

// Two containers of this host in overlapping ranges (two hosts allocated at
// once, then one migrated here) never run together: the start is refused and
// names the fix.
func TestStartContainer_OverlappingRangeRefused(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "a", "running", corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1_000_000_000})
	seedSecCT(t, s, rt, "b", "stopped", corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1_000_000_000})
	rt.listNames = []string{"a", "b"}
	rt.security = map[string]lxc.Security{
		"a": {IDMap: &lxc.IDMap{Base: 1_000_000_000, Size: lxc.IDMapSize}},
		"b": {IDMap: &lxc.IDMap{Base: 1_000_000_000, Size: lxc.IDMapSize}},
	}
	_, err := s.StartContainer(adminCtx(), &pb.StartContainerRequest{Name: "b", HostName: "host-a"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv ct convert") {
		t.Fatalf("start in an overlapping range: %v", err)
	}
	for _, n := range rt.startCalls {
		if n == "b" {
			t.Fatal("started")
		}
	}
}

// An operator restore of an unprivileged container whose range another live
// container now holds moves it to a fresh one; a migrate keeps its range.
func TestRestoreContainer_RangeCollisionIsRemapped(t *testing.T) {
	s, rt := secServer(t)
	repo := ctTestRepo(t)
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1_000_000_000, Confinement: lxc.ConfinementDefault})
	bk := &progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T12:00:00Z"}, bk); err != nil {
		t.Fatal(err)
	}
	// web lives on (another host now); its backup is restored here as well.
	ctx := context.Background()
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "web")
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{HostName: "host-b", Name: "web", State: "running",
		Project: "acme", CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 1_000_000_000})}); err != nil {
		t.Fatal(err)
	}
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "web", HostName: "host-a", RepoPath: repo, Timestamp: "2026-06-27T12:00:00Z"}, rs); err != nil {
		t.Fatal(err)
	}
	spec := specOf(t, s, "host-a", "web")
	if spec.IDMapBase == 0 || spec.IDMapBase == 1_000_000_000 {
		t.Fatalf("restored range %d collides or was dropped", spec.IDMapBase)
	}
	if len(rt.converts) != 1 || rt.converts[0].to.IDMap.Base != spec.IDMapBase {
		t.Fatalf("converts = %+v", rt.converts)
	}
}

// A range handed out is held by this host's ledger until a row records it, so
// two creates in flight (or a row still replicating) never share one; the
// on-disk config of a container no row knows holds its range too.
func TestAllocateIDMapBase_LedgerAndDisk(t *testing.T) {
	s, rt := secServer(t)
	a, err := s.allocateIDMapBase(context.Background(), "a")
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.allocateIDMapBase(context.Background(), "b")
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatalf("two allocations without rows share %d", a)
	}
	rt.listNames = []string{"stray"}
	rt.security = map[string]lxc.Security{"stray": {IDMap: &lxc.IDMap{Base: s.idmapSlotBase((s.idmapStartSlot() + 2) % defaultIDMapRanges), Size: lxc.IDMapSize}}}
	c, err := s.allocateIDMapBase(context.Background(), "c")
	if err != nil {
		t.Fatal(err)
	}
	if c == rt.security["stray"].IDMap.Base || c == a || c == b {
		t.Fatalf("allocated %d: taken (a=%d b=%d stray=%d)", c, a, b, rt.security["stray"].IDMap.Base)
	}
}
