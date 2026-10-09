package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// stoppedLXC is the real runtime on a temp store, with the two calls that
// need lxc binaries answered as for a stopped container.
type stoppedLXC struct{ *LXCRuntimeAdapter }

func (stoppedLXC) StateContainer(context.Context, string) (string, error) { return "stopped", nil }
func (stoppedLXC) ListContainers(context.Context) ([]string, error)       { return nil, nil }

// An lv ct convert interrupted partway, then run again, finishes to the range
// the first one recorded: every file in one range, the row naming it, and the
// container ready to start.
func TestConvertContainer_InterruptedConvertResumes(t *testing.T) {
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	store := filepath.Join(t.TempDir(), "lxc")
	runner := &lxc.LxcRunner{Lxcpath: store, IDMappedRootfs: "off"}
	s.SetContainerRuntime(stoppedLXC{NewLXCRuntimeAdapter(runner)})
	lxc.UseSubIDFilesForTest(t, t.TempDir())
	owners := lxc.UseOwnershipOverlayForTest(t)

	tpl := mkCTRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if err := os.WriteFile(filepath.Join(tpl, "etc", "shadow"), []byte("root:x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Create(context.Background(), lxc.CreateOpts{Name: "old", Template: tpl}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "old", State: "stopped",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: tpl}),
	}); err != nil {
		t.Fatal(err)
	}

	owners.FailAfter(2, errors.New("interrupted"))
	if _, err := s.ConvertContainer(adminCtx(), &pb.ConvertContainerRequest{Name: "old", Unprivileged: true}); err == nil {
		t.Fatal("the interrupted convert succeeded")
	}
	owners.FailAfter(-1, nil)
	ct, err := s.ConvertContainer(adminCtx(), &pb.ConvertContainerRequest{Name: "old", Unprivileged: true})
	if err != nil {
		t.Fatalf("re-run: %v", err)
	}
	sec, _ := runner.Security("old")
	if sec.Converting || sec.IDMap == nil || ct.IdmapBase != sec.IDMap.Base {
		t.Fatalf("after the re-run: config %+v, row base %d", sec, ct.IdmapBase)
	}
	base := sec.IDMap.Base
	_ = filepath.WalkDir(filepath.Join(store, "old", "rootfs"), func(p string, d os.DirEntry, err error) error {
		uid, gid := owners.Of(p)
		if int64(uid) < base || int64(uid) >= base+lxc.IDMapSize || int64(gid) < base || int64(gid) >= base+lxc.IDMapSize {
			t.Errorf("%s owned %d:%d, outside the container's range %d", p, uid, gid, base)
		}
		return nil
	})
	if err := runner.Start(context.Background(), "old"); err != nil && containsConvert(err) {
		t.Fatalf("start refused after the resumed convert: %v", err)
	}
}

func containsConvert(err error) bool {
	return err != nil && (strings.Contains(err.Error(), "unfinished conversion") || strings.Contains(err.Error(), "lv ct convert"))
}

// realConvertServer is a server on the real runtime with a stopped privileged
// container "old" that a convert can move over.
func realConvertServer(t *testing.T) (*Server, *lxc.LxcRunner, *lxc.OwnershipOverlay, string) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	s.dataDir = t.TempDir()
	store := filepath.Join(t.TempDir(), "lxc")
	runner := &lxc.LxcRunner{Lxcpath: store, IDMappedRootfs: "off"}
	s.SetContainerRuntime(stoppedLXC{NewLXCRuntimeAdapter(runner)})
	lxc.UseSubIDFilesForTest(t, t.TempDir())
	owners := lxc.UseOwnershipOverlayForTest(t)
	tpl := mkCTRootfs(t, filepath.Join(t.TempDir(), "tpl"))
	if _, err := runner.Create(context.Background(), lxc.CreateOpts{Name: "old", Template: tpl}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "old", State: "stopped",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: tpl}),
	}); err != nil {
		t.Fatal(err)
	}
	return s, runner, owners, store
}

// rowAgreesWithDisk asserts the row's recorded mode, range and confinement
// are what the container's config will start it with.
func rowAgreesWithDisk(t *testing.T, s *Server, runner *lxc.LxcRunner, ct *pb.Container) {
	t.Helper()
	sec, err := runner.Security("old")
	if err != nil {
		t.Fatal(err)
	}
	diskBase := int64(0)
	if sec.IDMap != nil {
		diskBase = sec.IDMap.Base
	}
	if sec.Converting || ct.IdmapBase != diskBase || ct.Privileged != (sec.IDMap == nil) || ct.Confinement != sec.Confinement {
		t.Fatalf("row says privileged=%v base=%d confinement=%s; disk says %+v (base %d)",
			ct.Privileged, ct.IdmapBase, ct.Confinement, sec, diskBase)
	}
	row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "old")
	if spec := corrosion.DecodeCreateSpec(row.CreateSpec); spec.IDMapBase != diskBase || spec.Confinement != sec.Confinement {
		t.Fatalf("stored spec %+v, disk %+v", spec, sec)
	}
}

// A marker that recorded no range (an interrupted confinement-only convert, or
// a revert of a privileged container) is finished, and a re-run asking for
// --unprivileged then really moves the container: the row and the disk agree.
func TestConvertContainer_ResumeWithoutARangeStillAppliesUnprivileged(t *testing.T) {
	s, runner, _, store := realConvertServer(t)
	if err := os.WriteFile(filepath.Join(store, "old", "litevirt-converting"), []byte(`{"Confinement":"default"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ct, err := s.ConvertContainer(adminCtx(), &pb.ConvertContainerRequest{Name: "old", Unprivileged: true})
	if err != nil {
		t.Fatal(err)
	}
	if ct.Privileged {
		t.Fatalf("--unprivileged left it privileged: %+v", ct)
	}
	rowAgreesWithDisk(t, s, runner, ct)
}

// A resumed convert records the confinement it finished to, not the re-run's
// (empty) request.
func TestConvertContainer_ResumeRecordsTheFinishedConfinement(t *testing.T) {
	s, runner, owners, _ := realConvertServer(t)
	owners.FailAfter(1, errors.New("interrupted"))
	if _, err := s.ConvertContainer(adminCtx(), &pb.ConvertContainerRequest{Name: "old", Unprivileged: true, Confinement: lxc.ConfinementDefault}); err == nil {
		t.Fatal("interrupted convert succeeded")
	}
	owners.FailAfter(-1, nil)
	ct, err := s.ConvertContainer(adminCtx(), &pb.ConvertContainerRequest{Name: "old", Unprivileged: true})
	if err != nil {
		t.Fatal(err)
	}
	rowAgreesWithDisk(t, s, runner, ct)
	if ct.Confinement != lxc.ConfinementDefault {
		t.Fatalf("confinement %q, want default", ct.Confinement)
	}
}

// The resume the marker messages name — lv ct convert <name>, no flags —
// finishes the recorded target, for a non-admin too (it restores what was
// recorded, it opts into nothing). Without a marker, no flags is still
// nothing to convert.
func TestConvertContainer_NoFlagsFinishesTheMarker(t *testing.T) {
	s, runner, _, store := realConvertServer(t)
	if _, err := s.ConvertContainer(ctOperatorCtx(), &pb.ConvertContainerRequest{Name: "old"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no flags, no marker: %v", err)
	}
	if err := os.WriteFile(filepath.Join(store, "old", "litevirt-converting"), []byte(`{"Confinement":"default"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ct, err := s.ConvertContainer(ctOperatorCtx(), &pb.ConvertContainerRequest{Name: "old"})
	if err != nil {
		t.Fatalf("lv ct convert old with a marker: %v", err)
	}
	rowAgreesWithDisk(t, s, runner, ct)
	if ct.Confinement != lxc.ConfinementDefault {
		t.Fatalf("confinement %q", ct.Confinement)
	}
}
