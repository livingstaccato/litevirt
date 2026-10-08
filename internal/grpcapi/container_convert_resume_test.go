package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
