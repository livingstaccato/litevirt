package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// unackedReleaseGate has latched but cannot grant a first use: a voter that
// is down for good never acknowledges it, so every retry is refused.
type unackedReleaseGate struct{}

func (unackedReleaseGate) WithFeature(_ context.Context, f capabilities.Feature,
	_ func(context.Context, capabilities.FeatureGrant) error) error {
	// The real gate's text (health.Checker.awaitReleaseAcks).
	return status.Errorf(codes.Unavailable, "%s's use is recorded here but not yet acknowledged by host-gone; "+
		"the write is refused until every host holds the record — retry", f)
}

func (unackedReleaseGate) FeatureAvailable(capabilities.Feature) bool { return true }

// n1, end to end over gRPC. A disaster-recovery restore of a host-access
// backup while the release gate cannot grant the first use: the admin's
// restore that keeps the mount is refused (and names the way out), and the
// same restore with --without-host-access lands now, without the mount, the
// request and what it left out audited.
//
// Mutation: drop WithoutHostAccess from the request or ignore it on the
// target — the second restore is refused and this goes red.
func TestFleet_RestoreWithoutHostAccessWhileTheGateCannotGrant(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
		n.Server.SetReleaseFeatureGate(openReleaseGate{t})
	}
	allowed, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.MkdirAll(filepath.Join(allowed, "data"), 0o755)
	lxc.TrustHookBinaryForTest(t)
	dst.CT.SetHostAccessPolicy(lxc.HostAccess{MountPaths: []string{allowed}, HookBinary: "/opt/litevirt"})
	createSizedContainer(t, c, src, "ct", "", 0, 256)
	rec, _ := corrosion.GetContainer(ctx, src.DB, src.Name, "ct")
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	cs.Mounts = []corrosion.ContainerHostMount{{HostPath: filepath.Join(allowed, "data"), ContainerPath: "/data"}}
	rec.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, src.DB, *rec); err != nil {
		t.Fatal(err)
	}
	repo, ts := backupContainer(t, c, src, "ct")

	dst.Server.SetReleaseFeatureGate(unackedReleaseGate{})
	err := restoreContainerAt(t, c, dst, repo, "ct", ts)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "--without-host-access") {
		t.Fatalf("admin restore keeping the mount while the gate cannot grant = %v; want Unavailable naming --without-host-access", err)
	}
	if row, _ := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct"); row != nil {
		t.Fatalf("a refused restore left a row: %+v", row)
	}

	st, err := c.SelfClient(dst).RestoreContainer(ctx, &pb.RestoreContainerRequest{
		RepoPath: repo, Name: "ct", Timestamp: ts, HostName: dst.Name, WithoutHostAccess: true,
	})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil {
		t.Fatalf("restore --without-host-access while the gate cannot grant: %v", err)
	}
	row, _ := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct")
	if row == nil {
		t.Fatal("restore --without-host-access left no row")
	}
	if got := corrosion.DecodeCreateSpec(row.CreateSpec); len(got.Mounts) != 0 || len(got.Devices) != 0 {
		t.Errorf("the restored row carries host access: %+v", got)
	}
	rows, qerr := dst.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'ct.restore' AND target = 'ct' AND result = 'ok'`)
	if qerr != nil {
		t.Fatal(qerr)
	}
	audited := false
	for _, r := range rows {
		d := r.String("detail")
		audited = audited || (strings.Contains(d, "--without-host-access") && strings.Contains(d, "/data"))
	}
	if !audited {
		t.Errorf("the requested strip is not audited with what it left out: %d ct.restore rows", len(rows))
	}
}
