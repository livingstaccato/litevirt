package grpcapi

import (
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review I2: an OCI library item pulled before owners were recorded is
// everyone's, and containers may already run from it. A non-admin's
// `lv ct pull --project P` over it would claim it for P, and every other
// project's container made from it would then be refused at its next
// recreate — after the recreate deleted it. So that first claim is the
// Admin's; a pull without --project, and an Admin's claim, work as before,
// and a main-era member built from the item is still redeployed.
func TestOCILibrary_ClaimingAnOwnerlessItemIsTheAdmins(t *testing.T) {
	s, rt := ctPathServer(t)
	root := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "web-img", "rootfs"))
	owner := filepath.Join(s.dataDir, ociOwnersDir, "web-img")

	_, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/web:2", Dest: "web-img", Project: "x"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-admin claim of an ownerless item: %v, want PermissionDenied", err)
	}
	if _, err := os.Stat(owner); !os.IsNotExist(err) {
		t.Fatalf("the item was claimed (%v)", err)
	}
	if len(rt.pullCalls) != 0 {
		t.Fatalf("the refused pull ran: %+v", rt.pullCalls)
	}
	// A brand-new item may still be claimed by its puller.
	if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/api:1", Dest: "fresh", Project: "x"}); err != nil {
		t.Fatalf("non-admin pull of a new item for its project: %v", err)
	}
	// Without --project the pull is everyone's, as before.
	if _, err := s.PullOCIImage(ctOperatorCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/web:2", Dest: "web-img"}); err != nil {
		t.Fatalf("non-admin pull without --project: %v", err)
	}
	if _, err := os.Stat(owner); !os.IsNotExist(err) {
		t.Fatalf("a pull without --project recorded an owner (%v)", err)
	}

	// A main-era member built from the item is redeployed unchanged.
	carl := carlCtx(t, s)
	image := "rootfs:" + root
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	seedStackCT(t, s, "st", "host-a", "web", image, corrosion.ContainerCreateSpec{Template: image, Arch: "amd64"})
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: image, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); err != nil {
		t.Fatalf("unchanged redeploy of a member built from the item: %v", err)
	}

	// The Admin may claim it.
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "ghcr.io/x/web:2", Dest: "web-img", Project: "x"}); err != nil {
		t.Fatalf("admin claim: %v", err)
	}
	if b, err := os.ReadFile(owner); err != nil || string(b) != "x\n" {
		t.Fatalf("admin claim recorded %q (%v)", b, err)
	}
}
