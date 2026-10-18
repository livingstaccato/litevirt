package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// oldSGDaemon is a daemon that predates project security groups: it drops
// the project field it does not know, creating a GLOBAL group and listing
// every group, and its release-feature list has no sg_projects.
type oldSGDaemon struct {
	pb.UnimplementedLiteVirtServer
	created []*pb.CreateSecurityGroupRequest
	listed  int
}

func (d *oldSGDaemon) GetUpgradeStatus(context.Context, *emptypb.Empty) (*pb.UpgradeStatus, error) {
	return &pb.UpgradeStatus{Features: []*pb.ReleaseFeatureStatus{{Name: "firewall_log", Declared: true}}}, nil
}

func (d *oldSGDaemon) CreateSecurityGroup(_ context.Context, req *pb.CreateSecurityGroupRequest) (*pb.SecurityGroup, error) {
	d.created = append(d.created, req)
	return &pb.SecurityGroup{Id: "sg-1", Name: req.GetName()}, nil
}

func (d *oldSGDaemon) ListSecurityGroups(context.Context, *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	d.listed++
	return &pb.ListSecurityGroupsResponse{Groups: []*pb.SecurityGroup{{Id: "sg-9", Name: "b-web"}}}, nil
}

// `--project` against a daemon that predates it is refused before anything
// is created or listed: that daemon would make a global group, and list every
// group unfiltered.
func TestSGCLI_ProjectAgainstAnOldDaemonIsRefused(t *testing.T) {
	d := &oldSGDaemon{}
	sgCLIDaemon(t, d, nil, "")
	noLocalDB(t)

	for _, args := range [][]string{{"create", "a-web", "--project", "acme"}, {"ls", "--project", "acme"}} {
		out, err := runSGCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), "predates project security groups") {
			t.Errorf("lv sg %v against an old daemon: err = %v, want the predates refusal", args, err)
		}
		if strings.Contains(out, "b-web") || strings.Contains(out, "Created") {
			t.Errorf("lv sg %v against an old daemon printed:\n%s", args, out)
		}
	}
	if len(d.created) != 0 || d.listed != 0 {
		t.Fatalf("the old daemon was asked to create %d and list %d times", len(d.created), d.listed)
	}
	// Without --project nothing changes.
	if _, err := runSGCLI(t, "create", "base"); err != nil {
		t.Fatalf("lv sg create without --project: %v", err)
	}
}
