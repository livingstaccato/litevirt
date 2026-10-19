package main

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

func (d *oldSGDaemon) ListSecurityGroups(_ context.Context, req *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	if req.GetProject() != sgProjectsProbe { // the CLI's probe lists nothing it prints
		d.listed++
	}
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

// scopedSGDaemon answers GetUpgradeStatus as a daemon does a token scoped to a
// project (it needs the root), and creates what it is asked. newBuild says
// whether it is an upgraded daemon (keeps the project) or a previous one
// (checks sg.write at the root, which the scoped token cannot pass).
type scopedSGDaemon struct {
	pb.UnimplementedLiteVirtServer
	newBuild bool
	created  int
}

func (d *scopedSGDaemon) GetUpgradeStatus(context.Context, *emptypb.Empty) (*pb.UpgradeStatus, error) {
	return nil, status.Error(codes.PermissionDenied, `token scope does not cover "/"`)
}

// ListSecurityGroups answers the CLI's probe (an invalid project) as each
// build does: an upgraded daemon validates the project before anything else,
// a previous one checks sg.read at the root first.
func (d *scopedSGDaemon) ListSecurityGroups(_ context.Context, req *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	if !d.newBuild {
		return nil, status.Error(codes.PermissionDenied, `token scope does not cover "/"`)
	}
	return nil, status.Errorf(codes.InvalidArgument, "invalid project %q: traversal", req.GetProject())
}

func (d *scopedSGDaemon) CreateSecurityGroup(_ context.Context, req *pb.CreateSecurityGroupRequest) (*pb.SecurityGroup, error) {
	if !d.newBuild {
		return nil, status.Error(codes.PermissionDenied, `token scope does not cover "/"`)
	}
	d.created++
	return &pb.SecurityGroup{Id: "sg-1", Name: req.GetName(), Project: req.GetProject()}, nil
}

// A token scoped to a project cannot read the upgrade status, so the create
// is sent and the daemon's own answer decides: an upgraded daemon creates the
// project's group; a previous one refuses the token at the root and nothing
// is created (the post-create project check covers any other answer).
func TestSGCLI_ProjectCreateWithAProjectScopedToken(t *testing.T) {
	d := &scopedSGDaemon{newBuild: true}
	sgCLIDaemon(t, d, nil, "")
	noLocalDB(t)
	if out, err := runSGCLI(t, "create", "a-web", "--project", "acme"); err != nil || !strings.Contains(out, "Created") {
		t.Fatalf("a scoped token's create against an upgraded daemon: %v\n%s", err, out)
	}
	if d.created != 1 {
		t.Fatalf("created %d groups, want 1", d.created)
	}

	old := &scopedSGDaemon{}
	sgCLIDaemon(t, old, nil, "")
	if _, err := runSGCLI(t, "create", "a-web", "--project", "acme"); err == nil ||
		!strings.Contains(err.Error(), "predates project security groups") {
		t.Fatalf("a scoped token's create against a previous daemon: %v, want the predates refusal", err)
	}
	if old.created != 0 {
		t.Fatalf("the previous daemon was asked to create %d groups", old.created)
	}
}

// declaringSGDaemon is a daemon with the release catalog that DECLARES
// sg_projects but does not implement it: it drops the project field, so it
// would create a GLOBAL group and list every group unfiltered.
type declaringSGDaemon struct {
	pb.UnimplementedLiteVirtServer
	created int
}

func (d *declaringSGDaemon) GetUpgradeStatus(context.Context, *emptypb.Empty) (*pb.UpgradeStatus, error) {
	return &pb.UpgradeStatus{Features: []*pb.ReleaseFeatureStatus{{Name: "sg_projects", Declared: true}}}, nil
}

func (d *declaringSGDaemon) ListSecurityGroups(context.Context, *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	return &pb.ListSecurityGroupsResponse{Groups: []*pb.SecurityGroup{{Id: "sg-9", Name: "b-web"}}}, nil
}

func (d *declaringSGDaemon) CreateSecurityGroup(_ context.Context, req *pb.CreateSecurityGroupRequest) (*pb.SecurityGroup, error) {
	d.created++
	return &pb.SecurityGroup{Id: "sg-1", Name: req.GetName()}, nil
}

// Declaring the feature is not implementing it: --project is refused before
// anything is created or listed against a daemon that drops the field.
func TestSGCLI_ProjectAgainstADaemonThatDeclaresButDoesNotImplement(t *testing.T) {
	d := &declaringSGDaemon{}
	sgCLIDaemon(t, d, nil, "")
	noLocalDB(t)
	for _, args := range [][]string{{"create", "a-web", "--project", "acme"}, {"ls", "--project", "acme"}} {
		out, err := runSGCLI(t, args...)
		if err == nil || !strings.Contains(err.Error(), "predates project security groups") {
			t.Errorf("lv sg %v: err = %v, want the predates refusal", args, err)
		}
		if strings.Contains(out, "b-web") || strings.Contains(out, "Created") {
			t.Errorf("lv sg %v printed:\n%s", args, out)
		}
	}
	if d.created != 0 {
		t.Fatalf("the daemon was asked to create %d groups", d.created)
	}
}

// Against a real daemon of this build the probe passes for a token scoped to
// a project, so `lv sg ls --project` lists that project's view.
func TestSGCLI_ProjectProbePassesAgainstThisBuildForAScopedToken(t *testing.T) {
	db := sgCLIScopedDaemon(t)
	seedSGListing(t, db)
	noLocalDB(t)
	if _, err := runSGCLI(t, "ls", "--project", "teamA"); err != nil {
		t.Fatalf("lv sg ls --project teamA with a token scoped to teamA: %v", err)
	}
}

// failingProbeDaemon answers the probe with an error a current daemon can
// give for reasons of its own.
type failingProbeDaemon struct {
	pb.UnimplementedLiteVirtServer
	created int
}

func (d *failingProbeDaemon) ListSecurityGroups(context.Context, *pb.ListSecurityGroupsRequest) (*pb.ListSecurityGroupsResponse, error) {
	return nil, status.Error(codes.Internal, "database is locked")
}

func (d *failingProbeDaemon) CreateSecurityGroup(context.Context, *pb.CreateSecurityGroupRequest) (*pb.SecurityGroup, error) {
	d.created++
	return &pb.SecurityGroup{Id: "sg-1"}, nil
}

// An error the probe does not expect is reported as what it is, not as an old
// daemon, and --project still stops before anything is created.
func TestSGCLI_AnUnexpectedProbeErrorIsReportedAsItIs(t *testing.T) {
	d := &failingProbeDaemon{}
	sgCLIDaemon(t, d, nil, "")
	noLocalDB(t)
	_, err := runSGCLI(t, "create", "a-web", "--project", "acme")
	if err == nil || strings.Contains(err.Error(), "predates") || !strings.Contains(err.Error(), "database is locked") {
		t.Fatalf("lv sg create --project with a failing probe: %v, want the daemon's own error and no 'predates'", err)
	}
	if d.created != 0 {
		t.Fatalf("created %d groups after a failed probe", d.created)
	}
}
