// Fleet scenarios: security groups owned by a project
// (docs/design/security-group-projects.md), over real daemons, real RBAC and
// real replication.
package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const sgProjNet = "sgnet"

// projectNetworkAdminToken creates user with Operator and NetworkAdmin on
// /projects/<project> only, reloads a real auth engine on every node, and
// returns the user's token.
func projectNetworkAdminToken(t *testing.T, c *Cluster, src *Node, user, project string) string {
	t.Helper()
	ctx := context.Background()
	if err := auth.SeedBuiltinRoles(ctx, src.DB); err != nil {
		t.Fatal(err)
	}
	admin := c.SelfClient(src)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: user, Password: user + "-password-0123456789", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"Operator", "NetworkAdmin"} {
		if _, err := admin.GrantRole(ctx, &pb.GrantRoleRequest{Path: "/projects/" + project, Role: role, Principal: "user:" + user + "@local", Propagate: true}); err != nil {
			t.Fatal(err)
		}
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: user, Name: user})
	if err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		e := auth.NewEngine(n.DB)
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		n.Server.SetAuthEngine(e)
	}
	return tok.Token
}

func wantSGFleetCode(t *testing.T, what string, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("%s: %v, want %v", what, err, want)
	}
}

func sgNamesOf(resp *pb.ListSecurityGroupsResponse) string {
	var out []string
	for _, g := range resp.GetGroups() {
		out = append(out, g.GetName())
	}
	return strings.Join(out, ",")
}

// TestFleet_SGProjects_AProjectCannotSeeUseOrAttachAnotherProjectsGroup: a
// NetworkAdmin of project acme, talking to a node other than the one the
// groups were made on, sees acme's groups and the global ones and never
// other's; cannot create in other; cannot create a VM, attach a NIC or bind
// a NIC with other's group; and can do each with acme's and the global ones.
// Root sees every group.
func TestFleet_SGProjects_AProjectCannotSeeUseOrAttachAnotherProjectsGroup(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		n.Server.SetBridgeEnsure(func(string) error { return nil })
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	gates := gateAll(t, c)
	latchOperationProtocol(t, c, gates)
	src, entry := c.Nodes[0], c.Nodes[1]
	admin := c.SelfClient(src)
	if _, err := admin.CreateNetwork(ctx, &pb.CreateNetworkRequest{
		Name: sgProjNet, Type: "isolated", Subnet: "172.16.82.0/24", Dhcp: true,
	}); err != nil {
		t.Fatalf("CreateNetwork: %v", err)
	}
	for _, p := range []string{"acme", "other"} {
		if _, err := admin.CreateProject(ctx, &pb.CreateProjectRequest{Name: p}); err != nil {
			t.Fatalf("CreateProject %s: %v", p, err)
		}
	}
	for _, g := range []struct{ name, project string }{{"base", ""}, {"a-web", "acme"}, {"b-web", "other"}} {
		if _, err := admin.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: g.name, Project: g.project}); err != nil {
			t.Fatalf("root creates %s: %v", g.name, err)
		}
	}
	tok := projectNetworkAdminToken(t, c, src, "alice", "acme")
	alice := c.bearerClient(entry, tok)
	eventually(t, convergeTimeout, "the groups to reach "+entry.Name, func() bool {
		sgs, _ := corrosion.ListSecurityGroups(ctx, entry.DB, "")
		return len(sgs) == 3
	})

	// See.
	resp, err := alice.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{Project: "acme", IncludeRules: true})
	if err != nil || sgNamesOf(resp) != "a-web,base" {
		t.Fatalf("alice's acme listing = %q (%v), want a-web,base", sgNamesOf(resp), err)
	}
	if resp, err = alice.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{}); err != nil || sgNamesOf(resp) != "a-web" {
		t.Fatalf("alice's listing = %q (%v), want a-web", sgNamesOf(resp), err)
	}
	_, err = alice.ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{Project: "other"})
	wantSGFleetCode(t, "alice lists other", err, codes.PermissionDenied)
	if resp, err = c.SelfClient(entry).ListSecurityGroups(ctx, &pb.ListSecurityGroupsRequest{}); err != nil || sgNamesOf(resp) != "a-web,b-web,base" {
		t.Fatalf("root's listing = %q (%v), want every group", sgNamesOf(resp), err)
	}

	// Manage.
	_, err = alice.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "b-db", Project: "other"})
	wantSGFleetCode(t, "alice creates in other", err, codes.PermissionDenied)
	if _, err := alice.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "a-db", Project: "acme"}); err != nil {
		t.Fatalf("alice creates in acme: %v", err)
	}

	// Use: a create naming other's group is refused and leaves no VM.
	vmReq := func(sgs ...string) *pb.CreateVMRequest {
		return &pb.CreateVMRequest{Spec: &pb.VMSpec{
			Name: "web", Project: "acme", Cpu: 1, MemoryMib: 512,
			Placement: &pb.PlacementSpec{Host: entry.Name},
			Network:   []*pb.NetworkAttachment{{Name: sgProjNet, SecurityGroups: sgs}},
		}}
	}
	_, err = alice.CreateVM(ctx, vmReq("a-web", "b-web"))
	wantSGFleetCode(t, "alice creates a VM bound to other's group", err, codes.PermissionDenied)
	if vm, _ := corrosion.GetVM(ctx, entry.DB, "web"); vm != nil {
		t.Fatalf("a refused create left VM %+v", vm)
	}
	if _, err := alice.CreateVM(ctx, vmReq("a-web", "base")); err != nil {
		t.Fatalf("alice creates a VM bound to acme's and a global group: %v", err)
	}

	// Attach: a NIC naming other's group is refused, whoever asks.
	for who, cli := range map[string]pb.LiteVirtClient{"alice": alice, "root": c.SelfClient(entry)} {
		_, err = cli.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "web",
			Nic: &pb.NetworkAttachment{Name: sgProjNet, SecurityGroups: []string{"b-web"}}})
		wantSGFleetCode(t, who+" attaches a NIC bound to other's group", err, codes.PermissionDenied)
		_, err = cli.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{VmName: "web", NetworkName: sgProjNet, SecurityGroups: []string{"b-web"}})
		wantSGFleetCode(t, who+" binds other's group", err, codes.PermissionDenied)
	}
	nics, err := corrosion.MergedVMNICs(ctx, entry.DB, "web")
	if err != nil || len(nics) != 1 {
		t.Fatalf("web's NICs = %+v (%v), want the one it was created with", nics, err)
	}
	if got := corrosion.DecodeSecurityGroups(nics[0].SecurityGroups); strings.Join(got, ",") != "a-web,base" {
		t.Fatalf("web's NIC binds %v after the refusals, want [a-web base]", got)
	}
	if _, err := alice.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{VmName: "web", NetworkName: sgProjNet, SecurityGroups: []string{"a-db"}}); err != nil {
		t.Fatalf("alice binds acme's group: %v", err)
	}

	// A container NIC is held to the same rule.
	_, err = alice.CreateContainer(ctx, &pb.CreateContainerRequest{
		HostName: entry.Name, Name: "ct-web", Project: "acme", Template: "download",
		Distro: "debian", Release: "bookworm", Arch: "amd64", Cpu: 1, MemoryMib: 256,
		Networks: []*pb.ContainerNetwork{{Name: "eth0", NetworkName: sgProjNet, SecurityGroups: []string{"b-web"}}},
	})
	wantSGFleetCode(t, "alice creates a container bound to other's group", err, codes.PermissionDenied)
	if !strings.Contains(err.Error(), "b-web") {
		t.Fatalf("the container refusal is not the group's: %v", err)
	}
}

// TestFleet_SGProjects_GatedOnTheReleaseToken drives the real
// CreateSecurityGroup RPC against real checkers: while a host is on the
// previous build the release token cannot latch, so a project group is refused
// with the release text and nothing carrying the project column reaches any
// replication stream, while a global group is created as before and reaches
// every host. Once every host is on this build the use is recorded and
// acknowledged by every replica, and the project group reaches every host.
func TestFleet_SGProjects_GatedOnTheReleaseToken(t *testing.T) {
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 8008)
	a, old := c.Nodes[0], c.Nodes[2]
	admin := c.SelfClient(a)
	if _, err := admin.CreateProject(ctx, &pb.CreateProjectRequest{Name: "acme"}); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)

	old.Server.SetWALQuarantined(func() bool { return true })
	_, err := admin.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "a-web", Project: "acme"})
	want := "the cluster upgrade must finish first (sg_projects needs " + capabilities.ReleaseToken + ")"
	if status.Code(err) != codes.FailedPrecondition || err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("a project group with %s on the old build: %v, want %q", old.Name, err, want)
	}
	if _, err := admin.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "base"}); err != nil {
		t.Fatalf("a global group mid-roll: %v", err)
	}
	eventually(t, convergeTimeout, "the global group on every host", func() bool {
		for _, n := range c.Nodes {
			if sgs, _ := corrosion.ListSecurityGroups(ctx, n.DB, ""); len(sgs) != 1 {
				return false
			}
		}
		return true
	})
	for _, n := range c.Nodes {
		assertNoProjectSGStatement(t, n)
		if featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureSGProjects)) {
			t.Fatalf("%s holds an sg_projects use that nothing wrote", n.Name)
		}
	}

	old.Server.SetWALQuarantined(old.DB.WALQuarantined) // the host is upgraded
	eventually(t, 15*time.Second, "the project group to be created on a uniform fleet", func() bool {
		_, err = admin.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "a-web", Project: "acme"})
		return err == nil
	})
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, string(capabilities.FeatureSGProjects)) {
			t.Fatalf("%s does not hold the sg_projects record although the group was written", n.Name)
		}
	}
	eventually(t, convergeTimeout, "the project group on every host", func() bool {
		for _, n := range c.Nodes {
			sgs, _ := corrosion.ListSecurityGroups(ctx, n.DB, "")
			found := false
			for _, g := range sgs {
				found = found || (g.Name == "a-web" && g.Project == "acme")
			}
			if !found {
				return false
			}
		}
		return true
	})
}

// assertNoProjectSGStatement fails when n's replication stream carries a
// security_groups statement naming the project column.
func assertNoProjectSGStatement(t *testing.T, n *Node) {
	t.Helper()
	rows, err := n.DB.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read %s mutation_log: %v", n.Name, err)
	}
	for _, r := range rows {
		s := r.String("stmts")
		if strings.Contains(s, "security_groups") && strings.Contains(s, "project") {
			t.Fatalf("%s put a project-carrying security_groups statement on its replication stream before "+
				"the latch; a previous-release peer cannot decode it:\n%s", n.Name, s)
		}
	}
}

// TestFleet_SGProjects_AContainerRestoreRefusesAnotherProjectsGroup: a
// container backup whose NIC names another project's group is not restored
// into acme with that binding — the restore is refused where it is written,
// as a clone is, rather than landing a binding only the firewall skips.
func TestFleet_SGProjects_AContainerRestoreRefusesAnotherProjectsGroup(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		openNICGuards(t, n)
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	admin := c.SelfClient(src)
	for _, p := range []string{"acme", "other"} {
		if _, err := admin.CreateProject(ctx, &pb.CreateProjectRequest{Name: p}); err != nil {
			t.Fatalf("CreateProject %s: %v", p, err)
		}
	}
	if _, err := admin.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "b-web", Project: "other"}); err != nil {
		t.Fatalf("create other's group: %v", err)
	}
	createSizedContainer(t, c, src, "ct", "acme", 0, 256)
	// The archived NIC names other's group, as a backup taken before the
	// group was created under that name would.
	rec, _ := corrosion.GetContainer(ctx, src.DB, src.Name, "ct")
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	cs.Networks = []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br-raw", MAC: "02:00:00:00:00:31", SecurityGroups: []string{"b-web"}}}
	rec.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, src.DB, *rec); err != nil {
		t.Fatal(err)
	}
	repo, ts := backupContainer(t, c, src, "ct")

	err := restoreContainerAt(t, c, dst, repo, "ct", ts)
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "b-web") {
		t.Fatalf("restoring a container bound to other's group into acme: %v, want PermissionDenied naming b-web", err)
	}
	if row, _ := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct"); row != nil {
		t.Fatalf("a refused restore landed a row on %s: %+v", dst.Name, row)
	}
}
