// Fleet scenarios: security groups owned by a project
// (docs/design/security-group-projects.md), over real daemons, real RBAC and
// real replication.
package fleet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

const sgProjNet = "sgnet"

// wireSGProjectsGates wires each node's corrosion gate to its own durable
// sg_projects_v1 latch, as the daemon does (wireSGProjectsGate).
func wireSGProjectsGates(c *Cluster, gates map[string]*health.Checker) {
	for _, n := range c.Nodes {
		g := gates[n.Name]
		n.DB.SetSGProjectsGate(func() bool { return g.DurablyLatched(capabilities.SGProjectsV1) })
	}
}

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
	wireSGProjectsGates(c, gates)
	latchOperationProtocol(t, c, gates)
	for _, n := range c.Nodes {
		if !gates[n.Name].Enforced(ctx, capabilities.SGProjectsV1) {
			t.Fatalf("%s: sg_projects_v1 did not latch on a uniform fleet", n.Name)
		}
	}
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

// TestFleet_SGProjects_AMaintenanceHostOnThePreviousBuildHoldsProjectGroupsOff:
// while one host this node replicates to — parked in maintenance, so it does
// not vote but still receives every statement — runs a build without
// sg_projects_v1, a project group is refused and nothing carrying the project
// column reaches any replication stream; a global group is created as before
// and reaches every host. Once that host is upgraded the token latches and the
// project group is created and reaches every host, the former holdout included.
func TestFleet_SGProjects_AMaintenanceHostOnThePreviousBuildHoldsProjectGroupsOff(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 8008})
	a, old := c.Nodes[0], c.Nodes[2]
	if err := corrosion.UpdateHostState(ctx, a.DB, old.Name, "maintenance"); err != nil {
		t.Fatal(err)
	}
	c.WaitConverged(t, convergeTimeout)

	var held atomic.Bool
	held.Store(true)
	gates := gateAll(t, c)
	for _, n := range c.Nodes {
		node := n
		gates[node.Name].SetPeerPinger(func(ctx context.Context, host string) ([]string, time.Time, error) {
			caps, wall, err := node.Server.PeerCapabilities(ctx, host)
			if held.Load() && host == old.Name {
				caps = withoutToken(caps, capabilities.SGProjectsV1)
			}
			return caps, wall, err
		})
	}
	wireSGProjectsGates(c, gates)
	ga := gates[a.Name]
	if !ga.Enforced(ctx, capabilities.FailoverScopeV1) {
		t.Fatal("failover_scope_v1 did not latch with every host advertising it; the rest is vacuous")
	}
	if ga.Enforced(ctx, capabilities.SGProjectsV1) {
		t.Fatalf("sg_projects_v1 latched on %s while %s — in maintenance, still receiving replication — "+
			"runs a build without it", a.Name, old.Name)
	}

	admin := c.SelfClient(a)
	_, err := admin.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "a-web", Project: "acme"})
	wantSGFleetCode(t, "a project group mid-roll", err, codes.FailedPrecondition)
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
	}

	held.Store(false) // the maintenance host is upgraded
	eventually(t, 20*time.Second, "sg_projects_v1 latches once every recipient has rolled", func() bool {
		return ga.Enforced(ctx, capabilities.SGProjectsV1)
	})
	if _, err := admin.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "a-web", Project: "acme"}); err != nil {
		t.Fatalf("a project group after the latch: %v", err)
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
