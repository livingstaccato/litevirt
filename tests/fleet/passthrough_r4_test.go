package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// scopedOperatorToken creates user on src as Operator on /projects/<project>
// only, loads a real auth engine on every node, and returns the user's token.
func scopedOperatorToken(t *testing.T, c *Cluster, src *Node, user, project string) string {
	t.Helper()
	ctx := context.Background()
	if err := auth.SeedBuiltinRoles(ctx, src.DB); err != nil {
		t.Fatal(err)
	}
	admin := c.SelfClient(src)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: user, Password: user + "-password-0123456789", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.GrantRole(ctx, &pb.GrantRoleRequest{Path: "/projects/" + project, Role: "Operator", Principal: "user:" + user + "@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: user, Name: user})
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range c.Nodes {
		e := auth.NewEngine(n.DB)
		if err := e.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		n.Server.SetAuthEngine(e)
	}
	return tok.Token
}

// R3-I1. The two bypasses of the restored-NIC rule, on real daemons:
//
//	(a) a managed NIC naming a network that has no record ("br-mgmt"), which
//	    the flat-bridge fallback would have rendered on the host bridge of
//	    that name;
//	(b) a raw NIC naming another project's RENDERED bridge (br-victim, the
//	    interface of project victim's network vnet), which reclassification
//	    would have attached with no project check.
//
// Neither a project-scoped operator's restore nor an admin's renders either
// one: both are dropped and audited, and the restore lands with the NIC the
// project may use.
func TestFleet_RestoreNICAdmissionBypasses(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	src, opDst, adminDst := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	for _, nr := range []corrosion.NetworkRecord{
		{Name: "ctnet", Type: "bridge", Config: `{"type":"bridge","interface":"br-ctnet"}`},
		{Name: "vnet", Type: "bridge", Project: "victim", Config: `{"type":"bridge","interface":"br-victim"}`},
	} {
		if err := corrosion.UpsertNetwork(ctx, src.DB, nr); err != nil {
			t.Fatal(err)
		}
	}
	createSizedContainer(t, c, src, "ct", "acme", 0, 256)
	rec, _ := corrosion.GetContainer(ctx, src.DB, src.Name, "ct")
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	cs.Networks = []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", MAC: "02:00:00:00:00:01"},
		{Name: "eth1", NetworkName: "br-mgmt", MAC: "02:00:00:00:00:02"},
		{Name: "eth2", Bridge: "br-victim", MAC: "02:00:00:00:00:03"},
	}
	rec.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, src.DB, *rec); err != nil {
		t.Fatal(err)
	}
	repo, ts := backupContainer(t, c, src, "ct")
	tok := scopedOperatorToken(t, c, src, "carol", "acme")

	opDst.Server.SetBackupRepos(map[string]string{"main": repo})
	st, err := c.bearerClient(opDst, tok).RestoreContainer(ctx, &pb.RestoreContainerRequest{RepoPath: "main", Name: "ct", Timestamp: ts, HostName: opDst.Name})
	if err != nil {
		t.Fatalf("scoped restore: %v", err)
	}
	for {
		if _, rerr := st.Recv(); rerr != nil {
			if !strings.Contains(rerr.Error(), "EOF") {
				t.Fatalf("scoped restore stream: %v", rerr)
			}
			break
		}
	}
	if err := restoreContainerAt(t, c, adminDst, repo, "ct", ts); err != nil {
		t.Fatalf("admin restore: %v", err)
	}
	for _, n := range []*Node{opDst, adminDst} {
		got := n.CT.Config("ct")
		if !strings.Contains(got, "lxc.net.0.link = br-ctnet") {
			t.Errorf("%s: the permitted NIC is not on its network's bridge:\n%s", n.Name, got)
		}
		for _, bad := range []string{"br-mgmt", "br-victim", "lxc.net.1"} {
			if strings.Contains(got, bad) {
				t.Errorf("%s: the restore rendered %q:\n%s", n.Name, bad, got)
			}
		}
		row, _ := corrosion.GetContainer(ctx, n.DB, n.Name, "ct")
		if row == nil {
			t.Fatalf("%s: the restore did not land", n.Name)
		}
		if nets := corrosion.DecodeCreateSpec(row.CreateSpec).Networks; len(nets) != 1 || nets[0].Bridge != "br-ctnet" {
			t.Errorf("%s: the restored row records NICs %+v; want only eth0 on br-ctnet", n.Name, nets)
		}
		for _, want := range []string{"br-mgmt", "vnet"} {
			if !auditedOn(t, n, "ct.restore", "ct", want) {
				t.Errorf("%s: the dropped NIC %q was not audited", n.Name, want)
			}
		}
	}
}
