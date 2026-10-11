package fleet

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// R2-I1. A restore attaches a NIC only where the caller may: a managed NIC
// on its network's own bridge whatever the archive's spec names, and a raw
// NIC only for raw-bridge authority. The archive spec here forges both — a
// managed NIC claiming another tenant's bridge and a raw NIC on the host's
// management bridge. A project-scoped operator's restore lands with the
// managed NIC on the network's bridge and the raw NIC dropped (and audited);
// an admin's keeps the raw NIC.
func TestFleet_RestoreForgedSpecBridges(t *testing.T) {
	// The archive, not replication, is the subject: one database.
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	src, opDst, adminDst := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	if err := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: "ctnet", Type: "bridge",
		Config: `{"type":"bridge","interface":"br-ctnet"}`}); err != nil {
		t.Fatal(err)
	}
	createSizedContainer(t, c, src, "ct", "acme", 0, 256)
	rec, _ := corrosion.GetContainer(ctx, src.DB, src.Name, "ct")
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	cs.Networks = []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-victim", MAC: "02:00:00:00:00:01"},
		{Name: "eth1", Bridge: "br-mgmt", MAC: "02:00:00:00:00:02"},
	}
	rec.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, src.DB, *rec); err != nil {
		t.Fatal(err)
	}
	repo, ts := backupContainer(t, c, src, "ct")

	// carol: Operator on /projects/acme only, through a real auth engine.
	if err := auth.SeedBuiltinRoles(ctx, src.DB); err != nil {
		t.Fatal(err)
	}
	admin := c.SelfClient(src)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "carol", Password: "carols-password-0123456789", Role: "operator"}); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.GrantRole(ctx, &pb.GrantRoleRequest{Path: "/projects/acme", Role: "Operator", Principal: "user:carol@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "carol", Name: "carol"})
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
	opDst.Server.SetBackupRepos(map[string]string{"main": repo})
	st, err := c.bearerClient(opDst, tok.Token).RestoreContainer(ctx, &pb.RestoreContainerRequest{RepoPath: "main", Name: "ct", Timestamp: ts, HostName: opDst.Name})
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
	got := opDst.CT.Config("ct")
	if !strings.Contains(got, "lxc.net.0.link = br-ctnet") {
		t.Errorf("the managed NIC is not on its network's bridge:\n%s", got)
	}
	for _, bad := range []string{"br-victim", "br-mgmt", "lxc.net.1"} {
		if strings.Contains(got, bad) {
			t.Errorf("a scoped operator's restore rendered %q:\n%s", bad, got)
		}
	}
	if row, _ := corrosion.GetContainer(ctx, opDst.DB, opDst.Name, "ct"); row == nil {
		t.Fatal("the restore did not land")
	} else if nets := corrosion.DecodeCreateSpec(row.CreateSpec).Networks; len(nets) != 1 || nets[0].Bridge != "br-ctnet" {
		t.Errorf("the restored row records NICs %+v; want only eth0 on br-ctnet", nets)
	}
	if !auditedOn(t, opDst, "ct.restore", "ct", "br-mgmt") {
		t.Error("the dropped raw NIC was not audited")
	}

	// An admin's restore keeps the raw NIC; the managed one is still re-homed.
	if err := restoreContainerAt(t, c, adminDst, repo, "ct", ts); err != nil {
		t.Fatalf("admin restore: %v", err)
	}
	got = adminDst.CT.Config("ct")
	if !strings.Contains(got, "lxc.net.0.link = br-ctnet") || !strings.Contains(got, "lxc.net.1.link = br-mgmt") || strings.Contains(got, "br-victim") {
		t.Errorf("an admin's restore rendered:\n%s", got)
	}
}
