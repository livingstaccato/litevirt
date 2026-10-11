package fleet

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// setContainerNICs rewrites the NICs n's row of name records.
func setContainerNICs(t *testing.T, n *Node, name string, nics []corrosion.ContainerNetwork) {
	t.Helper()
	ctx := context.Background()
	rec, err := corrosion.GetContainer(ctx, n.DB, n.Name, name)
	if err != nil || rec == nil {
		t.Fatalf("row %s on %s: %v", name, n.Name, err)
	}
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	cs.Networks = nics
	rec.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, n.DB, *rec); err != nil {
		t.Fatal(err)
	}
}

// rowNICs is what name's row on host records, as name@bridge.
func rowNICs(t *testing.T, n *Node, host, name string) []string {
	t.Helper()
	rec, err := corrosion.GetContainer(context.Background(), n.DB, host, name)
	if err != nil || rec == nil {
		t.Fatalf("row %s on %s (read on %s): %v", name, host, n.Name, err)
	}
	var out []string
	for _, nic := range corrosion.DecodeCreateSpec(rec.CreateSpec).Networks {
		out = append(out, nic.Name+"@"+nic.Bridge)
	}
	return out
}

// requireLinks fails unless cfg configures exactly the bridges want, as
// lxc.net.N.link lines, and none of bad.
func requireLinks(t *testing.T, who, cfg string, want []string, bad ...string) {
	t.Helper()
	for i, b := range want {
		if line := "lxc.net." + string(rune('0'+i)) + ".link = " + b; !strings.Contains(cfg, line) {
			t.Errorf("%s: the config lacks %q:\n%s", who, line, cfg)
		}
	}
	if line := "lxc.net." + string(rune('0'+len(want))) + "."; strings.Contains(cfg, line) {
		t.Errorf("%s: the config configures more than %d NICs:\n%s", who, len(want), cfg)
	}
	for _, b := range bad {
		if strings.Contains(cfg, b) {
			t.Errorf("%s: the config carries %q:\n%s", who, b, cfg)
		}
	}
}

// R4-I1. A cold migrate re-homes the container with every NIC its row
// records — a managed NIC whose network was force-deleted since (on the
// bridge the row records, as on main), a managed NIC, and a raw NIC.
func TestFleet_PeerMoveKeepsAForceDeletedNetworksNIC(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, nr := range []corrosion.NetworkRecord{
		{Name: "ctnet", Type: "bridge", Config: `{"type":"bridge","interface":"br-ctnet"}`},
		{Name: "doomed", Type: "bridge", Config: `{"type":"bridge","interface":"br-doomed"}`},
	} {
		if err := corrosion.UpsertNetwork(ctx, src.DB, nr); err != nil {
			t.Fatal(err)
		}
	}
	createContainer(t, c, src, "ct")
	setContainerNICs(t, src, "ct", []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-ctnet", MAC: "02:00:00:00:00:01"},
		{Name: "eth1", NetworkName: "doomed", Bridge: "br-doomed", MAC: "02:00:00:00:00:02"},
		{Name: "eth2", Bridge: "br-raw", MAC: "02:00:00:00:00:03"},
	})
	// lv network rm --force: the record is gone, the container's NIC is not.
	if err := corrosion.DeleteNetwork(ctx, src.DB, "doomed"); err != nil {
		t.Fatal(err)
	}
	if err := runMigrate(t, c, src, dst, "ct", stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	requireLinks(t, dst.Name, dst.CT.Config("ct"), []string{"br-ctnet", "br-doomed", "br-raw"})
	if got := strings.Join(rowNICs(t, dst, dst.Name, "ct"), " "); got != "eth0@br-ctnet eth1@br-doomed eth2@br-raw" {
		t.Errorf("the migrated row records NICs %q; want all three the source row recorded", got)
	}
}

// R4-I1. A cold migrate onto a host whose replica has not seen the
// container's row yet. Without the row the target cannot know which NICs
// (or mounts, or privilege) the container holds, so it refuses before it
// writes anything, and the source rolls back; it never strips them. The
// source sends the row with the move, so the move lands with every NIC.
func TestFleet_PeerMoveWithALaggingSourceRowIsRetriedNotStripped(t *testing.T) {
	// Nothing replicates here unless the scenario moves it: dst never sees
	// src's container row, nor the ctnet record.
	c := New(t, Options{Nodes: 2})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	if err := corrosion.UpsertNetwork(ctx, src.DB, corrosion.NetworkRecord{Name: "ctnet", Type: "bridge", Config: `{"type":"bridge","interface":"br-ctnet"}`}); err != nil {
		t.Fatal(err)
	}
	createContainer(t, c, src, "ct")
	setContainerNICs(t, src, "ct", []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-ctnet", MAC: "02:00:00:00:00:01"},
		{Name: "eth1", Bridge: "br-raw", MAC: "02:00:00:00:00:02"},
	})
	if rec, _ := corrosion.GetContainer(ctx, dst.DB, src.Name, "ct"); rec != nil {
		t.Fatal("the target already holds the source row; the scenario needs it absent")
	}

	// An earlier source build sends no row: refused before any write, with a
	// code the source reads as "nothing landed" (it rolls back), not
	// "indeterminate" (it would park the container).
	repo, ts := backupContainer(t, c, src, "ct")
	dst.Server.SetSourceRowWait(time.Second) // it waits for the row first (P1); it never comes
	md := metadata.AppendToOutgoingContext(ctx, "x-litevirt-migrate-from-host", src.Name)
	st, err := c.PeerClient(src, dst).RestoreContainer(md, &pb.RestoreContainerRequest{RepoPath: repo, Name: "ct", Timestamp: ts, HostName: dst.Name})
	if err == nil {
		for {
			if _, err = st.Recv(); err != nil {
				break
			}
		}
	}
	if err == io.EOF || status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a migrate restore with no source row = %v; want FailedPrecondition (retried after a rollback)", err)
	}
	if dst.CT.Exists("ct") {
		t.Fatal("the refused restore left a container on the target")
	}
	if rec, _ := corrosion.GetContainer(ctx, dst.DB, dst.Name, "ct"); rec != nil {
		t.Fatalf("the refused restore wrote a row: %+v", rec)
	}

	// This build's source carries its row: the move lands with both NICs.
	if err := runMigrate(t, c, src, dst, "ct", stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	requireLinks(t, dst.Name, dst.CT.Config("ct"), []string{"br-ctnet", "br-raw"})
	if got := strings.Join(rowNICs(t, dst, dst.Name, "ct"), " "); got != "eth0@br-ctnet eth1@br-raw" {
		t.Errorf("the migrated row records NICs %q; want both", got)
	}
}

// R4-I2. A failover relocation rebuilds the container from its backup, and
// an archive is only as honest as whoever can write the repo: one that adds
// a NIC on project victim's network (eth9) attaches nothing to it. The
// relocated container has exactly the NICs its row records — a managed and a
// raw one — and the dropped NIC is audited.
func TestFleet_ForgedArchiveRelocationAttachesNoForeignNetwork(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	coord, dead, target := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	const token = "tok-forged"
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536)
	}
	for _, nr := range []corrosion.NetworkRecord{
		{Name: "ctnet", Type: "bridge", Config: `{"type":"bridge","interface":"br-ctnet"}`},
		{Name: "vnet", Type: "bridge", Project: "victim", Config: `{"type":"bridge","interface":"br-victim"}`},
	} {
		if err := corrosion.UpsertNetwork(ctx, coord.DB, nr); err != nil {
			t.Fatal(err)
		}
	}
	createSizedContainer(t, c, dead, "ct", "acme", 0, 256)
	honest := []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-ctnet", MAC: "02:00:00:00:00:01"},
		{Name: "eth1", Bridge: "br-raw", MAC: "02:00:00:00:00:02"},
	}
	// The forger's archive: the honest NICs plus one on victim's network.
	setContainerNICs(t, dead, "ct", append(append([]corrosion.ContainerNetwork(nil), honest...),
		corrosion.ContainerNetwork{Name: "eth9", NetworkName: "vnet", Bridge: "br-victim", MAC: "02:00:00:00:00:09"}))
	repo, _ := backupContainer(t, c, dead, "ct")
	setContainerNICs(t, dead, "ct", honest)
	row, _ := corrosion.GetContainer(ctx, dead.DB, dead.Name, "ct")
	row.State, row.StateDetail = "relocating", corrosion.RelocateRestoreDetail(target.Name, token)
	if err := corrosion.UpsertContainer(ctx, dead.DB, *row); err != nil {
		t.Fatal(err)
	}

	coord.Server.SetBackupRepos(map[string]string{"main": repo})
	outcome, err := coord.Server.RestoreContainerFromBackup(ctx, "ct", target.Name, token)
	if err != nil || outcome != corrosion.RestoreLanded {
		t.Fatalf("relocate: (%v, %v)", outcome, err)
	}
	requireLinks(t, target.Name, target.CT.Config("ct"), []string{"br-ctnet", "br-raw"}, "br-victim")
	if got := strings.Join(rowNICs(t, target, target.Name, "ct"), " "); got != "eth0@br-ctnet eth1@br-raw" {
		t.Errorf("the relocated row records NICs %q; want only the row's eth0 and eth1", got)
	}
	if !auditedOn(t, target, "ct.restore", "ct", "eth9") {
		t.Error("the archive's dropped NIC eth9 was not audited")
	}
}

// R4-I1. A container whose row predates the create spec (an empty spec)
// says nothing about its NICs, so a peer move keeps the network its archive
// configures — the veth-on-bridge NICs litevirt renders — and drops any
// other kind, which is host access (a host NIC moved in).
func TestFleet_PeerMoveOfAPreSpecRowKeepsTheArchivesBridgeNICs(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	createContainer(t, c, src, "old")
	cfg := filepath.Join(src.CT.dir("old"), "config")
	f, err := os.OpenFile(cfg, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("lxc.net.0.type = veth\nlxc.net.0.link = br-legacy\nlxc.net.0.flags = up\nlxc.net.0.hwaddr = 02:00:00:00:00:0a\n" +
		"lxc.net.1.type = phys\nlxc.net.1.link = eth9\n")
	f.Close()
	// An earlier build's row: no create spec at all (an upsert keeps a spec
	// it is not given, so clear it directly).
	if err := src.DB.Execute(ctx, `UPDATE containers SET create_spec = '' WHERE host_name = ? AND name = ?`, src.Name, "old"); err != nil {
		t.Fatal(err)
	}
	if err := runMigrate(t, c, src, dst, "old", stagingRepo(t)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	got := dst.CT.Config("old")
	requireLinks(t, dst.Name, got, []string{"br-legacy"}, "phys", "eth9", "lxcbr0")
	if !strings.Contains(got, "lxc.net.0.hwaddr = 02:00:00:00:00:0a") {
		t.Errorf("the kept NIC lost its MAC:\n%s", got)
	}
}
