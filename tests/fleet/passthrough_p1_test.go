package fleet

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// p1Relocation sets up a relocation of ct from dead onto target the way an
// EARLIER-build coordinator drives it: the mark is on the coordinator's
// replica only (nothing replicates here unless the scenario moves it), and
// the request carries the token but no source row. The archive and the row
// record a managed NIC (ctnet), a raw NIC and one on project victim's
// network.
func p1Relocation(t *testing.T) (c *Cluster, coord, target *Node, repo, ts string, marked corrosion.ContainerRecord) {
	t.Helper()
	c = New(t, Options{Nodes: 3})
	ctx := context.Background()
	coord, dead, tgt := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		for _, nr := range []corrosion.NetworkRecord{
			{Name: "ctnet", Type: "bridge", Config: `{"type":"bridge","interface":"br-ctnet"}`},
			{Name: "vnet", Type: "bridge", Project: "victim", Config: `{"type":"bridge","interface":"br-victim"}`},
		} {
			if err := corrosion.UpsertNetwork(ctx, n.DB, nr); err != nil {
				t.Fatal(err)
			}
		}
	}
	createSizedContainer(t, c, dead, "ct", "acme", 0, 256)
	setContainerNICs(t, dead, "ct", []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-ctnet", MAC: "02:00:00:00:00:01"},
		{Name: "eth1", Bridge: "br-raw", MAC: "02:00:00:00:00:02"},
		{Name: "eth2", NetworkName: "vnet", Bridge: "br-victim", MAC: "02:00:00:00:00:03"},
	})
	repo, ts = backupContainer(t, c, dead, "ct")
	row, _ := corrosion.GetContainer(ctx, dead.DB, dead.Name, "ct")
	marked = *row
	marked.State, marked.StateDetail = "relocating", corrosion.RelocateRestoreDetail(tgt.Name, "tok-p1")
	if err := corrosion.UpsertContainer(ctx, coord.DB, marked); err != nil {
		t.Fatal(err)
	}
	return c, coord, tgt, repo, ts, marked
}

// olderCoordinatorRestore drives target's RestoreContainer as an earlier
// coordinator does: peer mTLS, the relocation token, no source row.
func olderCoordinatorRestore(t *testing.T, c *Cluster, coord, target *Node, repo, ts string) error {
	t.Helper()
	md := metadata.AppendToOutgoingContext(context.Background(), "x-litevirt-relocate-token", "tok-p1")
	st, err := c.PeerClient(coord, target).RestoreContainer(md, &pb.RestoreContainerRequest{RepoPath: repo, Name: "ct", Timestamp: ts, HostName: target.Name})
	if err != nil {
		return err
	}
	for {
		if _, err := st.Recv(); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
	}
}

// P1. The coordinator's mark reaches the target while the target waits for
// it: the relocation lands on the row's NICs — all three, the raw one
// included, which only the row authorizes.
func TestFleet_RelocationWaitsForTheMarkToArrive(t *testing.T) {
	c, coord, target, repo, ts, marked := p1Relocation(t)
	target.Server.SetSourceRowWait(20 * time.Second)
	go func() {
		time.Sleep(2 * time.Second) // replication catching up
		_ = corrosion.UpsertContainer(context.Background(), target.DB, marked)
	}()
	if err := olderCoordinatorRestore(t, c, coord, target, repo, ts); err != nil {
		t.Fatalf("a relocation whose mark arrived within the wait: %v", err)
	}
	requireLinks(t, target.Name, target.CT.Config("ct"), []string{"br-ctnet", "br-raw", "br-victim"})
	if got := strings.Join(rowNICs(t, target, target.Name, "ct"), " "); got != "eth0@br-ctnet eth1@br-raw eth2@br-victim" {
		t.Errorf("the relocated row records NICs %q; want the source row's three", got)
	}
}

// P1. An earlier-build coordinator's relocation reaches a target whose
// replica never sees the mark: it restores as main did — the container and
// its backed-up data land (never refused into an image-recreate) — with the
// archive's managed NIC its project may use, and the raw NIC and the one on
// another project's network dropped and audited.
func TestFleet_OlderCoordinatorRelocationWithNoRowRestoresAsMain(t *testing.T) {
	c, coord, target, repo, ts, _ := p1Relocation(t)
	target.Server.SetSourceRowWait(time.Second)
	if err := olderCoordinatorRestore(t, c, coord, target, repo, ts); err != nil {
		t.Fatalf("a relocation from an earlier coordinator with no row here was refused: %v", err)
	}
	if !target.CT.Exists("ct") {
		t.Fatal("the relocation did not land the container")
	}
	requireLinks(t, target.Name, target.CT.Config("ct"), []string{"br-ctnet"}, "br-raw", "br-victim")
	for _, want := range []string{"eth1", "eth2"} {
		if !auditedOn(t, target, "ct.restore", "ct", want) {
			t.Errorf("the dropped NIC %s was not audited", want)
		}
	}
}
