package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// P1. A relocation whose mark has not replicated here yet waits for it (a
// bounded poll of this replica) rather than refusing at once: the mark
// arriving within the wait is the row the move is authorized by.
func TestPeerMoveSource_WaitsForTheRowToArrive(t *testing.T) {
	s := testServer(t)
	s.hostName = "self"
	s.sourceRowWait = 5 * time.Second
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(relocateTokenMDKey, "tok"))
	spec := corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br-raw"}}})
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
			HostName: "dead", Name: "ct1", State: "relocating", StateDetail: corrosion.RelocateRestoreDetail("self", "tok"), CreateSpec: spec,
		})
	}()
	src, err := s.peerMoveSource(ctx, &pb.RestoreContainerRequest{Name: "ct1"}, "")
	if err != nil || src == nil || src.CreateSpec != spec {
		t.Fatalf("a mark that arrives within the wait = %+v (%v); want that row", src, err)
	}
}

// P1. An earlier-build coordinator sends no row; if the mark never reaches
// this replica, the relocation restores as main did (never refused into an
// image-recreate, which would lose the backed-up data): the source is nil,
// and the NICs are admitted from the archive by their network records.
func TestPeerMoveSource_OlderCoordinatorWithNoRowRestoresAsMain(t *testing.T) {
	s := testServer(t)
	s.hostName = "self"
	s.sourceRowWait = 50 * time.Millisecond
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(relocateTokenMDKey, "tok"))
	src, err := s.peerMoveSource(ctx, &pb.RestoreContainerRequest{Name: "ct1"}, "")
	if err != nil || src != nil {
		t.Fatalf("a relocation from an earlier coordinator with no row here = %+v (%v); want no source and no error", src, err)
	}
	// A cold migrate still refuses (its source rolls back; nothing is lost).
	if _, err := s.peerMoveSource(ctx, &pb.RestoreContainerRequest{Name: "ct1"}, "src"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a migrate with no source row = %v; want FailedPrecondition", err)
	}
}

// P1. With no source row (an earlier coordinator, the mark never arrived),
// a relocation's NICs are the archive's managed NICs whose network record
// exists, is a container's type and is one the project may use; a raw NIC,
// a missing network, a direct one and another project's are dropped and
// said.
func TestAuthorizeRestoredNICs_PeerMoveWithoutASourceRowRestoresAsMain(t *testing.T) {
	s := testServer(t)
	r4Networks(t, s)
	archive := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-forged"},
		{Name: "eth1", Bridge: "br-raw"},
		{Name: "eth2", NetworkName: "vnet"},
		{Name: "eth3", NetworkName: "gone"},
		{Name: "eth4", NetworkName: "mvt"},
	}}
	out, dropped, err := s.authorizeRestoredNICs(adminCtx(), "acme", archive, nil, true)
	if err != nil {
		t.Fatalf("a relocation with no source row: %v", err)
	}
	if got := nicNames(out.Networks); len(got) != 1 || got[0] != "eth0@br-ctnet" {
		t.Errorf("NICs = %v; want only eth0@br-ctnet (dropped %v)", got, dropped)
	}
	said := strings.Join(dropped, "; ")
	for _, want := range []string{"eth1", "eth2", "vnet", "eth3", "eth4"} {
		if !strings.Contains(said, want) {
			t.Errorf("the drop of %q was not said: %s", want, said)
		}
	}
}

// P2. A create whose network list cannot be read fails Unavailable (retried),
// never the raw-bridge path and never a code that reads as final.
func TestCreateContainer_UnreadableNetworkListIsUnavailable(t *testing.T) {
	s := testServer(t)
	s.SetContainerRuntime(&fakeCTRuntime{})
	if err := s.db.Execute(context.Background(), `DROP TABLE networks`); err != nil {
		t.Fatal(err)
	}
	_, err := s.CreateContainer(adminCtx(), &pb.CreateContainerRequest{
		Name: "web", Template: "download", Distro: "alpine", Release: "3.19",
		Networks: []*pb.ContainerNetwork{{Name: "eth0", Bridge: "br-x"}},
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("create with an unreadable network list = %v; want Unavailable", err)
	}
}

// P4. source_create_spec is honoured only on a peer move. An operator restore
// that sends one — a privileged spec with a mount and a raw br-victim NIC —
// gets none of it: the archive's spec, judged as an operator restore, is
// what lands.
func TestRestoreContainer_OperatorRestoreIgnoresSourceCreateSpec(t *testing.T) {
	s, _ := secServer(t)
	r4Networks(t, s)
	repo, ts := ctTestRepo(t), "2026-10-10T12:00:00Z"
	ctx := context.Background()
	if err := corrosion.UpsertContainer(ctx, s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "ct1", State: "stopped", Image: "alpine:3.19", Project: "acme",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", IDMapBase: 165536, Confinement: "default",
			Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "ctnet"}}}),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.BackupContainer(&pb.BackupContainerRequest{Name: "ct1", HostName: "host-a", RepoPath: repo, Timestamp: ts},
		&progressStream[pb.BackupContainerProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("BackupContainer: %v", err)
	}
	_ = corrosion.DeleteContainer(ctx, s.db, "host-a", "ct1")
	forged := corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download",
		Mounts:   []corrosion.ContainerHostMount{{HostPath: "/", ContainerPath: "/host", ReadWrite: true}},
		Networks: []corrosion.ContainerNetwork{{Name: "eth0", NetworkName: "ctnet"}, {Name: "eth1", Bridge: "br-victim"}}})
	if err := s.RestoreContainer(&pb.RestoreContainerRequest{Name: "ct1", RepoPath: repo, Timestamp: ts, SourceCreateSpec: forged},
		&progressStream[pb.RestoreContainerProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("operator restore: %v", err)
	}
	got := specOf(t, s, "host-a", "ct1")
	if len(got.Mounts) != 0 || got.IDMapBase == 0 {
		t.Errorf("the restored spec took the sent one's mounts or privilege: %+v", got)
	}
	if names := nicNames(got.Networks); len(names) != 1 || names[0] != "eth0@br-ctnet" {
		t.Errorf("the restored NICs = %v; want only the archive's eth0@br-ctnet", names)
	}
}
