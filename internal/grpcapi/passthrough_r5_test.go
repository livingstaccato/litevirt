package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// R4-I1 and R4-I2. A peer move (cold migrate, relocation) re-homes an
// existing container, so its NICs are the ones its SOURCE ROW records, by
// NIC name, managed NICs included — never the archive's:
//   - a managed NIC whose network record exists is rendered on that
//     network's bridge;
//   - one whose network record is gone (force-deleted, or not replicated
//     here yet) keeps the bridge the row records, as on main;
//   - a raw NIC keeps its bridge, and a direct/sriov one is kept as the row
//     records it;
//   - the row's address and MAC are what the container keeps;
//   - a NIC the archive adds (eth9 on project victim's network) is dropped
//     and said, wherever it points.
func TestAuthorizeRestoredNICs_PeerMoveTakesTheSourceRowsNICs(t *testing.T) {
	s := testServer(t)
	r4Networks(t, s)
	archive := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", IP: "10.9.9.9", MAC: "02:00:00:00:09:09"},
		{Name: "eth1", NetworkName: "gone"},
		{Name: "eth2", Bridge: "br-raw"},
		{Name: "eth3", NetworkName: "mvt"},
		{Name: "eth9", NetworkName: "vnet", Bridge: "br-victim"}, // forged: project victim's
	}}
	row := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-ctnet", IP: "10.0.0.5", MAC: "02:00:00:00:00:05"},
		{Name: "eth1", NetworkName: "gone", Bridge: "br-gone", MAC: "02:00:00:00:00:06"},
		{Name: "eth2", Bridge: "br-raw"},
		{Name: "eth3", NetworkName: "mvt", Bridge: "br-old"},
		{Name: "eth4", Bridge: "br-later"}, // added after the backup was taken
	}}
	source := &corrosion.ContainerRecord{Name: "ct", Project: "acme", CreateSpec: corrosion.EncodeCreateSpec(row)}
	out, dropped, err := s.authorizeRestoredNICs(adminCtx(), "acme", archive, source, true)
	if err != nil {
		t.Fatalf("peer move: %v", err)
	}
	want := []string{"eth0@br-ctnet", "eth1@br-gone", "eth2@br-raw", "eth3@br-old", "eth4@br-later"}
	if got := nicNames(out.Networks); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("a peer move's NICs = %v; want the source row's %v (dropped: %v)", got, want, dropped)
	}
	if len(out.Networks) > 0 && (out.Networks[0].IP != "10.0.0.5" || out.Networks[0].MAC != "02:00:00:00:00:05") {
		t.Errorf("eth0 kept %s/%s; want the row's 10.0.0.5/02:00:00:00:00:05", out.Networks[0].IP, out.Networks[0].MAC)
	}
	for _, n := range out.Networks {
		if n.Bridge == "br-victim" || n.NetworkName == "vnet" {
			t.Errorf("a peer move attached the archive's NIC %s to another project's network", n.Name)
		}
	}
	if said := strings.Join(dropped, "; "); !strings.Contains(said, "eth9") {
		t.Errorf("the archive's extra NIC eth9 was not said: %q", said)
	}
}

// R4-I1. A peer move whose source row predates the create spec (an empty
// spec) keeps the network the archive configures; nothing in the row says
// otherwise.
func TestRestoredNetworkMode_PreSpecPeerMoveKeepsTheArchivesNetwork(t *testing.T) {
	old := &corrosion.ContainerRecord{Name: "ct"}
	if got := restoredNetworkMode(false, old); got != networkKeepBridgeNICs {
		t.Errorf("a peer move of a row with no spec renders %v; want the archive's bridge NICs kept", got)
	}
	if got := restoredNetworkMode(true, nil); got != networkRender {
		t.Errorf("an operator restore renders %v; want its authorized NICs rendered", got)
	}
	row := &corrosion.ContainerRecord{Name: "ct", CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download"})}
	if got := restoredNetworkMode(false, row); got != networkRender {
		t.Errorf("a peer move of a row with a spec renders %v; want the row's NICs rendered", got)
	}
}

// m-3. A bridge whose classification cannot be read (the network list is
// unreadable) fails the restore closed, rather than reading as "raw" and
// keeping it on raw-bridge authority alone.
func TestAuthorizeRestoredNICs_UnreadableClassificationFailsClosed(t *testing.T) {
	s := testServer(t)
	r4Networks(t, s)
	_ = s.db.Close()
	cs := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br-victim"}}}
	out, dropped, err := s.authorizeRestoredNICs(adminCtx(), "acme", cs, nil, false)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("an unreadable network list = %v (NICs %v, dropped %v); want Unavailable", err, nicNames(out.Networks), dropped)
	}
}

// m-7. A clone judges a raw NIC by what its bridge now is: a raw bridge that
// is another project's rendered network is that project's NIC, refused as a
// restore or create refuses it. A raw bridge that is no network is carried.
func TestCloneContainer_ReclassifiesARawBridge(t *testing.T) {
	s, rt := secServer(t)
	r4Networks(t, s)
	seedSecCT(t, s, rt, "src", "stopped", corrosion.ContainerCreateSpec{Template: "download",
		Networks: []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br-victim"}}})
	_, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "src", Target: "c2", HostName: "host-a"})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "vnet") {
		t.Fatalf("clone of a source on another project's bridge = %v; want PermissionDenied naming vnet", err)
	}
	if len(rt.cloneCalls) != 0 {
		t.Fatalf("the refused clone copied the source: %+v", rt.cloneCalls)
	}
	seedSecCT(t, s, rt, "plain", "stopped", corrosion.ContainerCreateSpec{Template: "download",
		Networks: []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br-legacy"}}})
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "plain", Target: "c3", HostName: "host-a"}); err != nil {
		t.Fatalf("clone of a source on a raw bridge that is no network: %v", err)
	}
}
