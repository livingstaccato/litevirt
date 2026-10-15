package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// vtepRecorder is a NetworkProvisioner that records the VTEP address and the
// underlay each Provision is handed.
type vtepRecorder struct {
	bridgeRemovalProv
	localIPs  []string
	underlays []string
}

func (p *vtepRecorder) Provision(_ context.Context, _ *corrosion.Client, _ string, def compose.NetworkDef, localIP, _ string) (string, error) {
	p.localIPs = append(p.localIPs, localIP)
	p.underlays = append(p.underlays, def.Underlay)
	return "br-vni5177", nil
}

// labResolver models the lab node: before the latch the default-route
// endpoint every node shares, after it the host address on net1.
func labResolver(_ string, _ compose.NetworkDef, hostAddress string, switched bool) (string, string, error) {
	if !switched {
		return "10.0.2.15", "ens3", nil
	}
	return hostAddress, "net1", nil
}

func vxlanServer(t *testing.T, gate fakeFeatureGate) (*Server, *vtepRecorder) {
	t.Helper()
	s := testServerR2(t)
	prov := &vtepRecorder{}
	s.SetNetworkProvisioner(prov)
	s.SetReleaseFeatureGate(gate)
	s.SetHostAddress("10.77.0.11")
	s.SetVTEPResolver(labResolver)
	if err := corrosion.UpsertNetwork(adminCtx(), s.db, corrosion.NetworkRecord{
		Name: "vxd_vxdnet", Type: "vxlan", Config: `{"interface":"vxdnet","vni":5177}`,
	}); err != nil {
		t.Fatal(err)
	}
	return s, prov
}

// provisionEveryPath provisions vxd_vxdnet through each path a host does it
// by: the network reconciler, a VM create, a NIC hotplug and a failover start.
func provisionEveryPath(t *testing.T, s *Server) {
	t.Helper()
	ctx := adminCtx()
	if err := s.ReconcileNetworksOnce(ctx); err != nil {
		t.Fatalf("ReconcileNetworksOnce: %v", err)
	}
	if _, err := s.provisionForVM(ctx, "vxd_vxdnet"); err != nil {
		t.Fatalf("provisionForVM: %v", err)
	}
	if _, err := s.ensureNICNetworkProvisioned(ctx, "vxd_vxdnet"); err != nil {
		t.Fatalf("ensureNICNetworkProvisioned: %v", err)
	}
	// health.Reconciler's failover start: the record lookup hands the
	// server's ProvisionNetworkHere no address, and it resolves one.
	if _, err := network.ProvisionForVMWith(ctx, s.db, "vxd_vxdnet", s.hostName, s.ProvisionNetworkHere); err != nil {
		t.Fatalf("ProvisionForVMWith: %v", err)
	}
}

// Once the release token has latched, every path that provisions a vxlan
// network hands the provisioner the host's address (advertise_address) and
// the underlay resolved with it — not the default-route endpoint, which on
// the lab was 10.0.2.15 on every node, so each host's flood entry for every
// peer was itself.
func TestVXLANProvisioning_UsesTheHostAddressOnceLatched(t *testing.T) {
	s, prov := vxlanServer(t, fakeFeatureGate{t: t})
	provisionEveryPath(t, s)
	if len(prov.localIPs) != 4 {
		t.Fatalf("Provision calls = %v, want 4", prov.localIPs)
	}
	for i := range prov.localIPs {
		if prov.localIPs[i] != "10.77.0.11" || prov.underlays[i] != "net1" {
			t.Errorf("Provision call %d: local %q dev %q, want the host address 10.77.0.11 on net1",
				i, prov.localIPs[i], prov.underlays[i])
		}
	}
}

// Before the latch a host keeps the endpoint every earlier build used, so it
// still reaches its peers on the previous build.
func TestVXLANProvisioning_KeepsThePreviousEndpointBeforeTheLatch(t *testing.T) {
	s, prov := vxlanServer(t, fakeFeatureGate{err: errors.New("upgrade in progress")})
	provisionEveryPath(t, s)
	if len(prov.localIPs) != 4 {
		t.Fatalf("Provision calls = %v, want 4", prov.localIPs)
	}
	for i := range prov.localIPs {
		if prov.localIPs[i] != "10.0.2.15" || prov.underlays[i] != "ens3" {
			t.Errorf("Provision call %d: local %q dev %q, want the previous build's 10.0.2.15 on ens3",
				i, prov.localIPs[i], prov.underlays[i])
		}
	}
}

// A server never told its address refuses a vxlan network instead of
// guessing one, and says so once as an event naming the network.
func TestVXLANProvisioning_UnwiredAddressIsRefused(t *testing.T) {
	s, prov := vxlanServer(t, fakeFeatureGate{t: t})
	s.SetHostAddress("")
	s.SetVTEPResolver(nil) // network.ResolveVTEP
	ch, unsub := s.events.Subscribe()
	defer unsub()

	if _, err := s.provisionForVM(adminCtx(), "vxd_vxdnet"); err == nil {
		t.Fatal("a vxlan network was provisioned with no host address")
	}
	if len(prov.localIPs) != 0 {
		t.Fatalf("Provision was called with %v", prov.localIPs)
	}
	select {
	case e := <-ch:
		if e.Action != "network.vtep_refused" || e.Target != "vxd_vxdnet" {
			t.Fatalf("event %+v, want network.vtep_refused for vxd_vxdnet", e)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no network.vtep_refused event")
	}
	// The same refusal again is not a second event.
	_, _ = s.provisionForVM(adminCtx(), "vxd_vxdnet")
	select {
	case e := <-ch:
		t.Fatalf("a repeated refusal published again: %+v", e)
	case <-time.After(200 * time.Millisecond):
	}
}

// At the latch the network reconciler provisions a vxlan network once more,
// on the host address; after that a pass only syncs its forwarding entries.
func TestReconcileNetworks_ReprovisionsVXLANOnceAtTheLatch(t *testing.T) {
	ctx := adminCtx()
	s, prov := vxlanServer(t, fakeFeatureGate{err: errors.New("upgrade in progress")})
	if err := s.ReconcileNetworksOnce(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetReleaseFeatureGate(fakeFeatureGate{t: t}) // the token latches
	for i := 0; i < 2; i++ {
		if err := s.ReconcileNetworksOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if want := []string{"10.0.2.15", "10.77.0.11"}; len(prov.localIPs) != 2 ||
		prov.localIPs[0] != want[0] || prov.localIPs[1] != want[1] {
		t.Fatalf("Provision calls %v, want %v", prov.localIPs, want)
	}
}

// SyncVTEP hands the sync the peer its certificate names, with the VTEP it
// pushed, and refuses a VNI that is not the network's: that would rewrite
// another network's device from this network's rows.
func TestSyncVTEP_PassesTheSenderAndChecksTheVNI(t *testing.T) {
	s, _ := vxlanServer(t, fakeFeatureGate{t: t})
	type args struct {
		network, host string
		vni           int
		peer, addr    string
	}
	var got []args
	prev := syncPeerVTEP
	syncPeerVTEP = func(_ context.Context, _ *corrosion.Client, networkName, hostName string, vni int, peer, peerAddr string) error {
		got = append(got, args{networkName, hostName, vni, peer, peerAddr})
		return nil
	}
	t.Cleanup(func() { syncPeerVTEP = prev })
	ctx := peerCtxFor(t, s, "node-4")

	if _, err := s.SyncVTEP(ctx, &pb.SyncVTEPRequest{NetworkName: "vxd_vxdnet", VtepIp: "10.77.0.14", Vni: 5177}); err != nil {
		t.Fatalf("SyncVTEP: %v", err)
	}
	want := args{"vxd_vxdnet", s.hostName, 5177, "node-4", "10.77.0.14"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("sync called with %+v, want [%+v]", got, want)
	}
	_, err := s.SyncVTEP(ctx, &pb.SyncVTEPRequest{NetworkName: "vxd_vxdnet", VtepIp: "10.77.0.14", Vni: 999})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("SyncVTEP with another VNI: %v, want InvalidArgument", err)
	}
	if len(got) != 1 {
		t.Fatalf("a mismatched VNI still reached the sync: %+v", got)
	}
}
