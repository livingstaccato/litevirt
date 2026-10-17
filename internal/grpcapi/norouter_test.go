package grpcapi

import (
	"context"
	"github.com/litevirt/litevirt/internal/corrosion"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/compose"
)

// TestRoutedNetwork: which of a VM's NICs make its isolated NICs lose the
// router — any NIC that can carry its default route, a host-isolated one
// (its seed gives it the bridge as gateway) included; never an isolated NIC
// or one on a network with no record.
func TestRoutedNetwork(t *testing.T) {
	for _, tc := range []struct {
		name string
		def  *compose.NetworkDef
		want bool
	}{
		{"no record", nil, false},
		{"isolated", &compose.NetworkDef{Type: "isolated", Subnet: "10.1.0.0/24"}, false},
		{"isolated v6", &compose.NetworkDef{Type: "isolated", Subnet: "2001:db8::/64"}, false},
		{"isolated host-isolated", &compose.NetworkDef{Type: "isolated", Subnet: "10.1.0.0/24", HostIsolation: true}, true},
		{"bridge", &compose.NetworkDef{Type: "bridge", Subnet: "10.2.0.0/24"}, true},
		{"bridge host-isolated", &compose.NetworkDef{Type: "bridge", HostIsolation: true}, true},
		{"vxlan", &compose.NetworkDef{Type: "vxlan", VNI: 5}, true},
		{"direct", &compose.NetworkDef{Type: "direct", Interface: "eth0"}, true},
	} {
		if got := routedNetwork(tc.def); got != tc.want {
			t.Errorf("%s: routedNetwork = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Missing schema forces both delayed attempts; database teardown must wait
// for them even though the original caller has already returned.
func TestDHCPRetriesAreJoinedNetworkWork(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	s := &Server{db: db}
	s.resyncDHCPHosts()
	done := make(chan struct{})
	go func() { s.WaitNetworkWork(); close(done) }()
	defer func() { <-done }()
	select {
	case <-done:
		t.Fatal("network work joined before the DHCP retries finished")
	case <-time.After(30 * time.Millisecond):
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("DHCP retries did not finish")
	}
}

func TestDHCPStopCancelsAndJoinsChildren(t *testing.T) {
	db := corrosion.NewTestClientT(t)
	s := &Server{db: db}
	ctx, cancel := context.WithCancel(context.Background())
	periodicDone := s.StartDHCPReservations(ctx, time.Hour)
	s.resyncDHCPHosts()
	done := make(chan struct{})
	go func() { s.StopDHCPReservations(); s.WaitNetworkWork(); close(done) }()
	defer func() { cancel(); <-done }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stop did not cancel the periodic worker and delayed retries")
	}
	select {
	case <-periodicDone:
	default:
		t.Fatal("stop returned before the periodic worker exited")
	}
	refused := s.StartDHCPReservations(ctx, time.Hour)
	select {
	case <-refused:
	default:
		t.Fatal("a stopped server admitted another DHCP child")
	}
}
