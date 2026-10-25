package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestListHosts_ReturnsFenceStrategy pins that the list RPC carries each
// host's fence strategy, as InspectHost does. `lv doctor fence` and the UI
// health page name the hosts that fence only over SSH from ListHosts, and
// while it left the field empty they read every host as best-effort: the
// rc9 lab listed IPMI hosts under "fence only over SSH" (rc9-lab F2).
//
// Mutation: drop FenceStrategy from ListHosts' pb.Host — red.
func TestListHosts_ReturnsFenceStrategy(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	want := map[string]string{"bmc": "ipmi", "rf": "redfish", "sshonly": "ssh", "unset": ""}
	for name, strategy := range want {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
			State: "active", CPUTotal: 8, MemTotal: 16384, FenceStrategy: strategy,
		}); err != nil {
			t.Fatalf("InsertHost(%s): %v", name, err)
		}
	}
	resp, err := s.ListHosts(ctx, &pb.ListHostsRequest{})
	if err != nil {
		t.Fatalf("ListHosts: %v", err)
	}
	if len(resp.GetHosts()) != len(want) {
		t.Fatalf("ListHosts returned %d hosts, want %d", len(resp.GetHosts()), len(want))
	}
	for _, h := range resp.GetHosts() {
		if got := h.GetFenceStrategy(); got != want[h.GetName()] {
			t.Errorf("ListHosts: %s fence strategy %q, want %q", h.GetName(), got, want[h.GetName()])
		}
		in, err := s.InspectHost(ctx, &pb.InspectHostRequest{Name: h.GetName()})
		if err != nil {
			t.Fatalf("InspectHost(%s): %v", h.GetName(), err)
		}
		if in.GetFenceStrategy() != h.GetFenceStrategy() {
			t.Errorf("%s: ListHosts says %q, InspectHost %q", h.GetName(), h.GetFenceStrategy(), in.GetFenceStrategy())
		}
	}
}
