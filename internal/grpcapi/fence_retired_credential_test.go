package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// `lv host fence` hands a retired fence credential on as retired, never as the
// old hosts.ipmi_pass column. The BMC address is TEST-NET-1 (RFC 5737), so a
// fence that escapes the check fails fast instead of reaching a real BMC.
//
// Mutation: drop IPMICredentialRetired from FenceHost's HostConfig — red.
func TestFenceHost_RetiredFenceCredentialReachesTheFence(t *testing.T) {
	s := fenceTestServer(t, false, false)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: "peer", Address: "10.0.0.2", SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active",
		FenceStrategy: "ipmi",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.DB().Exec(`UPDATE hosts SET ipmi_address = '192.0.2.10', ipmi_user = 'probe',
		ipmi_pass = 'Old-Machine-Pass' WHERE name = 'peer'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.DB().Exec(`INSERT INTO host_fence_credentials (host_name, ipmi_pass, updated_at, deleted_at)
		VALUES ('peer', '', '2026-06-01T00:00:00Z', '2026-06-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	var got fence.HostConfig
	s.SetFenceExecutor(func(_ context.Context, h fence.HostConfig) fence.Result {
		got = h
		return fence.Execute(context.Background(), h)
	})
	resp, err := s.FenceHost(adminCtx(), &pb.FenceHostRequest{Name: "peer", Confirmed: true})
	if err != nil {
		t.Fatalf("FenceHost: %v", err)
	}
	if got.IPMIPass != "" || !got.IPMICredentialRetired {
		t.Errorf("fence HostConfig has IPMIPass set %v, retired %v; want no password and retired",
			got.IPMIPass != "", got.IPMICredentialRetired)
	}
	if resp.GetDetail() == "" || !strings.Contains(resp.GetDetail(), "no IPMI password") {
		t.Errorf("FenceHost detail = %q; want it to say there is no IPMI password", resp.GetDetail())
	}
}
