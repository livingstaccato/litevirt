package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestAuditWriter_RPCRowsAreSigned: every RPC audits through Server.auditAs on
// s.db — and since bdf97c28 and 5f91f87f so do the web UI's security-group,
// resource-mapping and firewall changes, which call these handlers rather than
// writing in-process. On a signing client every such row comes out signed and
// verify counts it so. user.reset-admin, the third path, is pinned by
// TestResetAdminPassword_LocalRootResetsAndAuditsOnce. Listed in corrosion's
// TestAuditWriters_EveryCallSiteIsCovered.
func TestAuditWriter_RPCRowsAreSigned(t *testing.T) {
	s := testServer(t)
	corrosion.SignAuditRowsForTest(t, s.db, s.hostName)
	ctx := adminCtxWithEngine(t, s)

	if _, err := s.SetFirewallDefault(ctx, &pb.SetFirewallDefaultRequest{DefaultDeny: true}); err != nil {
		t.Fatalf("SetFirewallDefault: %v", err)
	}
	if _, err := s.CreateSecurityGroup(ctx, &pb.CreateSecurityGroupRequest{Name: "web"}); err != nil {
		t.Fatalf("CreateSecurityGroup: %v", err)
	}
	s.auditAs(ctx, "alice", "vm.create", "web-1", "", "ok")

	corrosion.AssertAuditRowsSignedForTest(t, s.db, 3)
}
