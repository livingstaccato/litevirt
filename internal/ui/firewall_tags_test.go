package ui

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

func (m *mockGRPC) ListFirewallTags(_ context.Context, _ *pb.ListFirewallTagsRequest, _ ...grpc.CallOption) (*pb.ListFirewallTagsResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listFirewallTagsResp == nil {
		return nil, status.Error(codes.Unimplemented, "ListFirewallTags is not implemented")
	}
	return m.listFirewallTagsResp, nil
}

// The VM page shows the VM's firewall tags read-only, in a row of their own
// beside the labels; a daemon that cannot say shows no row.
//
// Mutation: drop the row from the template — red.
func TestVMDetail_ShowsFirewallTags(t *testing.T) {
	mock := newDefaultMock()
	mock.listFirewallTagsResp = &pb.ListFirewallTagsResponse{Tags: []*pb.FirewallTags{
		{Kind: "vm", Workload: "vm1", FwId: "aa", Tags: map[string]string{"role": "web", "env": "prod"}},
	}}
	s := newTestUIServer(t, mock)
	w := serveRequest(s, withAuth(mustReq(t, "GET", "/vms/vm1")))
	if w.Code != 200 {
		t.Fatalf("GET /vms/vm1: %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "Firewall tags:</span> env=prod role=web") {
		t.Errorf("the VM page does not show its firewall tags:\n%s", body)
	}

	old := newDefaultMock()
	w = serveRequest(newTestUIServer(t, old), withAuth(mustReq(t, "GET", "/vms/vm1")))
	if w.Code != 200 || strings.Contains(w.Body.String(), "Firewall tags:") {
		t.Errorf("an older daemon: %d, row shown=%v", w.Code, strings.Contains(w.Body.String(), "Firewall tags:"))
	}
}
