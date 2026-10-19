package ui

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// synfloodUIMock answers GetFirewallSynflood with resp or err.
type synfloodUIMock struct {
	*mockGRPC
	resp *pb.GetFirewallSynfloodResponse
	err  error
}

func (m *synfloodUIMock) GetFirewallSynflood(context.Context, *pb.GetFirewallSynfloodRequest, ...grpc.CallOption) (*pb.GetFirewallSynfloodResponse, error) {
	return m.resp, m.err
}

// The rest of the firewall page reads nothing here.
func (m *synfloodUIMock) ListClusterFirewallRules(context.Context, *pb.ListClusterFirewallRulesRequest, ...grpc.CallOption) (*pb.ListClusterFirewallRulesResponse, error) {
	return &pb.ListClusterFirewallRulesResponse{}, nil
}

func (m *synfloodUIMock) ListHostFirewallRules(context.Context, *pb.ListHostFirewallRulesRequest, ...grpc.CallOption) (*pb.ListHostFirewallRulesResponse, error) {
	return &pb.ListHostFirewallRulesResponse{}, nil
}

func (m *synfloodUIMock) ListIpSets(context.Context, *pb.ListIpSetsRequest, ...grpc.CallOption) (*pb.ListIpSetsResponse, error) {
	return &pb.ListIpSetsResponse{}, nil
}

func (m *synfloodUIMock) ListFirewallDefaults(context.Context, *pb.ListFirewallDefaultsRequest, ...grpc.CallOption) (*pb.ListFirewallDefaultsResponse, error) {
	return &pb.ListFirewallDefaultsResponse{}, nil
}

func synfloodUIServer(t *testing.T, m *synfloodUIMock) *Server {
	t.Helper()
	s, err := NewServer(m, "test-cluster")
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// rowText is the visible text of the table row naming host.
func rowText(body, host string) string {
	m := regexp.MustCompile(`(?s)<tr[^>]*>\s*<td[^>]*>` + regexp.QuoteMeta(host) + `</td>.*?</tr>`).FindString(body)
	return strings.Join(strings.Fields(regexp.MustCompile(`<[^>]+>`).ReplaceAllString(m, " ")), " ")
}

// The firewall page loads a SYN-flood panel that shows, per host, what the
// host itself has in force (Track B review I-2): an observing host says
// observe, a host on a build without in_force says predates, a host that
// could not be asked shows "-" and why; never "on" for any of them. Against a
// daemon that predates SYN-flood status the panel says so.
//
// Mutations: show the policy as in force — h1 shows on: red; show an empty
// in_force as on — h3: red; load the panel with the page — red.
func TestUIFirewall_SynfloodPanelShowsWhatIsInForce(t *testing.T) {
	m := &synfloodUIMock{mockGRPC: newDefaultMock(), resp: &pb.GetFirewallSynfloodResponse{Policies: []*pb.FirewallSynfloodPolicy{
		{Scope: "cluster", Mode: "on", Rate: 200, Burst: 1000, SetBy: "olga"},
		{Scope: "host/h1", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, InForce: "observe", DropsV4: 5},
		{Scope: "host/h3", Mode: "on", Rate: 200, Burst: 1000, Inherited: true},
		{Scope: "host/h4", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, Error: "unreachable: connection refused"},
		{Scope: "host/h6", Mode: "on", Rate: 200, Burst: 1000, Inherited: true, InForce: "ipv6-only", DropsV6: 2},
	}}}
	s := synfloodUIServer(t, m)

	page := serveRequest(s, authReq(t, "GET", "/firewall", nil))
	assertStatus(t, page, http.StatusOK)
	// The panel asks every host only when asked, not on each page view
	// (round-1 re-review n-2).
	mustContain(t, page.Body.String(), `hx-get="/ui/firewall/synflood"`, `hx-trigger="click"`)
	if strings.Contains(page.Body.String(), `hx-trigger="load"`) {
		t.Error("the firewall page asks every host for SYN-flood status on each view")
	}

	w := serveRequest(s, authReq(t, "GET", "/ui/firewall/synflood", nil))
	assertStatus(t, w, http.StatusOK)
	body := w.Body.String()
	mustContain(t, body, "on, 200/second burst 1000")
	// Asking again needs no page reload (round-2 re-review n-b).
	mustContain(t, body, `hx-get="/ui/firewall/synflood"`)
	for host, want := range map[string]string{
		"h1": "h1 on observe 200 1000 cluster 5 0",
		"h3": "h3 on predates 200 1000 cluster 0 0",
		"h4": "h4 on - 200 1000 cluster - - unreachable: connection refused",
		"h6": "h6 on ipv6-only 200 1000 cluster - 2",
	} {
		if got := rowText(body, host); got != want {
			t.Errorf("row %s = %q, want %q", host, got, want)
		}
	}

	m.resp, m.err = nil, status.Error(codes.Unimplemented, "unknown method GetFirewallSynflood")
	w = serveRequest(s, authReq(t, "GET", "/ui/firewall/synflood", nil))
	mustContain(t, w.Body.String(), "predates SYN-flood status")
}
