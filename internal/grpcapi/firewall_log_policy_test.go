package grpcapi

import (
	"context"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func logPolicyServer(t *testing.T) (*Server, *relGate) {
	t.Helper()
	s := testServer(t)
	g := &relGate{t: t, open: true}
	s.SetReleaseFeatureGate(g)
	s.db.SetClusterPolicyGate(func() bool { return true })
	for _, h := range []string{"node-1", "cluster"} {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	return s, g
}

// C3 (B4's cases for firewall_log): setting the log policy needs role
// operator; it goes through the firewall_log gate and is refused before the
// latch with nothing written; the scope is the cluster ("" or "cluster") or a
// known host; inherit is for a host only; 0 means the default budget and a
// budget out of 1..10000 is refused; each write is audited as
// firewall.log_policy with the scope and before/after.
//
// Mutations: skip WithReleaseFeature — the closed gate does not refuse, red;
// check role viewer — the viewer writes, red; accept an unknown host — red;
// audit nothing — red.
func TestSetFirewallLogPolicy(t *testing.T) {
	s, g := logPolicyServer(t)
	ctx := adminCtx()
	set := func(c context.Context, scope, mode string, rate, burst uint32) (*pb.FirewallLogPolicy, error) {
		return s.SetFirewallLogPolicy(c, &pb.SetFirewallLogPolicyRequest{Scope: scope, Mode: mode, Rate: rate, Burst: burst})
	}
	if _, err := set(viewerCtx(), "", "on", 0, 0); status.Code(err) != codes.PermissionDenied {
		t.Errorf("viewer: %v, want PermissionDenied", err)
	}
	g.open = false
	if _, err := set(ctx, "", "on", 0, 0); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("before the latch: %v, want FailedPrecondition", err)
	}
	if rows, _ := s.db.Query(context.Background(), `SELECT 1 FROM cluster_policies WHERE key LIKE 'firewall_log%'`); len(rows) != 0 {
		t.Fatal("a row was written before the latch")
	}
	g.open = true
	g.used = nil
	p, err := set(ctx, "", "on", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if p.GetScope() != "cluster" || !p.GetDefaultPolicy() || p.GetRate() != 5 || p.GetBurst() != 10 {
		t.Errorf("cluster on = %+v, want on at 5/10", p)
	}
	if !slices.Equal(g.used, []capabilities.Feature{capabilities.FeatureFirewallLog}) {
		t.Errorf("gates asked %v, want firewall_log", g.used)
	}
	// Round 2 m-3: the cluster scope's audit target is "(cluster)", which no
	// host name can be, so it cannot be read as host cluster's.
	wantAudit(t, s, "firewall.log_policy", "admin", "(cluster)", "before=unset after=on rate=5 burst=10")

	if _, err := set(ctx, "node-1", "off", 50, 100); err != nil {
		t.Fatal(err)
	}
	wantAudit(t, s, "firewall.log_policy", "admin", "node-1", "before=unset after=off rate=50 burst=100")
	if _, err := set(ctx, "node-1", "inherit", 0, 0); err != nil {
		t.Fatal(err)
	}
	wantAudit(t, s, "firewall.log_policy", "admin", "node-1", "before=off rate=50 burst=100 after=unset")
	// Round 1 m-10 (Track B4's rule): "" is the cluster; every other scope,
	// "cluster" included, is a host, so a host named cluster is reachable.
	if _, err := set(ctx, "cluster", "off", 0, 0); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := corrosion.GetFirewallLogPolicy(context.Background(), s.db, ""); !got.On() {
		t.Errorf("scope \"cluster\" changed the cluster row: %+v", got)
	}
	if got, rec, _ := corrosion.GetFirewallLogPolicy(context.Background(), s.db, "cluster"); !rec || got.On() {
		t.Errorf("scope \"cluster\" did not set host cluster's row: %+v %v", got, rec)
	}
	wantAudit(t, s, "firewall.log_policy", "admin", "cluster", "before=unset after=off rate=5 burst=10")
	if _, err := set(ctx, "cluster", "inherit", 0, 0); err != nil {
		t.Errorf("inherit for host cluster: %v", err)
	}

	for _, bad := range []struct {
		scope, mode string
		rate, burst uint32
		what        string
	}{
		{"nope", "on", 0, 0, "an unknown host"},
		{"", "inherit", 0, 0, "inherit at the cluster scope"},
		{"", "maybe", 0, 0, "an unknown mode"},
		{"", "on", 10001, 0, "a rate over the maximum"},
		{"node-1", "on", 0, 10001, "a burst over the maximum"},
		{"node-1", "inherit", 5, 0, "inherit with a rate"},
	} {
		if _, err := set(ctx, bad.scope, bad.mode, bad.rate, bad.burst); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: %v, want InvalidArgument", bad.what, err)
		}
	}
}

// C3: the status lists the cluster policy first, then every host by name with
// its own row or the cluster's (inherited), a host named "cluster" included.
// Any authenticated role may read it.
//
// Mutation: report a host with no row as not inherited — red.
func TestGetFirewallLogPolicy(t *testing.T) {
	s, _ := logPolicyServer(t)
	ctx := adminCtx()
	if _, err := s.SetFirewallLogPolicy(ctx, &pb.SetFirewallLogPolicyRequest{Mode: "on", Rate: 7, Burst: 9}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetFirewallLogPolicy(ctx, &pb.SetFirewallLogPolicyRequest{Scope: "node-1", Mode: "off"}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.GetFirewallLogPolicy(viewerCtx(), &pb.GetFirewallLogPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	ps := resp.GetPolicies()
	if len(ps) != 3 {
		t.Fatalf("policies = %+v, want the cluster and two hosts", ps)
	}
	if c := ps[0]; c.GetScope() != "cluster" || c.GetInherited() || !c.GetDefaultPolicy() || c.GetRate() != 7 || c.GetBurst() != 9 || c.GetSetBy() != "admin" {
		t.Errorf("first row = %+v, want the cluster's on at 7/9 set by admin", c)
	}
	if h := ps[1]; h.GetScope() != "cluster" || !h.GetInherited() || !h.GetDefaultPolicy() || h.GetRate() != 7 {
		t.Errorf("host \"cluster\" = %+v, want inherited from the cluster's on at 7", h)
	}
	if n := ps[2]; n.GetScope() != "node-1" || n.GetInherited() || n.GetDefaultPolicy() || n.GetRate() != 5 {
		t.Errorf("node-1 = %+v, want its own off at the default budget", n)
	}

	// Round 1 m-8: an unreadable row is shown as rate 0 burst 0 (no readable
	// row has either), and is not inherited.
	if err := s.db.Execute(context.Background(), `UPDATE cluster_policies SET value = '{' WHERE key = 'firewall_log/node-1'`); err != nil {
		t.Fatal(err)
	}
	resp, err = s.GetFirewallLogPolicy(viewerCtx(), &pb.GetFirewallLogPolicyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if n := resp.GetPolicies()[2]; n.GetRate() != 0 || n.GetBurst() != 0 || n.GetInherited() || n.GetDefaultPolicy() {
		t.Errorf("unreadable node-1 = %+v, want rate 0 burst 0, not inherited", n)
	}
}
