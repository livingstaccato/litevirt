package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func synfloodServer(t *testing.T, open bool, hosts ...string) *Server {
	t.Helper()
	s := guardServer(t, open)
	for _, h := range hosts {
		if err := corrosion.InsertHost(context.Background(), s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

// `lv firewall synflood` writes need the operator role (a viewer is refused,
// nothing written) and are audited as firewall.synflood with the scope as
// target and the state before and after.
//
// Mutations: drop RequireRole — the viewer writes: red; drop the audit, or
// record the wrong before — red.
func TestSetFirewallSynflood_RoleAndAudit(t *testing.T) {
	ctx := context.Background()
	s := synfloodServer(t, true, "h1")
	if _, err := s.SetFirewallSynflood(userCtx("v", "viewer"), &pb.SetFirewallSynfloodRequest{Mode: "on"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a viewer: %v, want PermissionDenied", err)
	}
	if _, rec, _ := corrosion.GetFirewallSynflood(ctx, s.db, ""); rec {
		t.Fatal("a refused write left a row")
	}
	op := userCtx("olga", "operator")
	p, err := s.SetFirewallSynflood(op, &pb.SetFirewallSynfloodRequest{Mode: "on"})
	if err != nil || p.GetScope() != "cluster" || p.GetMode() != "on" || p.GetRate() != 200 || p.GetBurst() != 1000 {
		t.Fatalf("on with the defaults: %+v, %v", p, err)
	}
	wantAudit(t, s, "firewall.synflood", "olga", "cluster", "before=unset after=on 200/1000")
	if _, err := s.SetFirewallSynflood(op, &pb.SetFirewallSynfloodRequest{Mode: "on", Rate: 50, Burst: 60}); err != nil {
		t.Fatal(err)
	}
	wantAudit(t, s, "firewall.synflood", "olga", "cluster", "before=on 200/1000 after=on 50/60")
	if _, err := s.SetFirewallSynflood(op, &pb.SetFirewallSynfloodRequest{Scope: "h1", Mode: "off"}); err != nil {
		t.Fatal(err)
	}
	wantAudit(t, s, "firewall.synflood", "olga", "h1", "before=unset after=off")
	if _, err := s.SetFirewallSynflood(op, &pb.SetFirewallSynfloodRequest{Scope: "h1", Mode: "inherit"}); err != nil {
		t.Fatal(err)
	}
	wantAudit(t, s, "firewall.synflood", "olga", "h1", "before=off after=unset")
}

// The scope is the cluster (empty) or a host this replica knows; the mode is
// on, off or inherit (a host only); on's rate and burst are 1-100000, 0 the
// default. Nothing refused is written.
//
// Mutation: drop the host lookup — an unknown host is written: red.
func TestSetFirewallSynflood_Validation(t *testing.T) {
	ctx := context.Background()
	s := synfloodServer(t, true, "h1")
	op := userCtx("olga", "operator")
	for name, req := range map[string]*pb.SetFirewallSynfloodRequest{
		"unknown host":         {Scope: "nope", Mode: "on"},
		"unknown mode":         {Mode: "strict"},
		"cluster inherit":      {Mode: "inherit"},
		"rate over":            {Mode: "on", Rate: 100001},
		"burst over":           {Mode: "on", Burst: 100001},
		"off with a rate":      {Mode: "off", Rate: 5},
		"inherit with a burst": {Scope: "h1", Mode: "inherit", Burst: 5},
	} {
		_, err := s.SetFirewallSynflood(op, req)
		want := codes.InvalidArgument
		if name == "unknown host" {
			want = codes.NotFound
		}
		if status.Code(err) != want {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	rows, err := s.db.Query(ctx, `SELECT key FROM cluster_policies WHERE key LIKE 'firewall_synflood%'`)
	if err != nil || len(rows) != 0 {
		t.Errorf("refused writes left rows %v, %v", rows, err)
	}
	if p, err := s.SetFirewallSynflood(op, &pb.SetFirewallSynfloodRequest{Mode: "on", Rate: 1, Burst: 100000}); err != nil || p.GetRate() != 1 || p.GetBurst() != 100000 {
		t.Errorf("the bounds: %+v, %v", p, err)
	}
}

// Before the release latch every write is refused with the release text and
// nothing is written.
//
// Mutation: write without WithReleaseFeature — red.
func TestSetFirewallSynflood_RefusedBeforeTheLatch(t *testing.T) {
	ctx := context.Background()
	s := synfloodServer(t, false, "h1")
	s.db.SetClusterPolicyGate(func() bool { return true })
	for _, req := range []*pb.SetFirewallSynfloodRequest{{Mode: "on"}, {Scope: "h1", Mode: "off"}} {
		_, err := s.SetFirewallSynflood(userCtx("olga", "operator"), req)
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "firewall_synflood needs "+capabilities.ReleaseToken) {
			t.Errorf("%+v before the latch: %v, want the release refusal", req, err)
		}
	}
	if rows, err := s.db.Query(ctx, `SELECT key FROM cluster_policies WHERE key LIKE 'firewall_synflood%'`); err != nil || len(rows) != 0 {
		t.Errorf("refused writes left rows %v, %v", rows, err)
	}
}

// status: the cluster's policy first, then every host's as resolved — its
// own row, or the cluster's marked inherited — including a host named
// "cluster", which has a row of its own (B1 review m-1).
//
// Mutations: resolve a host from the cluster row only — h2's own off is
// lost: red; key host "cluster" as the cluster — red.
func TestGetFirewallSynflood_PerHost(t *testing.T) {
	s := synfloodServer(t, true, "h2", "cluster", "h1")
	op := userCtx("olga", "operator")
	for _, req := range []*pb.SetFirewallSynfloodRequest{
		{Mode: "on", Rate: 300, Burst: 1500}, {Scope: "h2", Mode: "off"}, {Scope: "cluster", Mode: "on", Rate: 7, Burst: 8},
	} {
		if _, err := s.SetFirewallSynflood(op, req); err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
	}
	if _, err := s.GetFirewallSynflood(context.Background(), &pb.GetFirewallSynfloodRequest{}); status.Code(err) != codes.Unauthenticated && status.Code(err) != codes.PermissionDenied {
		t.Errorf("no caller: %v, want refused", err)
	}
	r, err := s.GetFirewallSynflood(viewerCtx(), &pb.GetFirewallSynfloodRequest{})
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		scope, mode string
		rate, burst uint32
		inherited   bool
		setBy       string
	}
	var got []row
	for _, p := range r.GetPolicies() {
		got = append(got, row{p.GetScope(), p.GetMode(), p.GetRate(), p.GetBurst(), p.GetInherited(), p.GetSetBy()})
	}
	want := []row{
		{"cluster", "on", 300, 1500, false, "olga"},
		{"cluster", "on", 7, 8, false, "olga"},
		{"h1", "on", 300, 1500, true, ""},
		{"h2", "off", 0, 0, false, "olga"},
	}
	if len(got) != len(want) {
		t.Fatalf("policies = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("policy %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}
