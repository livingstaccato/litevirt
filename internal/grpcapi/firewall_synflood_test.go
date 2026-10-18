package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc"
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

// synfloodPeer answers the local_only leg of the fan-out with its own drops,
// and refuses a call without local_only (which would fan out again).
type synfloodPeer struct {
	pb.LiteVirtClient
	v4, v6 uint64
}

func (p synfloodPeer) GetFirewallSynflood(_ context.Context, in *pb.GetFirewallSynfloodRequest, _ ...grpc.CallOption) (*pb.GetFirewallSynfloodResponse, error) {
	if !in.GetLocalOnly() {
		return nil, status.Error(codes.FailedPrecondition, "a fan-out leg without local_only")
	}
	return &pb.GetFirewallSynfloodResponse{Policies: []*pb.FirewallSynfloodPolicy{{DropsV4: p.v4, DropsV6: p.v6}}}, nil
}

// status asks every active host for its own lv-sf 4 and lv-sf 6 counters
// (local_only=true) and reads this host's from its kernel. A host that cannot
// be asked, or is not active, shows why in error, never a zero; this host's
// counters failing to read shows the same way.
//
// Mutations: fan out without local_only — h1 shows an error: red; report an
// unreachable host as zero drops with no error — red; drop this host's read
// error — red.
func TestGetFirewallSynflood_DropsPerHost(t *testing.T) {
	ctx := context.Background()
	s := synfloodServer(t, true, "test-host", "h1", "h2")
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "h3", Address: "10.0.0.3", State: "maintenance"}); err != nil {
		t.Fatal(err)
	}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		if host == "h1" {
			return synfloodPeer{v4: 7, v6: 2}, func() {}, nil
		}
		return nil, nil, errors.New("connection refused")
	}
	s.synFloodDrops = func(context.Context) (uint64, uint64, error) { return 11, 4, nil }
	r, err := s.GetFirewallSynflood(viewerCtx(), &pb.GetFirewallSynfloodRequest{})
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*pb.FirewallSynfloodPolicy{}
	for _, p := range r.GetPolicies()[1:] {
		by[p.GetScope()] = p
	}
	check := func(host string, v4, v6 uint64, errHas string) {
		t.Helper()
		p := by[host]
		if p == nil {
			t.Fatalf("no entry for %s", host)
		}
		if errHas == "" && (p.GetError() != "" || p.GetDropsV4() != v4 || p.GetDropsV6() != v6) {
			t.Errorf("%s: drops %d/%d error %q, want %d/%d", host, p.GetDropsV4(), p.GetDropsV6(), p.GetError(), v4, v6)
		}
		if errHas != "" && !strings.Contains(p.GetError(), errHas) {
			t.Errorf("%s: error %q, want it to say %q", host, p.GetError(), errHas)
		}
	}
	check("test-host", 11, 4, "")
	check("h1", 7, 2, "")
	check("h2", 0, 0, "connection refused")
	check("h3", 0, 0, "maintenance")
	if c := r.GetPolicies()[0]; c.GetError() != "" || c.GetDropsV4() != 0 {
		t.Errorf("the cluster entry carries counters: %+v", c)
	}

	// The fan-out leg: this host's entry alone, with its own counters.
	r, err = s.GetFirewallSynflood(viewerCtx(), &pb.GetFirewallSynfloodRequest{LocalOnly: true})
	if err != nil || len(r.GetPolicies()) != 1 || r.GetPolicies()[0].GetScope() != "test-host" || r.GetPolicies()[0].GetDropsV4() != 11 {
		t.Fatalf("local_only = %+v, %v; want this host's entry with its drops", r, err)
	}
	s.synFloodDrops = func(context.Context) (uint64, uint64, error) { return 0, 0, errors.New("nft: Operation not permitted") }
	r, err = s.GetFirewallSynflood(viewerCtx(), &pb.GetFirewallSynfloodRequest{LocalOnly: true})
	if err != nil || !strings.Contains(r.GetPolicies()[0].GetError(), "Operation not permitted") {
		t.Errorf("unreadable local counters: %+v, %v; want the error", r, err)
	}
}
