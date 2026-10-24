package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestCreateLoadBalancer_PersistsDurableHolder: an explicit LB created with no
// hosts must persist a concrete holder ([self]), not [] — otherwise a later
// update/reapply entering through another node can't tell who serves the VIP.
func TestCreateLoadBalancer_PersistsDurableHolder(t *testing.T) {
	s := testServerR2(t)
	s.db.SetClusterPolicyGate(func() bool { return true }) // failover_scope_v1 latched: the LB's snat is recordable
	ctx := adminCtx()
	s.vipGateFlipped = func() bool { return true }
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil } // no real haproxy
	s.vipHoldersOverride = func(context.Context, string) ([]string, bool) {
		return nil, true // VIP unassigned everywhere
	}

	if _, err := s.CreateLoadBalancer(ctx, &pb.CreateLBRequest{
		Name: "lbNoHosts", Vip: "10.0.100.92/24", Algorithm: "roundrobin",
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.0.0.9"}},
		// Hosts intentionally empty.
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	rows, _ := s.db.Query(ctx, `SELECT hosts FROM lb_configs WHERE name = 'lbNoHosts' AND deleted_at IS NULL`)
	if len(rows) == 0 {
		t.Fatal("LB row not persisted")
	}
	if got := rows[0].String("hosts"); got != `["test-host"]` {
		t.Errorf("explicit LB with no hosts must persist a durable holder [test-host]; hosts = %q", got)
	}
}

// TestLBRunsOnHost_ExplicitNeedsRecordedHolder: an explicit LB (no stack) with no
// recorded holder must NOT be claimed by an arbitrary host — only VM-derived
// membership for a STACK LB may run without an explicit host list.
func TestLBRunsOnHost_ExplicitNeedsRecordedHolder(t *testing.T) {
	s := testServerR2(t)
	ctx := context.Background()

	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: "[]"}) {
		t.Error("explicit LB with empty hosts must not run on an arbitrary host")
	}
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: ""}) {
		t.Error("explicit LB with unset hosts must not run here")
	}
	if !s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: `["test-host"]`}) {
		t.Error("explicit LB whose recorded holder is this host must run here")
	}
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", Hosts: `["other"]`}) {
		t.Error("explicit LB held by another host must not run here")
	}
	// Stack LB, empty hosts, no local VMs → derived membership yields false (not a
	// blanket claim). The StackName != "" branch is what permits VM-derived running.
	if s.lbRunsOnHost(ctx, corrosion.LBConfigRecord{Name: "x", StackName: "s", Hosts: "[]"}) {
		t.Error("stack LB with no local VMs must not run here")
	}
}

// TestLBHostsUnset: a marshaled nil slice is the JSON string "null", NOT "[]" —
// all unowned shapes must be recognized.
func TestLBHostsUnset(t *testing.T) {
	for _, s := range []string{"", "[]", "null"} {
		if !lbHostsUnset(s) {
			t.Errorf("lbHostsUnset(%q) = false; want true (unowned)", s)
		}
	}
	for _, s := range []string{`["h"]`, `["a","b"]`} {
		if lbHostsUnset(s) {
			t.Errorf("lbHostsUnset(%q) = true; want false (has holder)", s)
		}
	}
}

// TestStoredVIP_StrictOnEveryReadPath: a stored VIP is parsed like a new one.
// One ParseVIP refuses ("10.0.0.1/24/extra") is not repaired and applied: the
// update fails closed and the reapply applies nothing.
//
// Mutation: read the stored VIP leniently (address half only) on either path —
// red.
func TestStoredVIP_StrictOnEveryReadPath(t *testing.T) {
	ctx := adminCtx()
	s := testServerR2(t)
	applied := 0
	s.lbApplyOverride = func(context.Context, lb.Config) error { applied++; return nil }
	rec := corrosion.LBConfigRecord{
		Name: "sloppy", VIP: "10.0.0.1/24/extra", Algorithm: "roundrobin",
		Hosts: `["test-host"]`, Ports: `[{"listen":80,"target":8080,"protocol":"tcp"}]`, Enabled: true, Generation: "g1",
	}
	if err := corrosion.UpsertLBConfig(ctx, s.db, rec); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := s.UpdateLoadBalancer(ctx, &pb.UpdateLBRequest{Name: "sloppy", Algorithm: "leastconn"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("update of an LB with an unparseable stored VIP = %v; want FailedPrecondition", err)
	}
	s.reapplyExplicitLB(ctx, rec)
	if applied != 0 {
		t.Errorf("an unparseable stored VIP was applied %d time(s)", applied)
	}
}
