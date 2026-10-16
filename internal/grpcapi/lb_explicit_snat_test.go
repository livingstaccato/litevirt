package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// explicitSNATServer is a server with a host-isolated network whose subnet
// holds the test VIPs, and cluster_policies writable when gate is true.
func explicitSNATServer(t *testing.T, gate bool) *Server {
	t.Helper()
	s := testServer(t)
	s.SetBridgeExists(func(string) bool { return true })
	s.lbApplyOverride = func(context.Context, lb.Config) error { return nil }
	s.db.SetClusterPolicyGate(func() bool { return gate })
	putNetwork(t, s, "hinet", "bridge", compose.NetworkDef{Interface: "hinet", Subnet: "10.202.0.0/24", HostIsolation: true})
	return s
}

// lbIntent is the LB's firewall intent on this host: whether it is recorded,
// and whether it SNATs.
func lbIntent(t *testing.T, s *Server, name string) (found, snat bool) {
	t.Helper()
	intents, err := corrosion.ListHostFWIntent(context.Background(), s.db, s.hostName)
	if err != nil {
		t.Fatal(err)
	}
	for _, in := range intents {
		if in.ScopeKey == "lb:"+name {
			return true, in.SNATVIP != ""
		}
	}
	return false, false
}

func createExplicitLB(t *testing.T, s *Server, name, vip string, snat bool) {
	t.Helper()
	if _, err := s.CreateLoadBalancer(adminCtx(), &pb.CreateLBRequest{
		Name: name, Vip: vip, Hosts: []string{s.hostName}, Snat: snat,
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.202.0.10"}},
	}); err != nil {
		t.Fatalf("CreateLoadBalancer %s: %v", name, err)
	}
}

func lbConfig(t *testing.T, s *Server, name string) corrosion.LBConfigRecord {
	t.Helper()
	cfgs, err := corrosion.ListLBConfigs(context.Background(), s.db)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cfgs {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("no lb_configs row %s", name)
	return corrosion.LBConfigRecord{}
}

func inspectSNAT(t *testing.T, s *Server, name string) bool {
	t.Helper()
	resp, err := s.InspectLoadBalancer(adminCtx(), &pb.InspectLBRequest{Name: name})
	if err != nil {
		t.Fatalf("InspectLoadBalancer %s: %v", name, err)
	}
	return resp.GetSnat()
}

func listSNAT(t *testing.T, s *Server, name string) bool {
	t.Helper()
	resp, err := s.ListLoadBalancers(adminCtx(), nil)
	if err != nil {
		t.Fatalf("ListLoadBalancers: %v", err)
	}
	for _, l := range resp.Lbs {
		if l.Name == name {
			return l.GetSnat()
		}
	}
	t.Fatalf("ListLoadBalancers: no %s", name)
	return false
}

// TestExplicitLB_SNATOnlyWhenAsked: an LB made with `lv lb create` on a
// host-isolated network does no outbound SNAT unless --snat asks for it, at
// create, at every re-apply, and as inspect reports it; `lv lb update --snat`
// turns it on and `--snat=false` off again, and a peer told nothing (an
// earlier build's ApplyLB) follows the recorded setting.
//
// Mutations (each red): the create's local intent ignores the setting (SNAT
// always); reapplyExplicitLB SNATs regardless; lbSNAT ignores the record;
// the update ignores req.Snat; ApplyLB with no snat field SNATs an explicit LB;
// ListLoadBalancers leaves snat false.
func TestExplicitLB_SNATOnlyWhenAsked(t *testing.T) {
	s := explicitSNATServer(t, true)
	ctx := context.Background()

	createExplicitLB(t, s, "plain", "10.202.0.250/24", false)
	createExplicitLB(t, s, "natted", "10.202.0.251/24", true)
	for name, want := range map[string]bool{"plain": false, "natted": true} {
		if found, snat := lbIntent(t, s, name); !found || snat != want {
			t.Errorf("%s after create: intent %v, SNAT %v; want SNAT %v", name, found, snat, want)
		}
		if got := inspectSNAT(t, s, name); got != want {
			t.Errorf("%s: inspect SNAT %v, want %v", name, got, want)
		}
		if got := listSNAT(t, s, name); got != want {
			t.Errorf("%s: list SNAT %v, want %v", name, got, want)
		}
		s.reapplyExplicitLB(ctx, lbConfig(t, s, name))
		if found, snat := lbIntent(t, s, name); !found || snat != want {
			t.Errorf("%s after re-apply: intent %v, SNAT %v; want SNAT %v", name, found, snat, want)
		}
	}

	if _, err := s.UpdateLoadBalancer(adminCtx(), &pb.UpdateLBRequest{Name: "plain", Snat: proto.Bool(true)}); err != nil {
		t.Fatalf("update --snat: %v", err)
	}
	if _, snat := lbIntent(t, s, "plain"); !snat || !inspectSNAT(t, s, "plain") {
		t.Error("update --snat: not SNATting")
	}
	if _, err := s.UpdateLoadBalancer(adminCtx(), &pb.UpdateLBRequest{Name: "plain", Snat: proto.Bool(false)}); err != nil {
		t.Fatalf("update --snat=false: %v", err)
	}
	if _, snat := lbIntent(t, s, "plain"); snat || inspectSNAT(t, s, "plain") {
		t.Error("update --snat=false: still SNATting")
	}
	// An unrelated edit keeps the setting.
	if _, err := s.UpdateLoadBalancer(adminCtx(), &pb.UpdateLBRequest{Name: "plain", Algorithm: "leastconn"}); err != nil {
		t.Fatalf("update --algorithm: %v", err)
	}
	if _, snat := lbIntent(t, s, "plain"); snat {
		t.Error("an unrelated update turned SNAT on")
	}

	// A peer's ApplyLB from an earlier build carries no snat field.
	if _, err := s.ApplyLB(peerCtxFor(t, s, "node-0"), &pb.ApplyLBRequest{
		LbName: "plain", Vip: "10.202.0.250/24", Hosts: []string{s.hostName},
		Ports: []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
	}); err != nil {
		t.Fatalf("ApplyLB: %v", err)
	}
	if found, snat := lbIntent(t, s, "plain"); !found || snat {
		t.Errorf("ApplyLB with no snat field: intent %v, SNAT %v; want no SNAT", found, snat)
	}
}

// TestExplicitLB_StoredBeforeTheSettingKeepsSNAT: an explicit LB stored
// before the setting existed has no record and keeps SNATting, and so does
// one whose record belongs to an earlier incarnation of its name.
//
// Mutation: read a missing record as "no SNAT" — red.
func TestExplicitLB_StoredBeforeTheSettingKeepsSNAT(t *testing.T) {
	s := explicitSNATServer(t, true)
	ctx := context.Background()
	if err := corrosion.PersistLBFull(ctx, s.db, corrosion.LBConfigRecord{
		Name: "legacy", VIP: "10.202.0.252/24", Algorithm: "roundrobin", Enabled: true, Generation: "g-new",
		Hosts: `["test-host"]`, Ports: `[{"listen":80,"target":8080,"protocol":"tcp"}]`,
	}, nil); err != nil {
		t.Fatal(err)
	}
	s.reapplyExplicitLB(ctx, lbConfig(t, s, "legacy"))
	if found, snat := lbIntent(t, s, "legacy"); !found || !snat {
		t.Errorf("no record: intent %v, SNAT %v; want SNAT", found, snat)
	}
	if !inspectSNAT(t, s, "legacy") || !listSNAT(t, s, "legacy") {
		t.Error("no record: inspect or list says no SNAT")
	}

	// A record of an earlier incarnation (another generation) is not this
	// LB's setting.
	if err := s.db.Execute(ctx, `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES (?, ?, 'x', ?)`,
		corrosion.LBSNATKeyPrefix+"legacy", `{"snat":false,"generation":"g-old"}`, s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	if !inspectSNAT(t, s, "legacy") {
		t.Error("an earlier incarnation's record turned SNAT off")
	}
}

// TestExplicitLB_SettingNotRecordable: until cluster_policies is writable
// (failover_scope_v1 not latched), a create without --snat is refused, since
// an LB with no recorded setting SNATs, and the refusal names the remedies;
// a create with --snat succeeds and SNATs; an update that sets snat is
// refused. A stack LB's snat is its compose file's, so an update setting it
// is refused.
//
// Mutation: create without --snat as before the refusal — red.
func TestExplicitLB_SettingNotRecordable(t *testing.T) {
	s := explicitSNATServer(t, false)
	_, err := s.CreateLoadBalancer(adminCtx(), &pb.CreateLBRequest{
		Name: "early", Vip: "10.202.0.253/24", Hosts: []string{s.hostName},
		Ports:    []*pb.LBPort{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		Backends: []*pb.LBBackendAddress{{Name: "b1", Address: "10.202.0.10"}},
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("create without --snat with the gate closed: %v, want FailedPrecondition", err)
	}
	for _, remedy := range []string{"--snat", "lv cluster upgrade-status", "failover_scope_v1"} {
		if !strings.Contains(status.Convert(err).Message(), remedy) {
			t.Errorf("refusal %q does not name %q", status.Convert(err).Message(), remedy)
		}
	}
	if cfgs, lerr := corrosion.ListLBConfigs(context.Background(), s.db); lerr != nil || len(cfgs) != 0 {
		t.Errorf("a refused create left lb_configs %+v (%v)", cfgs, lerr)
	}

	createExplicitLB(t, s, "early", "10.202.0.253/24", true)
	if _, snat := lbIntent(t, s, "early"); !snat || !inspectSNAT(t, s, "early") {
		t.Error("create --snat with the gate closed: not SNATting")
	}
	_, err = s.UpdateLoadBalancer(adminCtx(), &pb.UpdateLBRequest{Name: "early", Snat: proto.Bool(false)})
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("update --snat=false with the gate closed: %v, want FailedPrecondition", err)
	}

	s.db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.UpsertLBConfig(context.Background(), s.db, corrosion.LBConfigRecord{
		Name: "shop-lb", StackName: "shop", VIP: "10.202.0.254/24", Enabled: true, Hosts: `["test-host"]`,
	}); err != nil {
		t.Fatal(err)
	}
	_, err = s.UpdateLoadBalancer(adminCtx(), &pb.UpdateLBRequest{Name: "shop-lb", Snat: proto.Bool(true)})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("update --snat on a stack LB: %v, want InvalidArgument", err)
	}
}

// TestListLoadBalancers_OneFailingSNATLookupDoesNotFailTheList: snat is a
// display-only field of the list, so an LB whose lookup errors is listed with
// snat unknown (unset, not false) and every other LB is listed normally.
//
// Mutation (red): ListLoadBalancers returns the lookup's error again.
func TestListLoadBalancers_OneFailingSNATLookupDoesNotFailTheList(t *testing.T) {
	s := explicitSNATServer(t, true)
	createExplicitLB(t, s, "good", "10.202.0.250/24", true)
	createExplicitLB(t, s, "broken", "10.202.0.251/24", true)
	s.lbListSNATOverride = func(ctx context.Context, name, stack, gen string) (bool, error) {
		if name == "broken" {
			return false, errors.New("read cluster_policies: database is locked")
		}
		return s.lbSNAT(ctx, name, stack, gen)
	}
	resp, err := s.ListLoadBalancers(adminCtx(), nil)
	if err != nil {
		t.Fatalf("ListLoadBalancers failed for one LB's snat lookup: %v", err)
	}
	got := map[string]*bool{}
	for _, l := range resp.Lbs {
		got[l.Name] = l.Snat
	}
	if len(got) != 2 {
		t.Fatalf("listed %v, want both LBs", got)
	}
	if got["good"] == nil || !*got["good"] {
		t.Error("good: snat lost because another LB's lookup failed")
	}
	if got["broken"] != nil {
		t.Errorf("broken: snat reported as %v although its lookup failed; want unknown (unset)", *got["broken"])
	}
}
