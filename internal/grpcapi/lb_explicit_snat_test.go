package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

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
	return resp.Snat
}

// TestExplicitLB_SNATOnlyWhenAsked: an LB made with `lv lb create` on a
// host-isolated network does no outbound SNAT unless --snat asks for it, at
// create, at every re-apply, and as inspect reports it; `lv lb update --snat`
// turns it on and `--snat=false` off again, and a peer told nothing (an
// earlier build's ApplyLB) follows the recorded setting.
//
// Mutations (each red): the create's local intent ignores the setting (SNAT
// always); reapplyExplicitLB SNATs regardless; lbSNAT ignores the record;
// the update ignores req.Snat; ApplyLB with no snat field SNATs an explicit LB.
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
	if !inspectSNAT(t, s, "legacy") {
		t.Error("no record: inspect says no SNAT")
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
// (failover_scope_v1 not latched), a create without --snat still succeeds,
// SNATting as an earlier build's would, and says so in an lb.snat_unrecorded
// event; an update that sets snat is refused. A stack LB's snat is its
// compose file's, so an update setting it is refused.
//
// Mutation: drop the event — red.
func TestExplicitLB_SettingNotRecordable(t *testing.T) {
	s := explicitSNATServer(t, false)
	ch, cancel := s.events.Subscribe()
	defer cancel()
	createExplicitLB(t, s, "early", "10.202.0.253/24", false)
	if _, snat := lbIntent(t, s, "early"); !snat {
		t.Error("an unrecorded create does not SNAT as before")
	}
	deadline := time.After(2 * time.Second)
	for seen := false; !seen; {
		select {
		case e := <-ch:
			seen = e.Action == "lb.snat_unrecorded" && strings.Contains(e.Detail, `"early"`)
		case <-deadline:
			t.Fatal("no lb.snat_unrecorded event")
		}
	}
	_, err := s.UpdateLoadBalancer(adminCtx(), &pb.UpdateLBRequest{Name: "early", Snat: proto.Bool(false)})
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
