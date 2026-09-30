package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// fwAuditRow is the newest audit_log row for one action.
type fwAuditRow struct {
	found                        bool
	user, target, detail, result string
}

func lastAuditRow(t *testing.T, s *Server, action string) fwAuditRow {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT username, target, detail, result FROM audit_log
		 WHERE action = ? ORDER BY seq DESC, timestamp DESC LIMIT 1`, action)
	if err != nil {
		t.Fatalf("query audit_log: %v", err)
	}
	if len(rows) == 0 {
		return fwAuditRow{}
	}
	r := rows[0]
	return fwAuditRow{found: true, user: r.String("username"), target: r.String("target"),
		detail: r.String("detail"), result: r.String("result")}
}

func wantAudit(t *testing.T, s *Server, action, user, target, detail string) {
	t.Helper()
	got := lastAuditRow(t, s, action)
	if !got.found {
		t.Fatalf("%s: no audit row; the firewall changed and the signed chain says nothing did", action)
	}
	if got.user != user || got.target != target || got.detail != detail || got.result != "ok" {
		t.Errorf("%s audit row = user=%q target=%q detail=%q result=%q\n"+
			"                 want user=%q target=%q detail=%q result=\"ok\"",
			action, got.user, got.target, got.detail, got.result, user, target, detail)
	}
}

// Issue colonelpanik/litevirt#182, the audit half. Every firewall-policy
// mutation must leave a row that says who made it, what it touched, and what
// the policy was before and after. A row that records only "firewall rule
// removed, id=abc" proves the change happened and destroys the evidence of
// what it was: the rule is tombstoned, so the audit log is the only place left
// that can say which port the removal opened.
//
// These call the gRPC handlers the CLI, the REST API and the web UI all reach,
// so the one assertion covers every entry point that goes through the daemon.
func TestFirewallMutations_AuditWhoWhatBeforeAfter(t *testing.T) {
	s := testServer(t)
	ctx := adminCtxWithEngine(t, s)

	t.Run("default policy", func(t *testing.T) {
		if _, err := s.SetFirewallDefault(ctx, &pb.SetFirewallDefaultRequest{DefaultDeny: true}); err != nil {
			t.Fatalf("SetFirewallDefault(deny): %v", err)
		}
		wantAudit(t, s, "firewall.default-deny", "alice", "cluster", "before=unset after=deny")

		if _, err := s.SetFirewallDefault(ctx, &pb.SetFirewallDefaultRequest{Scope: "cluster"}); err != nil {
			t.Fatalf("SetFirewallDefault(accept): %v", err)
		}
		wantAudit(t, s, "firewall.default-deny", "alice", "cluster", "before=deny after=accept")
	})

	t.Run("cluster rule", func(t *testing.T) {
		// Proto, action and priority are left empty: the "after" must be the
		// rule as stored and enforced, not the request as typed.
		created, err := s.CreateClusterFirewallRule(ctx, &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{
			Direction: "ingress", Port: "22", Cidr: "10.0.0.0/8", Comment: "ssh from lan",
		}})
		if err != nil {
			t.Fatalf("CreateClusterFirewallRule: %v", err)
		}
		rule := `{ingress all port=22 cidr=10.0.0.0/8 accept priority=100 comment="ssh from lan"}`
		wantAudit(t, s, "firewall.cluster-rule.add", "alice", created.Id, "before=none after="+rule)

		if _, err := s.DeleteClusterFirewallRule(ctx, &pb.DeleteClusterFirewallRuleRequest{Id: created.Id}); err != nil {
			t.Fatalf("DeleteClusterFirewallRule: %v", err)
		}
		wantAudit(t, s, "firewall.cluster-rule.rm", "alice", created.Id, "before="+rule+" after=none")
	})

	t.Run("host rule", func(t *testing.T) {
		created, err := s.CreateHostFirewallRule(ctx, &pb.CreateHostFirewallRuleRequest{Rule: &pb.FirewallRule{
			HostName: "node-2", Direction: "egress", Proto: "udp", Port: "53", Action: "drop", Priority: 10,
		}})
		if err != nil {
			t.Fatalf("CreateHostFirewallRule: %v", err)
		}
		rule := `{host=node-2 egress udp port=53 cidr=any drop priority=10}`
		wantAudit(t, s, "firewall.host-rule.add", "alice", created.Id, "before=none after="+rule)

		if _, err := s.DeleteHostFirewallRule(ctx, &pb.DeleteHostFirewallRuleRequest{Id: created.Id}); err != nil {
			t.Fatalf("DeleteHostFirewallRule: %v", err)
		}
		wantAudit(t, s, "firewall.host-rule.rm", "alice", created.Id, "before="+rule+" after=none")
	})

	t.Run("ip set", func(t *testing.T) {
		created, err := s.CreateIpSet(ctx, &pb.CreateIpSetRequest{
			Name: "blocklist", Cidrs: []string{"203.0.113.0/24", "198.51.100.7"},
		})
		if err != nil {
			t.Fatalf("CreateIpSet: %v", err)
		}
		set := `{name=blocklist cidrs=[203.0.113.0/24,198.51.100.7]}`
		wantAudit(t, s, "firewall.ipset.add", "alice", "blocklist", "before=none after="+set)

		if _, err := s.DeleteIpSet(ctx, &pb.DeleteIpSetRequest{Id: created.Id}); err != nil {
			t.Fatalf("DeleteIpSet: %v", err)
		}
		wantAudit(t, s, "firewall.ipset.rm", "alice", created.Id, "before="+set+" after=none")
	})

	t.Run("delete of an id that does not exist", func(t *testing.T) {
		// "none" is a claim that nothing was there. It must come from a read
		// that succeeded, and it must not be dressed up as a removed rule.
		if _, err := s.DeleteClusterFirewallRule(ctx, &pb.DeleteClusterFirewallRuleRequest{Id: "no-such-rule"}); err != nil {
			t.Fatalf("DeleteClusterFirewallRule: %v", err)
		}
		wantAudit(t, s, "firewall.cluster-rule.rm", "alice", "no-such-rule", "before=none after=none")
	})

	t.Run("security-group binding", func(t *testing.T) {
		// The incident-response lever: moving a VM's NIC into, or out of, an
		// isolation group. It wrote the binding and logged to slog only.
		if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
			Name: "web-1", HostName: s.hostName, Spec: "{}", State: "running", Project: "_default",
		}, []corrosion.InterfaceRecord{{
			VMName: "web-1", NetworkName: "lan", MAC: "52:54:00:00:00:01", SecurityGroups: []string{"isolate"},
		}}, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		if _, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
			VmName: "web-1", NetworkName: "lan", SecurityGroups: []string{"web", "ssh"},
		}); err != nil {
			t.Fatalf("BindSecurityGroups: %v", err)
		}
		wantAudit(t, s, "sg.bind", "alice", "web-1", "network=lan before=[isolate] after=[web,ssh]")
	})
}
