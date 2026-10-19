package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/firewall"
)

// TestFleet_FirewallLog_ReleaseSwitchAndRender (C9) runs firewall logging
// through the real release gate. While one host is WAL-quarantined (on the
// previous build) a logged rule and a log policy are refused with the release
// text and no use is recorded anywhere. Once every host runs this build both
// are written, every replica holds the use, and every node's plan, built by
// the production loader, renders the logged rule under the policy.
//
// Mutation: write before the latch (skip the log gate in logRow) — the
// mid-roll rule is stored, red.
func TestFleet_FirewallLog_ReleaseSwitchAndRender(t *testing.T) {
	ctx := context.Background()
	c, _ := latchedFleet(t, 3, 1171)
	a, old := c.Nodes[0], c.Nodes[2]
	cl := c.SelfClient(a)
	rule := &pb.CreateClusterFirewallRuleRequest{Rule: &pb.FirewallRule{
		Direction: "ingress", Proto: "tcp", Port: "22", Cidr: "10.1.0.0/16", Action: "drop", Log: true}}
	policy := &pb.SetFirewallLogPolicyRequest{Mode: "on", Rate: 7, Burst: 20}
	release := "the cluster upgrade must finish first (firewall_log needs " + capabilities.ReleaseToken + ")"

	old.Server.SetWALQuarantined(func() bool { return true }) // the previous build
	if _, err := cl.CreateClusterFirewallRule(ctx, rule); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), release) {
		t.Fatalf("a logged rule mid-roll: %v, want the release refusal", err)
	}
	if _, err := cl.SetFirewallLogPolicy(ctx, policy); status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), release) {
		t.Fatalf("the log policy mid-roll: %v, want the release refusal", err)
	}
	if resp, err := cl.ListClusterFirewallRules(ctx, &pb.ListClusterFirewallRulesRequest{}); err != nil || len(resp.GetRules()) != 0 {
		t.Fatalf("rules after the refusal = %v, %v; want none", resp.GetRules(), err)
	}
	for _, n := range c.Nodes {
		if featureUsedOn(t, n, capabilities.ReleaseToken, "firewall_log") {
			t.Fatalf("%s holds a firewall_log use although every write was refused", n.Name)
		}
	}

	old.Server.SetWALQuarantined(old.DB.WALQuarantined) // every host on this build
	var id string
	eventually(t, 10*time.Second, "a logged rule to be accepted on a uniform fleet", func() bool {
		r, err := cl.CreateClusterFirewallRule(ctx, rule)
		if err != nil {
			return false
		}
		id = r.GetId()
		return true
	})
	if _, err := cl.SetFirewallLogPolicy(ctx, policy); err != nil {
		t.Fatalf("the log policy on a uniform fleet: %v", err)
	}
	for _, n := range c.Nodes {
		if !featureUsedOn(t, n, capabilities.ReleaseToken, "firewall_log") {
			t.Fatalf("%s does not hold the firewall_log use although a logged rule was written", n.Name)
		}
	}
	for _, n := range c.Nodes {
		n := n
		eventually(t, 15*time.Second, n.Name+" to render the logged rule under the policy", func() bool {
			p, err := firewall.CorrosionPlanLoader(n.DB, n.Name, firewall.Plan{}, firewall.LoaderOptions{
				RunningTaps: n.Virt.RunningDomainTaps,
				Logging:     func() (bool, uint16) { return true, 27 },
			})(ctx)
			if err != nil {
				return false
			}
			logged := false
			for _, r := range p.ClusterRules {
				logged = logged || (r.ID == id && r.Log && r.Action == firewall.Drop)
			}
			if !logged || !p.LogPolicy.Default || p.LogPolicy.Rate != 7 {
				return false
			}
			out, err := firewall.Render(p)
			return err == nil && strings.Contains(out, `log group 27 snaplen 96 prefix "lv-log - - `+id+` drop"`)
		})
	}
}
