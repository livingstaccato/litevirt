package firewall

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// C6 (spec §3.4): the logging probe checks, with nft -c, a bridge table
// holding the renderer's own forms: a named limit declared as the renderer
// declares one and a log line as the renderer writes it, to the configured
// group. A refusal is returned.
//
// Mutation: probe a plain `log` with no group — the form differs from the
// renderer's, red.
func TestProbeLogging_UsesTheRenderersForms(t *testing.T) {
	prev := probeRunner
	t.Cleanup(func() { probeRunner = prev })
	var stdin string
	refuse := false
	probeRunner = func(_ context.Context, in string, args ...string) (string, error) {
		stdin = in
		if refuse {
			return "Error: Could not process rule: No such file or directory", errors.New("exit status 1")
		}
		return "", nil
	}
	if err := ProbeLogging(context.Background(), 31); err != nil {
		t.Fatal(err)
	}
	var lim strings.Builder
	renderLogLimit(&lim, "lv_lg_probe", LogPolicy{})
	for _, want := range []string{strings.TrimSpace(lim.String()), logStmt(LogPolicy{Group: 31}, "lv_lg_probe", logPrefix("lvprobe", "in", "default", "drop")), "table bridge "} {
		if !strings.Contains(stdin, want) {
			t.Errorf("probe input lacks %q:\n%s", want, stdin)
		}
	}
	refuse = true
	if err := ProbeLogging(context.Background(), 31); err == nil {
		t.Error("a refused probe returned nil")
	}
}

// C6: the loader renders log lines only where logging is available here
// (the probe passed and the listener's group is set); otherwise nothing is
// logged, whatever the rules and the policy say. Available, the plan carries
// the configured group and the host's resolved policy; an unreadable policy
// row is reported and reads as off at the default budget.
//
// Mutations: render the lines anyway — Available with the probe refused, red;
// skip the policy — Default stays off, red; drop the report — red.
func TestLoader_LoggingOnlyWhereAvailable(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetFirewallLogPolicy(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureFirewallLog), "",
		corrosion.FirewallLogPolicy{Default: corrosion.LogPolicyOn, Rate: 7, Burst: 20}, "a"); err != nil {
		t.Fatal(err)
	}
	rawRow(t, db, `INSERT INTO cluster_firewall_rules
		(id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('c-log', 'ingress', 'tcp', '22', '10.0.0.0/8', 'drop+log', 100, '', '', 't', 1)`)
	load := func(avail bool) Plan {
		t.Helper()
		p, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
			Logging: func() (bool, uint16) { return avail, 31 },
		})(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := load(false)
	if p.LogPolicy.Available {
		t.Errorf("unavailable: LogPolicy = %+v", p.LogPolicy)
	}
	out, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, " log ") || strings.Contains(out, "limit name") {
		t.Errorf("unavailable host rendered a log line:\n%s", out)
	}
	p = load(true)
	if lp := p.LogPolicy; !lp.Available || lp.Group != 31 || !lp.Default || lp.Rate != 7 || lp.Burst != 20 {
		t.Errorf("available: LogPolicy = %+v, want group 31, default on at 7/20", lp)
	}
	if out, _ := Render(p); !strings.Contains(out, "log group 31") {
		t.Errorf("available host rendered no log line:\n%s", out)
	}
	if len(p.UnreadablePolicies) != 0 {
		t.Errorf("unreadable = %v, want none", p.UnreadablePolicies)
	}
	rawRow(t, db, `UPDATE cluster_policies SET value = '{' WHERE key = 'firewall_log'`)
	p = load(true)
	if lp := p.LogPolicy; !lp.Available || lp.Default || lp.Rate != DefaultLogRate {
		t.Errorf("unreadable: LogPolicy = %+v, want off at the default budget", lp)
	}
	if len(p.UnreadablePolicies) != 1 || !strings.Contains(p.UnreadablePolicies[0], "firewall_log") {
		t.Errorf("unreadable = %v, want the firewall_log key named", p.UnreadablePolicies)
	}
}
