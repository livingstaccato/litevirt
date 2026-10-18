package firewall

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Round 1 I-1 (privacy, L-1): log lines are rendered only while this host's
// listener holds the NFLOG group. A probe that passed is not enough: another
// process bound to the group would receive every logged packet's headers.
// Each bind transition asks for a pass, so the lines go when the bind is lost
// and come back when it returns.
//
// Mutations: available whenever the probe passed — red (unbound but
// available); no pass on a transition — red.
func TestLogGate_AvailableOnlyWhileBound(t *testing.T) {
	var passes atomic.Int32
	g := NewLogGate(31, nil, func() { passes.Add(1) })
	if ok, grp := g.Logging(); ok || grp != 31 {
		t.Fatalf("before any bind: %v %d, want unavailable", ok, grp)
	}
	g.OnBind(errors.New("operation not permitted"))
	if ok, _ := g.Logging(); ok {
		t.Error("a failed bind made logging available")
	}
	g.OnBind(nil)
	if ok, _ := g.Logging(); !ok {
		t.Error("bound, but logging unavailable")
	}
	g.OnBind(errors.New("socket closed"))
	if ok, _ := g.Logging(); ok {
		t.Error("the bind was lost, but logging is still available")
	}
	if n := passes.Load(); n != 2 {
		t.Errorf("passes asked = %d, want one per change of the bound state (2)", n)
	}
	refused := NewLogGate(31, errors.New("nft refused"), func() {})
	refused.OnBind(nil)
	if ok, _ := refused.Logging(); ok {
		t.Error("a refused probe still made logging available")
	}
}

// Round 1 I-1: with the probe passed and the listener not bound (the group
// held by another process), the loader renders no log line, whatever the
// rules and the policy say.
//
// Mutation: the daemon's old wiring (available when the probe passed) — red.
func TestLoader_NoLogLineWhileListenerUnbound(t *testing.T) {
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
	g := NewLogGate(27, nil, func() {})
	g.OnBind(errors.New("bind group 27: operation not permitted"))
	p, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{Logging: g.Logging})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Render(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "log group") || p.LogPolicy.Available {
		t.Errorf("the group is held by another process but log lines were rendered:\n%s", out)
	}
	g.OnBind(nil)
	p, _ = CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{Logging: g.Logging})(ctx)
	if out, _ := Render(p); !strings.Contains(out, "log group 27") {
		t.Errorf("bound, but no log line rendered:\n%s", out)
	}
}

// Round 1 I-2 (merge seam with Track B): the log block appends to the
// pass's unreadable-policy list, so an entry an earlier block made (the
// SYN-flood policy's) survives, and each names its own effect.
//
// Mutation: assign rather than append — the earlier entry is lost, red.
func TestLoadLogPolicy_AppendsUnreadable(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	rawRow(t, db, `INSERT INTO cluster_policies (key, value, set_by, updated_at) VALUES ('firewall_log', '{', 'a', '1')`)
	syn := "firewall_synflood/host-a holds \"{\": read as on at 200/1000"
	p := Plan{UnreadablePolicies: []string{syn}}
	if err := loadLogPolicy(ctx, db, "host-a", LoaderOptions{Logging: func() (bool, uint16) { return true, 27 }}, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.UnreadablePolicies) != 2 || p.UnreadablePolicies[0] != syn ||
		!strings.Contains(p.UnreadablePolicies[1], "firewall_log") || !strings.Contains(p.UnreadablePolicies[1], "read as logging off at 5/10") {
		t.Errorf("unreadable = %q, want the SYN-flood entry kept and the log entry naming its effect", p.UnreadablePolicies)
	}
}

// Round 2 m-1 (window 1): a daemon that is stopping turns logging off for
// good, whatever the listener reports after, and Stop says whether lines may
// have been rendered (so the stop pass is run only then).
//
// Mutation: Stop leaves the bound flag — still available, red.
func TestLogGate_StopTurnsLoggingOff(t *testing.T) {
	g := NewLogGate(27, nil, func() {})
	if g.Stop() {
		t.Error("Stop on a never-bound gate says lines may be rendered")
	}
	g = NewLogGate(27, nil, func() {})
	g.OnBind(nil)
	if !g.Stop() {
		t.Error("Stop on a bound gate says no line was rendered")
	}
	if ok, _ := g.Logging(); ok {
		t.Error("logging still available after Stop")
	}
	g.OnBind(nil)
	if ok, _ := g.Logging(); ok {
		t.Error("a bind after Stop made logging available again")
	}
}
