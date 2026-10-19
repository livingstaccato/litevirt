package corrosion

import (
	"context"
	"testing"
)

// C2 (0-F): firewall_log's data is present when this replica holds a live
// rule of any tier whose stored action is in the log form, in any case or
// padding, or a log policy row with a value. A tombstoned rule, an emptied
// policy row or an unrelated key is not data.
//
// Mutations: probe only cluster rules — the host or sg rule is not found,
// red; ignore deleted_at — the tombstoned rule counts, red; skip the policy
// keys — a policy row is not found, red.
func TestFirewallLogDataPresent(t *testing.T) {
	ctx := context.Background()
	fresh := func() *Client {
		c := ipv6FWDB(t)
		openClusterPolicyGate(c)
		return c
	}
	present := func(c *Client) bool {
		t.Helper()
		ok, err := FirewallLogDataPresent(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		return ok
	}
	c := fresh()
	if present(c) {
		t.Fatal("an empty replica has data")
	}
	mustExec(t, c, clusterPolicyUpsertSQL, "firewall_log", "", "a", "t")
	mustExec(t, c, clusterPolicyUpsertSQL, "firewall_log/node-0", "", "a", "t")
	mustExec(t, c, clusterPolicyUpsertSQL, "firewall_logz", "x", "a", "t")
	mustExec(t, c, `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at, deleted_at)
		VALUES ('gone', 'ingress', 'tcp', '', '', 'drop+log', 100, '', '', 't', 't', 't')`)
	mustExec(t, c, `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
		VALUES ('plain', 'ingress', 'tcp', '', '', 'drop', 100, '', '', 't', 't')`)
	if present(c) {
		t.Fatal("emptied rows, other keys, a plain rule or a tombstoned rule counted as data")
	}
	for what, write := range map[string]func(c *Client){
		"cluster policy": func(c *Client) { mustExec(t, c, clusterPolicyUpsertSQL, "firewall_log", `{"default":"on"}`, "a", "t") },
		"host policy":    func(c *Client) { mustExec(t, c, clusterPolicyUpsertSQL, "firewall_log/node-0", `x`, "a", "t") },
		"cluster rule": func(c *Client) {
			mustExec(t, c, `INSERT INTO cluster_firewall_rules (id, direction, proto, port_range, cidr, action, priority, comment, stack_name, created_at, updated_at)
				VALUES ('c', 'ingress', 'tcp', '', '', 'drop+log', 100, '', '', 't', 't')`)
		},
		"host rule, upper case and padded": func(c *Client) {
			mustExec(t, c, `INSERT INTO host_firewall_rules (id, host_name, direction, proto, port_range, cidr, action, priority, comment, created_at, updated_at)
				VALUES ('h', 'node-0', 'ingress', 'tcp', '', '', ' ACCEPT+LOG' || char(10), 100, '', 't', 't')`)
		},
		"sg rule": func(c *Client) {
			mustExec(t, c, `INSERT INTO sg_rules (id, sg_id, direction, proto, port_range, cidr, action, priority, created_at, updated_at)
				VALUES ('s', 'sg', 'ingress', 'tcp', '', '', 'reject+log', 100, 't', 't')`)
		},
	} {
		c := fresh()
		write(c)
		if !present(c) {
			t.Errorf("%s: not found", what)
		}
	}
}

// C2 (m-13): API replies and audit text carry the plain verdict and "log",
// never the stored suffix.
//
// Mutation: SplitLoggedAction returns the stored action — the reply carries
// "drop+log", red.
func TestSplitLoggedAction_AndAuditText(t *testing.T) {
	for stored, want := range map[string]struct {
		verdict string
		log     bool
	}{
		"drop+log": {"drop", true}, "ACCEPT+LOG": {"accept", true}, "drop": {"drop", false}, "": {"", false},
	} {
		v, l := SplitLoggedAction(stored)
		if v != want.verdict || l != want.log {
			t.Errorf("SplitLoggedAction(%q) = %q, %v; want %q, %v", stored, v, l, want.verdict, want.log)
		}
	}
	if got := LoggedAction(""); got != "accept+log" {
		t.Errorf("LoggedAction(\"\") = %q, want accept+log", got)
	}
	if got := LoggedAction("drop"); got != "drop+log" {
		t.Errorf("LoggedAction(drop) = %q", got)
	}
	r := FirewallRule{Direction: "ingress", Proto: "tcp", PortRange: "22", Action: "drop+log", Priority: 100}
	if got, want := r.AuditText(), "{ingress tcp port=22 cidr=any drop log priority=100}"; got != want {
		t.Errorf("audit text = %q, want %q", got, want)
	}
	sr := SGRule{SGID: "sg", Direction: "ingress", Proto: "tcp", Action: "drop", Priority: 100}
	if got, want := sr.AuditText(), "{sg=sg ingress tcp port=any cidr=any drop priority=100}"; got != want {
		t.Errorf("unlogged audit text = %q, want %q", got, want)
	}
}
