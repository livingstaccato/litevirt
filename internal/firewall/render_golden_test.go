package firewall

import (
	"testing"

	"github.com/litevirt/litevirt/internal/testkit/golden"
)

// Golden-file coverage for the deterministic firewall renderer. Each
// case below pins one rendering surface (cluster tier, host tier, NIC
// dispatch, IPset expansion, default-deny). Update with `go test
// ./internal/firewall/ -run TestRenderGolden -update`.
func TestRenderGolden(t *testing.T) {
	cases := []struct {
		name string
		path string
		plan Plan
	}{
		{
			name: "empty",
			path: "testdata/render_empty.golden",
			plan: Plan{},
		},
		{
			name: "default_deny_no_rules",
			path: "testdata/render_default_deny.golden",
			plan: Plan{DefaultDeny: true},
		},
		{
			name: "cluster_and_host_tier",
			path: "testdata/render_cluster_host.golden",
			plan: Plan{
				DefaultDeny: true,
				ClusterRules: []Rule{
					{Direction: Egress, Proto: "all", CIDR: "10.0.0.0/8", Action: Drop, Comment: "no rfc1918 egress"},
				},
				HostRules: []Rule{
					{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "192.0.2.0/24", Action: Accept, Comment: "ssh from jump"},
				},
			},
		},
		{
			name: "ipsets_and_nic_binding",
			path: "testdata/render_ipsets_nic.golden",
			plan: Plan{
				DefaultDeny: true,
				IPSets: []IPSet{
					{Name: "trusted", CIDRs: []string{"10.0.0.0/24", "10.0.1.0/24"}},
				},
				SecurityGroups: []SecurityGroup{
					{Name: "web", Rules: []Rule{
						{Direction: Ingress, Proto: "tcp", PortRange: "80", CIDR: "@trusted", Action: Accept},
						{Direction: Ingress, Proto: "tcp", PortRange: "443", CIDR: "@trusted", Action: Accept},
					}},
				},
				NICs: []NICBinding{
					{NICDev: "tap-vm1-0", VMName: "vm1", SecurityGroups: []string{"web"}},
				},
			},
		},
		{
			name: "nat_and_isolation",
			path: "testdata/render_nat_isolation.golden",
			plan: Plan{
				NAT: []NATRule{
					// out of order to prove deterministic sort + SNAT-before-masquerade.
					{Subnet: "10.0.2.0/24", Bridge: "br-mgd-b"},
					{Subnet: "10.0.1.0/24", Bridge: "br-mgd-a"},
					{Subnet: "10.100.0.0/24", OutIface: "eth0", SNATTo: "203.0.113.5"},
				},
				HostIsolation: []IsolationChain{
					{Bridge: "br-iso-z"},
					{Bridge: "br-iso-a", Exceptions: []IsolationException{
						{VIP: "10.100.0.50", Ports: []int{80, 443}},
					}},
				},
			},
		},
		{
			// Firewall logging (spec §3.4): per-NIC and routed log lines,
			// the default verdict, an IPv6 split and a reject.
			name: "log_enforce",
			path: "testdata/render_log_enforce.golden",
			plan: goldenLogPlan(NICModeEnforce),
		},
		{
			name: "log_observe",
			path: "testdata/render_log_observe.golden",
			plan: goldenLogPlan(NICModeObserve),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Render(tc.plan)
			if err != nil {
				t.Fatalf("Render: %v", err)
			}
			golden.Assert(t, tc.path, got)
			assertEveryLogHasGroup(t, got)
			assertLimitsDeclared(t, got)
		})
	}
}

// goldenLogPlan logs rules in every tier and the default verdict.
func goldenLogPlan(mode string) Plan {
	return Plan{
		DefaultDeny: true,
		NICMode:     mode,
		LogPolicy:   LogPolicy{Available: true, Group: 27, Default: true, Rate: 20, Burst: 40},
		IPSets: []IPSet{
			{Name: "trusted", CIDRs: []string{"10.0.0.0/24", "fd00::/64"}},
		},
		ClusterRules: []Rule{
			{ID: "c0ffee", Direction: Ingress, Proto: "tcp", PortRange: "25", Action: Reject, Log: true, Comment: "no smtp"},
			{ID: "c2", Direction: Egress, Proto: "all", CIDR: "10.9.0.0/16", Action: Drop},
		},
		HostRules: []Rule{
			{ID: "h1", Direction: Ingress, Proto: "udp", PortRange: "161", CIDR: "@trusted", Action: Accept, Log: true},
		},
		SecurityGroups: []SecurityGroup{
			{Name: "web", Rules: []Rule{
				{ID: "s1", Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "@trusted", Action: Drop, Log: true},
				{ID: "s2", Direction: Ingress, Proto: "tcp", PortRange: "443", Action: Accept},
				{ID: "Not An Id", Direction: Egress, Proto: "udp", PortRange: "53", Action: Accept, Log: true},
			}},
		},
		NICs: []NICBinding{
			{NICDev: "tap-vm1-0", VMName: "vm1", SecurityGroups: []string{"web"}},
			{NICDev: "veth.c1", VMName: "c1", ExtraRules: []Rule{
				{ID: "n1", Direction: Ingress, Proto: "icmp", Action: Drop, Log: true},
			}},
		},
	}
}
