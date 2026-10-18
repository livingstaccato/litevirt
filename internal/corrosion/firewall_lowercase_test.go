package corrosion

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// Every rule writer stores proto, port and action lower case (spec §0.4,
// review I-1): nft resolves a service name only in lower case, so a stored
// `SSH` would stop every host's firewall from applying.
//
// Mutation: a writer stores the fields as sent — its row keeps `SSH`, red.
func TestFirewallWriters_StoreLowercase(t *testing.T) {
	ctx := context.Background()
	c := ipv6FWDB(t)
	none := capabilities.FeatureGrant{}
	if err := InsertClusterFirewallRuleWithGrant(ctx, c, none, none, none, FirewallRule{ID: "c", Direction: "ingress", Proto: "TCP", PortRange: "SSH", Action: "DROP"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertHostFirewallRuleWithGrant(ctx, c, none, none, none, FirewallRule{ID: "h", HostName: "h", Direction: "ingress", Proto: "UDP", PortRange: "{ 53, DOMAIN }", Action: "Accept"}); err != nil {
		t.Fatal(err)
	}
	if err := InsertSGRuleWithGrant(ctx, c, none, none, none, SGRule{ID: "s", SGID: "sg", Direction: "ingress", Proto: "Tcp", PortRange: "HTTP - HTTPS", Action: "REJECT"}); err != nil {
		t.Fatal(err)
	}
	cr, _ := ListClusterFirewallRules(ctx, c)
	hr, _ := ListHostFirewallRules(ctx, c, "")
	sr, _ := ListSGRules(ctx, c, "sg")
	if len(cr) != 1 || cr[0].Proto != "tcp" || cr[0].PortRange != "ssh" || cr[0].Action != "drop" {
		t.Errorf("cluster rule stored as %+v", cr)
	}
	if len(hr) != 1 || hr[0].Proto != "udp" || hr[0].PortRange != "{ 53, domain }" || hr[0].Action != "accept" {
		t.Errorf("host rule stored as %+v", hr)
	}
	if len(sr) != 1 || sr[0].Proto != "tcp" || sr[0].PortRange != "http - https" || sr[0].Action != "reject" {
		t.Errorf("sg rule stored as %+v", sr)
	}
}
