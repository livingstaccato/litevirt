package firewall

import (
	"strings"
	"testing"
)

// A tcp/udp port is rendered lower case (review I-1): nft resolves a service
// name only in lower case, so a row an older peer stored as `SSH` loads as
// `ssh` instead of making nft refuse every host's table. Numeric and already
// lower-case ports render as before (the compat goldens).
//
// Mutation: render the port as stored — `dport SSH`, red.
func TestRender_PortLowercased(t *testing.T) {
	out, err := Render(Plan{ClusterRules: []Rule{
		{Direction: Ingress, Proto: "TCP", PortRange: "SSH", Action: Accept},
		{Direction: Ingress, Proto: "udp", PortRange: "{ 53, DOMAIN }", Action: Accept},
	}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"tcp dport ssh accept", "udp dport { 53, domain } accept"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered script lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "SSH") || strings.Contains(out, "DOMAIN") {
		t.Errorf("rendered script keeps an upper-case service name:\n%s", out)
	}
}
