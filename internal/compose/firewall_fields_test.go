package compose

import (
	"strings"
	"testing"
)

// TestValidate_FirewallFields (finding F-1): a compose file whose firewall
// rule or ip set carries text that would add nft syntax to every host's
// ruleset is refused, naming the field, the value and where it is.
func TestValidate_FirewallFields(t *testing.T) {
	bad := map[string]string{
		"sg port": `
security-groups:
  web:
    rules:
      - { direction: ingress, proto: tcp, port: "22; flush ruleset", action: accept }
`,
		"cluster cidr": `
firewall:
  cluster-rules:
    - { direction: ingress, cidr: "10.0.0.0/8 }", action: drop }
`,
		"cluster comment": `
firewall:
  cluster-rules:
    - { direction: ingress, action: drop, comment: 'x"; accept; #' }
`,
		"ipset element": `
ipsets:
  office:
    cidrs: ["10.0.0.0/8 accept"]
`,
	}
	want := map[string]string{
		"sg port":         "security-groups.web.rules[0]",
		"cluster cidr":    "firewall.cluster-rules[0]",
		"cluster comment": "firewall.cluster-rules[0]",
		"ipset element":   "ipsets.office",
	}
	for name, body := range bad {
		_, err := ParseBytes([]byte("name: s\n" + body))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), want[name]) || !strings.Contains(err.Error(), "invalid") {
			t.Errorf("%s: %v does not name %s", name, err, want[name])
		}
	}
	// Forms nft accepts, including a rule with no direction, still parse.
	ok := `name: s
security-groups:
  web:
    rules:
      - { proto: TCP, port: "{ 80, 443 }", action: accept }
      - { direction: ingress, proto: tcp, port: "!= 22", cidr: "10.0.0.1-10.0.0.9", action: drop }
      - { direction: ingress, proto: tcp, port: 22, cidr: "@office" }
ipsets:
  office:
    cidrs: ["10.0.0.0/24", "10.1.0.1-10.1.0.9"]
firewall:
  cluster-rules:
    - { direction: egress, proto: udp, port: "53", cidr: "!= 10.0.0.0/8", comment: "dns" }
`
	if _, err := ParseBytes([]byte(ok)); err != nil {
		t.Errorf("valid firewall sections refused: %v", err)
	}
}
