package firewall

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// A comment holding ";" and "#" (spec §0.4, re-review R1-C1) is text inside
// nft's quoted string: the write grammar takes it, and the renderer writes it
// quoted as it is, so a rule with the comment `a; b #1` keeps loading.
//
// Mutations: the comment grammar refuses ";" or "#" — red; quoteComment
// rewrites them — red.
func TestComment_SemicolonAndHashAreText(t *testing.T) {
	const c = "a; b #1"
	if err := rulefield.Rule("ingress", "tcp", "22", "10.0.0.0/8", "accept", c); err != nil {
		t.Errorf("write grammar refused the comment %q: %v", c, err)
	}
	if err := rulefield.StoredRule("ingress", "tcp", "22", "10.0.0.0/8", "accept", c); err != nil {
		t.Errorf("stored-row grammar refused the comment %q: %v", c, err)
	}
	out, err := Render(Plan{ClusterRules: []Rule{{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "10.0.0.0/8", Action: Accept, Comment: c}}})
	if err != nil {
		t.Fatalf("Render refused the comment %q: %v", c, err)
	}
	if !strings.Contains(out, `comment "a; b #1"`) {
		t.Errorf("rendered script does not carry the comment quoted as written:\n%s", out)
	}
}
