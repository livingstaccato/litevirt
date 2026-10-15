package firewall

import (
	"strings"
	"testing"
)

// injectMark is a word no renderer ever writes. Every payload below places it
// where nft would read it as part of the ruleset if the payload got through.
const injectMark = "INJECTED"

// nftOutsideStrings returns script with every nft quoted string and #-comment
// removed, as nft's lexer sees them: a quoted string runs from `"` to the next
// `"` (nft has no escape inside one), a comment from `#` to the end of the line.
// What remains is what nft parses as ruleset syntax.
func nftOutsideStrings(script string) string {
	var b strings.Builder
	inStr, inComment := false, false
	for _, r := range script {
		switch {
		case inComment:
			if r == '\n' {
				inComment = false
				b.WriteRune(r)
			}
		case inStr:
			if r == '"' {
				inStr = false
			}
		case r == '"':
			inStr = true
		case r == '#':
			inComment = true
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// assertNoInjection fails if the payload's mark reached nft syntax.
func assertNoInjection(t *testing.T, name string, p Plan) {
	t.Helper()
	out, err := Render(p)
	if err != nil {
		return // refused whole: nothing reached a script
	}
	// Upper-cased: the renderer lowercases a protocol, mark included.
	if strings.Contains(strings.ToUpper(nftOutsideStrings(out)), injectMark) {
		t.Errorf("%s: injected text reached the nft script as syntax:\n%s", name, out)
	}
}

// TestRender_RuleFieldInjection (finding F-1): a rule field carrying a
// newline, `;`, brace, space or quote must never add nft syntax of its own to
// the ruleset. Each payload is rendered in the cluster tier with a NIC
// present, so it reaches both the inet forward chain and the per-NIC table.
func TestRender_RuleFieldInjection(t *testing.T) {
	base := Rule{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "10.0.0.0/8", Action: Drop}
	cases := map[string]func(*Rule){
		"proto semicolon":   func(r *Rule) { r.Proto = "esp; " + injectMark },
		"proto newline":     func(r *Rule) { r.Proto = "esp\n" + injectMark },
		"proto brace":       func(r *Rule) { r.Proto = "esp }\n}\ntable inet " + injectMark + " {" },
		"port semicolon":    func(r *Rule) { r.PortRange = "22; " + injectMark },
		"port newline":      func(r *Rule) { r.PortRange = "22\n" + injectMark },
		"port space":        func(r *Rule) { r.PortRange = "22 " + injectMark },
		"cidr v4 brace":     func(r *Rule) { r.CIDR = "10.0.0.0/8 }\n" + injectMark },
		"cidr v4 semicolon": func(r *Rule) { r.CIDR = "10.0.0.0/8; " + injectMark },
		"cidr v6 newline":   func(r *Rule) { r.CIDR = "fd00::/8\n" + injectMark },
		"action newline":    func(r *Rule) { r.Action = Action("drop\n" + injectMark) },
		"direction newline": func(r *Rule) { r.Direction = Direction("ingress\n" + injectMark) },
		"comment quote":     func(r *Rule) { r.Comment = `x"; ` + injectMark + ` accept; #` },
		"comment newline":   func(r *Rule) { r.Comment = "x\n" + injectMark },
	}
	for name, mut := range cases {
		for _, mode := range []string{NICModeEnforce, NICModeObserve} {
			r := base
			mut(&r)
			assertNoInjection(t, name+"/"+mode, Plan{
				DefaultDeny:  true,
				NICMode:      mode,
				ClusterRules: []Rule{r},
				NICs:         []NICBinding{{NICDev: "tap0", VMName: "vm"}},
			})
		}
	}
}

// TestRender_IPSetInjection: an ip set's name and elements are written into
// the script as text too.
func TestRender_IPSetInjection(t *testing.T) {
	cases := map[string]IPSet{
		"name brace":        {Name: "s {\n    }\n    " + injectMark + " {", CIDRs: []string{"10.0.0.0/8"}},
		"name semicolon":    {Name: "s; " + injectMark, CIDRs: []string{"10.0.0.0/8"}},
		"element v4 brace":  {Name: "s", CIDRs: []string{"10.0.0.0/8 }\n" + injectMark + " {"}},
		"element v4 comma":  {Name: "s", CIDRs: []string{"10.0.0.0/8 } ; " + injectMark}},
		"element v6 brace":  {Name: "s", CIDRs: []string{"fd00::/8 }\n" + injectMark}},
		"element v4 spaces": {Name: "s", CIDRs: []string{"10.0.0.0/8 " + injectMark}},
	}
	for name, set := range cases {
		assertNoInjection(t, name, Plan{IPSets: []IPSet{set}, NICs: []NICBinding{{NICDev: "tap0", VMName: "vm"}}})
	}
}

// TestRender_SGNameInjectionObserve: in observe mode a security group's name
// becomes part of each would-drop counter's comment.
func TestRender_SGNameInjectionObserve(t *testing.T) {
	name := `a"; ` + injectMark + ` accept; #`
	assertNoInjection(t, "sg name", Plan{
		DefaultDeny: true,
		NICMode:     NICModeObserve,
		SecurityGroups: []SecurityGroup{{Name: name, Rules: []Rule{
			{Direction: Ingress, Proto: "tcp", PortRange: "22", Action: Drop},
		}}},
		NICs: []NICBinding{{NICDev: "tap0", VMName: "vm", SecurityGroups: []string{name}}},
	})
}

// TestRender_NATIsolationInjection: the per-host NAT and isolation intents
// name bridges, interfaces, subnets and addresses written as text.
func TestRender_NATIsolationInjection(t *testing.T) {
	bad := "x\n" + injectMark
	cases := map[string]Plan{
		"masq subnet":  {NAT: []NATRule{{Subnet: "10.0.0.0/24 " + injectMark, Bridge: "br0"}}},
		"masq bridge":  {NAT: []NATRule{{Subnet: "10.0.0.0/24", Bridge: bad}}},
		"snat iface":   {NAT: []NATRule{{Subnet: "10.0.0.0/24", OutIface: bad, SNATTo: "1.2.3.4"}}},
		"snat to":      {NAT: []NATRule{{Subnet: "10.0.0.0/24", OutIface: "eth0", SNATTo: "1.2.3.4 " + injectMark}}},
		"iso bridge":   {HostIsolation: []IsolationChain{{Bridge: bad}}},
		"iso vip":      {HostIsolation: []IsolationChain{{Bridge: "br0", Exceptions: []IsolationException{{VIP: "10.0.0.5 " + injectMark, Ports: []int{80}}}}}},
		"nic bridge":   {NICs: []NICBinding{{NICDev: "tap0", Bridge: bad}}},
		"nic dev":      {NICs: []NICBinding{{NICDev: bad}}},
		"gateway addr": {Gateways: []string{"10.0.0.1 " + injectMark}, NICs: []NICBinding{{NICDev: "tap0"}}},
	}
	for name, p := range cases {
		assertNoInjection(t, name, p)
	}
}
