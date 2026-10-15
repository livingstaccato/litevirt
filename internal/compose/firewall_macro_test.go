package compose

import (
	"strings"
	"testing"
)

const macroSGFile = `name: s
security-groups:
  web:
    rules:
      - { direction: ingress, proto: tcp, port: "22", action: accept }
      - { direction: ingress, macro: DNS, action: accept }
      - { direction: egress, macro: web, cidr: "10.0.0.0/8", action: drop }
      - { direction: ingress, proto: tcp, port: "8080", action: accept }
firewall:
  cluster-rules:
    - { direction: egress, macro: ntp, action: accept }
    - { direction: egress, macro: ssh, action: accept, comment: mine }
`

func TestMacro_ExpandsWithRulePriority(t *testing.T) {
	f, err := ParseBytes([]byte(macroSGFile))
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		proto, port, cidr, comment string
		prio                       int
	}
	var got []row
	for _, r := range f.SecurityGroups["web"].Rules {
		if r.Macro != "" {
			t.Errorf("an expanded row still names its macro: %+v", r)
		}
		got = append(got, row{r.Proto, r.Port, r.CIDR, r.Comment, r.Priority})
	}
	want := []row{
		{"tcp", "22", "", "", 10},
		{"udp", "53", "", "", 20},
		{"tcp", "53", "", "", 20},
		{"tcp", "80", "10.0.0.0/8", "", 30},
		{"tcp", "443", "10.0.0.0/8", "", 30},
		{"tcp", "8080", "", "", 40},
	}
	if len(got) != len(want) {
		t.Fatalf("rows = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("row %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	// Cluster rows carry the label unless a comment was given.
	cr := f.FirewallDefaults.ClusterRules
	if len(cr) != 2 || cr[0].Comment != "macro NTP" || cr[0].Proto != "udp" || cr[0].Port != "123" || cr[0].Priority != 10 {
		t.Errorf("cluster rule 0 = %+v", cr[0])
	}
	if cr[1].Comment != "mine" || cr[1].Priority != 20 {
		t.Errorf("cluster rule 1 = %+v", cr[1])
	}
}

func TestMacro_RefusesPortProtoAndUnknown(t *testing.T) {
	cases := map[string]struct{ rule, want string }{
		"port":    {`{ direction: ingress, macro: SSH, port: "2222" }`, "macro"},
		"proto":   {`{ direction: ingress, macro: SSH, proto: tcp }`, "macro"},
		"unknown": {`{ direction: ingress, macro: Nope }`, "unknown macro"},
		"cidr":    {`{ direction: ingress, macro: SSH, cidr: "10.0.0.1 }" }`, "invalid"},
	}
	for name, c := range cases {
		_, err := ParseBytes([]byte("name: s\nsecurity-groups:\n  web:\n    rules:\n      - " + c.rule + "\n"))
		if err == nil || !strings.Contains(err.Error(), "security-groups.web.rules[0]") || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	// The port refusal is about the combination, not the port's own grammar.
	_, err := ParseBytes([]byte("name: s\nfirewall:\n  cluster-rules:\n    - { direction: ingress, macro: SSH, port: \"22\" }\n"))
	if err == nil || !strings.Contains(err.Error(), "cannot be combined") {
		t.Errorf("cluster port refusal = %v", err)
	}
}

func TestMacro_StrictFieldsStillRefuseUnknownKey(t *testing.T) {
	_, err := ParseBytes([]byte("name: s\nsecurity-groups:\n  web:\n    rules:\n      - { direction: ingress, macroo: SSH }\n"))
	if err == nil || !strings.Contains(err.Error(), `unknown field "macroo"`) {
		t.Errorf("err = %v", err)
	}
	// priority is not a YAML key: the row order sets it.
	_, err = ParseBytes([]byte("name: s\nsecurity-groups:\n  web:\n    rules:\n      - { direction: ingress, proto: tcp, port: 1, priority: 5 }\n"))
	if err == nil || !strings.Contains(err.Error(), `unknown field "priority"`) {
		t.Errorf("priority err = %v", err)
	}
}

// A stored stack is read, not judged, but still re-expanded.
func TestMacro_StoredYAMLReExpands(t *testing.T) {
	f, err := parseWith([]byte(macroSGFile), parseOpts{stored: true})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(f.SecurityGroups["web"].Rules); n != 6 {
		t.Errorf("stored rows = %d, want 6", n)
	}
}

func TestExpandMacros_Idempotent(t *testing.T) {
	f, err := ParseBytes([]byte(macroSGFile))
	if err != nil {
		t.Fatal(err)
	}
	if err := ExpandMacros(f); err != nil {
		t.Fatal(err)
	}
	if n := len(f.SecurityGroups["web"].Rules); n != 6 {
		t.Errorf("rows after a second expansion = %d, want 6", n)
	}
}

// A stored stack is read, not judged: a macro this build cannot resolve
// leaves the stack readable, its other rows intact; the deploy's strict
// expansion still refuses it.
func TestMacro_StoredUnknownMacroStillParses(t *testing.T) {
	const y = `name: s
security-groups:
  web:
    rules:
      - { direction: ingress, proto: tcp, port: "22", action: accept }
      - { direction: ingress, macro: FromTheFuture, action: accept }
      - { direction: ingress, macro: DNS, action: accept }
firewall:
  cluster-rules:
    - { direction: ingress, macro: SSH, port: "1", action: accept }
`
	f, err := ParseStored([]byte(y))
	if err != nil {
		t.Fatalf("stored stack with an unresolvable macro: %v", err)
	}
	rs := f.SecurityGroups["web"].Rules
	if len(rs) != 4 || rs[0].Port != "22" || rs[1].Macro != "FromTheFuture" || rs[1].Priority != 20 ||
		rs[2].Port != "53" || rs[2].Priority != 30 || rs[3].Port != "53" {
		t.Errorf("rows = %+v", rs)
	}
	if cr := f.FirewallDefaults.ClusterRules; len(cr) != 1 || cr[0].Macro != "SSH" {
		t.Errorf("cluster rows = %+v", cr)
	}
	if err := ExpandMacros(f); err == nil {
		t.Error("the strict expansion accepted an unresolvable macro")
	}
	if _, err := ParseBytes([]byte(y)); err == nil {
		t.Error("a deploy parse accepted an unresolvable macro")
	}
}
