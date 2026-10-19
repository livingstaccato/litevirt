package compose

import "testing"

// C7: `log: true` on a rule parses into Log, on a macro rule into every row
// the macro expands to; a rule without it does not log.
//
// Mutation: drop Log in macro expansion — the DNS rows do not log, red.
func TestFirewallRule_LogField(t *testing.T) {
	f, err := ParseBytes([]byte(`name: s
security-groups:
  web:
    rules:
      - { direction: ingress, proto: tcp, port: "22", action: drop, log: true }
      - { direction: ingress, macro: DNS, action: accept, log: true }
      - { direction: ingress, proto: tcp, port: "80", action: accept }
firewall:
  cluster-rules:
    - { direction: ingress, proto: tcp, port: "23", action: reject, log: true }
`))
	if err != nil {
		t.Fatal(err)
	}
	var logs []bool
	for _, r := range f.SecurityGroups["web"].Rules {
		logs = append(logs, r.Log)
	}
	if want := []bool{true, true, true, false}; len(logs) != len(want) || logs[0] != want[0] || logs[1] != want[1] || logs[2] != want[2] || logs[3] != want[3] {
		t.Errorf("sg rule logs = %v, want %v", logs, want)
	}
	if cr := f.FirewallDefaults.ClusterRules; len(cr) != 1 || !cr[0].Log {
		t.Errorf("cluster rules = %+v, want one logged", cr)
	}
}
