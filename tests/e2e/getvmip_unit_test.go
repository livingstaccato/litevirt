package e2e

import (
	"testing"

	lvcompose "github.com/litevirt/litevirt/internal/compose"
)

// TestInspectNICIP: lab 2 (guest-agent run) found getVMIP matching
// networkName == "brnet" while lv inspect reports a stack's network under its
// scoped name, "<stack>_brnet", so every lookup timed out on a guest that held
// its lease. The lookup takes the scoped name, and only that: a network of
// the same short name in ANOTHER stack is not this one.
//
// Mutation: match by suffix (strings.HasSuffix(name, "_"+network) or
// equality) in inspectNICIP — the bare-name lookup returns another stack's
// address.
func TestInspectNICIP(t *testing.T) {
	const out = `{"name":"vm","interfaces":[
	 {"networkName":"other_brnet","mac":"52:54:00:00:00:01","ip":"172.41.0.9"},
	 {"networkName":"gaprobe_brnet","mac":"52:54:00:f8:ce:23","ip":"172.41.0.2"},
	 {"networkName":"gaprobe_isonet","mac":"52:54:00:f8:ce:24","ip":""}]}`
	if got := inspectNICIP(out, lvcompose.ScopedNetworkName("gaprobe", "brnet")); got != "172.41.0.2" {
		t.Errorf("scoped lookup = %q, want 172.41.0.2", got)
	}
	if got := inspectNICIP(out, "brnet"); got != "" {
		t.Errorf("bare-name lookup = %q: matched a network not named brnet", got)
	}
	if got := inspectNICIP(out, "gaprobe_isonet"); got != "" {
		t.Errorf("a NIC with no address yet gave %q", got)
	}
	if got := inspectNICIP("not json", "gaprobe_brnet"); got != "" {
		t.Errorf("unparseable output gave %q", got)
	}
}
