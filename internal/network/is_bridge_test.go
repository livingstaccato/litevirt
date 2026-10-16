package network

import "testing"

// IsBridge is true only for a bridge: a link that exists but is not a bridge
// (lo), a name no link has, and a name that is not a link name at all are
// all false.
//
// Mutation: IsBridge returns BridgeExists — "lo" goes red.
func TestIsBridge_OnlyABridge(t *testing.T) {
	if !BridgeExists("lo") {
		t.Skip("no lo on this host")
	}
	for _, name := range []string{"lo", "lv-no-such-br", "../lo", ""} {
		if IsBridge(name) {
			t.Errorf("IsBridge(%q) = true, want false", name)
		}
	}
}
