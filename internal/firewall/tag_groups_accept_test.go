package firewall

import "testing"

// A logged accept is an accept and a logged drop a deny, as tag-group
// rm --force judges a reference (D6 review m-7): an accept on a missing
// group must match nothing, never lose its address as a deny does.
//
// A bare "+log" names no verdict and is a deny, failing closed (D6
// re-review n-2).
//
// Mutations: compare the action without stripping +log — accept+log is a
// deny: red; read a bare "+log" as "" — it is an accept: red.
func TestIsAccept_LoggedVerdicts(t *testing.T) {
	for action, want := range map[string]bool{
		"": true, "accept": true, " ACCEPT ": true, "accept+log": true, "Accept+LOG": true,
		"drop": false, "drop+log": false, "reject": false, "reject+log": false, "+log": false, " +LOG ": false,
	} {
		if got := isAccept(action); got != want {
			t.Errorf("isAccept(%q) = %v, want %v", action, got, want)
		}
	}
}
