package auth

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestGrantCovers_IsASubsetTest: for every pair, whatever the requested grant
// matches, the held grant matches too — checked against verbMatches itself
// over a corpus of verbs, so GrantCovers cannot drift from the matcher it
// stands in for.
func TestGrantCovers_IsASubsetTest(t *testing.T) {
	grants := []string{"*", "vm.*", "vm.start", "vm.read", "*.read", "ct.*", "*.start", "lb.*", "vm.x.*",
		"*.x.read", "perm.modify", "perm.*", "*.*", ".read", "vm", "*.modify", "vmx.read", "vmx.*", "xread", "*read"}
	verbs := []string{"vm.start", "vm.read", "vm.x.read", "vm.x.y", "ct.read", "ct.start", "lb.read", "lb.create",
		"perm.modify", "audit.read", "x.read", ".read", "vm", "*.*", "vm.*", "*", "network.x.read", "vmx.read", "xread", "vmx.start"}
	for _, held := range grants {
		for _, req := range grants {
			if !GrantCovers(held, req) {
				continue
			}
			for _, v := range verbs {
				if verbMatches([]string{req}, v) && !verbMatches([]string{held}, v) {
					t.Errorf("GrantCovers(%q, %q) but %q matches %q and not %q", held, req, req, v, held)
				}
			}
		}
	}
	for _, c := range []struct {
		held, req string
		want      bool
	}{
		{"*", "*", true}, {"vm.*", "*", false}, {"*.read", "vm.*", false}, {"vm.*", "vm.start", true},
		{"vm.start", "vm.*", false}, {"*.read", "vm.read", true}, {"Operator", "Admin", false},
	} {
		if got := GrantCovers(c.held, c.req); got != c.want {
			t.Errorf("GrantCovers(%q, %q) = %v, want %v", c.held, c.req, got, c.want)
		}
	}
}

// TestGrantsAt_PropagationAndHasAnyBindingExcept covers the two engine reads
// delegation decides on.
func TestGrantsAt_PropagationAndHasAnyBindingExcept(t *testing.T) {
	e := NewEngine(nil)
	e.snap.Store(&engineSnapshot{
		roleVerbs: map[string][]string{"A": {"vm.*"}, "B": {"ct.*"}},
		bindings: []corrosion.RoleBindingRecord{
			{ID: "1", Path: "/p", Role: "A", Principal: "user:u@local", Propagate: true},
			{ID: "2", Path: "/p/q", Role: "B", Principal: "user:u@local", Propagate: false},
			{ID: "3", Path: "/other", Role: "B", Principal: "user:v@local", Propagate: true},
		},
	})
	u := []string{"user:u@local"}
	if got := e.GrantsAt(u, "/p/q", false); len(got) != 2 {
		t.Errorf("GrantsAt(/p/q, exact) = %v, want vm.* and ct.*", got)
	}
	if got := e.GrantsAt(u, "/p/q", true); len(got) != 1 || got[0] != "vm.*" {
		t.Errorf("GrantsAt(/p/q, propagating) = %v, want only the propagating vm.*", got)
	}
	if got := e.GrantsAt(u, "/p2", false); len(got) != 0 {
		t.Errorf("GrantsAt(/p2) = %v, want nothing (sibling prefix)", got)
	}
	if !e.HasAnyBindingExcept(u, "1") || e.HasAnyBindingExcept([]string{"user:v@local"}, "3") {
		t.Error("HasAnyBindingExcept miscounts")
	}
	if !e.HoldsVerbAnywhere(u, "ct.start") || e.HoldsVerbAnywhere(u, VerbPermModify) {
		t.Error("HoldsVerbAnywhere miscounts")
	}
}
