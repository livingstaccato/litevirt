package auth

import "testing"

// ctroot.exec is granted only by name, by "ctroot.*" or by "*": a role
// written as "*.exec" for vm.exec and ct.exec does not become a root shell
// in every privileged container, and a delegate holding one cannot grant it.
func TestContainerRootVerbIsNotCarriedBySuffixWildcards(t *testing.T) {
	for _, tc := range []struct {
		grant string
		want  bool
	}{
		{"*.exec", false},
		{"ct.*", false},
		{"ct.exec", false},
		{"*", true},
		{"ctroot.*", true},
		{VerbContainerRoot, true},
	} {
		if got := verbMatches([]string{tc.grant}, VerbContainerRoot); got != tc.want {
			t.Errorf("verbMatches(%q, %s) = %v, want %v", tc.grant, VerbContainerRoot, got, tc.want)
		}
		if got := GrantCovers(tc.grant, VerbContainerRoot); got != tc.want {
			t.Errorf("GrantCovers(%q, %s) = %v, want %v", tc.grant, VerbContainerRoot, got, tc.want)
		}
	}
	// Suffix wildcards still work for everything else.
	if !verbMatches([]string{"*.exec"}, "vm.exec") || !GrantCovers("*.exec", "ct.exec") {
		t.Error("*.exec no longer covers vm.exec / ct.exec")
	}
	if u := UncoveredGrants([]string{"*.exec"}, []string{"ct.exec", VerbContainerRoot}); len(u) != 1 || u[0] != VerbContainerRoot {
		t.Errorf("a delegate holding *.exec may grant ContainerRoot's verbs; uncovered = %v", u)
	}
}
