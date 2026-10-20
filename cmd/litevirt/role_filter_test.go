package main

import "testing"

// Review L5: lv role ls --role keeps a held binding of that role, which the
// API lists as "<role> (held)".
//
// Mutation: the suffix not stripped — red.
func TestRoleList_FilterKeepsAHeldBindingOfItsRole(t *testing.T) {
	for _, tc := range []struct {
		listed, filter string
		want           bool
	}{
		{"Operator", "Operator", true},
		{"Operator (held)", "Operator", true},
		{"Operator (held)", "", true},
		{"Viewer (held)", "Operator", false},
		{"Operator", "Viewer", false},
	} {
		if got := bindingHasRole(tc.listed, tc.filter); got != tc.want {
			t.Errorf("bindingHasRole(%q, %q) = %v, want %v", tc.listed, tc.filter, got, tc.want)
		}
	}
}
