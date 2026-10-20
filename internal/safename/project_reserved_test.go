package safename

import "testing"

func TestValidateNewProjectName_ReservedSegments(t *testing.T) {
	for _, bad := range []string{"/acme/vms", "acme/networks/x", "/a/storage_pools", "/a/security_groups", "/a/containers", "/a/stacks"} {
		if err := ValidateNewProjectName(bad); err == nil {
			t.Errorf("%q accepted, want refused", bad)
		}
	}
	for _, ok := range []string{"/acme", "acme/team", "/vms", "/acme/vms2"} {
		if err := ValidateNewProjectName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}

func TestValidateNewProjectName_RootAndDefaultRefused(t *testing.T) {
	for _, bad := range []string{"/", "//", "///", "/_default", "_default", "_default/"} {
		if err := ValidateNewProjectName(bad); err == nil {
			t.Errorf("%q accepted, want refused", bad)
		}
	}
	for _, ok := range []string{"/_default/x", "_defaults", "/acme"} {
		if err := ValidateNewProjectName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
}
