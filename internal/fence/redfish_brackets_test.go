package fence

import (
	"net/url"
	"testing"
)

// The Redfish endpoint rule refuses brackets except around a plain IPv6
// literal host. Go's URL parser accepts a zoned literal, whose zone is free
// text: it can carry a token body, or an escaped "]" that leaves the host
// unbalanced. A zone names an interface on one node, which means nothing on
// the next, so it is refused too.
//
// Mutation: drop the bracket rule from redfishBaseURL — the zoned cases are
// accepted, red.
func TestValidateRedfishConfig_BracketsOnlyAroundAPlainIPv6Literal(t *testing.T) {
	for _, e := range []string{
		"https://[fe80::1%25trust=on;path=managed;v=2]",
		"https://[fe80::1%25x%5D]",
		"https://[fe80::1%25en0]",
	} {
		if _, err := url.Parse(e); err != nil {
			t.Fatalf("premise: the URL parser refuses %q (%v); the case tests nothing", e, err)
		}
		if err := ValidateRedfishConfig(RedfishConfig{Endpoint: e}); err == nil {
			t.Errorf("accepted %q", e)
		}
	}
	for _, e := range []string{"https://[fd00::9]", "https://[fd00::9]:443/", "https://bmc.example"} {
		if err := ValidateRedfishConfig(RedfishConfig{Endpoint: e}); err != nil {
			t.Errorf("refused %q: %v", e, err)
		}
	}
	for e, want := range map[string]bool{
		"https://[fe80::1%25x%5D]": true, "https://[fd00::9]": false, "https://bmc.example": false, "10.0.0.9 [trust=on": true,
	} {
		if got := UnsafeBMCAddress(e); got != want {
			t.Errorf("UnsafeBMCAddress(%q) = %v, want %v", e, got, want)
		}
	}
}
