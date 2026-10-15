package main

import "testing"

// --nic-mtu takes <nic>=<MTU|bridge> with a 0-based NIC number; 0 removes the
// MTU and bridge is stored as 1. Anything else is refused before a call.
func TestParseNICMTU(t *testing.T) {
	for in, want := range map[string][2]int32{"0=9000": {0, 9000}, "2=bridge": {2, 1}, " 1 = BRIDGE ": {1, 1}, "0=0": {0, 0}} {
		got, err := parseNICMTU(in)
		if err != nil || got.GetOrdinal() != want[0] || got.GetMtu() != want[1] {
			t.Errorf("parseNICMTU(%q) = %+v, %v; want ordinal %d mtu %d", in, got, err, want[0], want[1])
		}
	}
	for _, bad := range []string{"9000", "x=9000", "-1=9000", "0=", "0=abc", "0=-5", "0=1", "0=575", "0=65521"} {
		if _, err := parseNICMTU(bad); err == nil {
			t.Errorf("parseNICMTU(%q) accepted", bad)
		}
	}
}
