package network

import (
	"context"
	"testing"
)

// NextFreeIPv4From scans from an offset and wraps, and like nextFreeIP never
// returns the network address, the gateway (first host) or the broadcast
// address.
//
// Mutation: drop the wrap (`% n`) — the offset past the end errors or leaves
// the subnet; start at base+1 — offset 0 returns the gateway.
func TestNextFreeIPv4From(t *testing.T) {
	for _, tc := range []struct {
		subnet string
		used   []string
		offset uint64
		want   string
	}{
		{"10.0.0.0/24", nil, 0, "10.0.0.2"},
		{"10.0.0.0/24", nil, 10, "10.0.0.12"},
		{"10.0.0.0/24", nil, 252, "10.0.0.254"},
		{"10.0.0.0/24", nil, 253, "10.0.0.2"}, // wraps
		{"10.0.0.0/24", []string{"10.0.0.254", "10.0.0.2/24"}, 252, "10.0.0.3"},
		{"10.0.0.0/30", nil, 7, "10.0.0.2"},
	} {
		got, err := NextFreeIPv4From(tc.subnet, tc.used, tc.offset)
		if err != nil || got != tc.want {
			t.Errorf("NextFreeIPv4From(%s, %v, %d) = %q, %v; want %q", tc.subnet, tc.used, tc.offset, got, err, tc.want)
		}
	}
	if _, err := NextFreeIPv4From("10.0.0.0/31", nil, 0); err == nil {
		t.Error("a /31 has no usable address past the gateway, want an error")
	}
	if _, err := NextFreeIPv4From("10.0.0.0/30", []string{"10.0.0.2"}, 0); err == nil {
		t.Error("an exhausted subnet, want an error")
	}
	if _, err := NextFreeIPv4From("fd00::/64", nil, 0); err == nil {
		t.Error("an IPv6 subnet, want an error")
	}
}

// The builtin allocator passes over ClaimRequest.Exclude: addresses a caller
// has handed out whose rows are not written yet (review m-5).
//
// Mutation: drop `used = append(used, exclude...)` — red.
func TestBuiltinClaimPassesOverExclude(t *testing.T) {
	db := newTestDB(t)
	got, err := NewBuiltinAllocator(db).Claim(context.Background(), ClaimRequest{
		Network: "n", Subnet: "10.5.0.0/24", MAC: "52:54:00:00:00:01", OwnerKind: "ct", OwnerHost: "h", Name: "c",
		Exclude: []string{"10.5.0.2", "10.5.0.3"},
	})
	if err != nil || got.IP != "10.5.0.4" {
		t.Errorf("claim = %q, %v; want 10.5.0.4", got.IP, err)
	}
}
