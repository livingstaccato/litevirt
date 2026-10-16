package network

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestIsolatedBridgeName(t *testing.T) {
	cases := []struct {
		name    string
		network string
		want    string // "" means "don't care about exact value, just check length"
	}{
		{"short fits verbatim", "internal", "br-iso-internal"}, // 15 chars exactly
		{"e2e-net fits", "e2e-net", "br-iso-e2e-net"},
		{"9-char name is hashed", "e2e-rvnet", ""}, // br-iso-e2e-rvnet would be 16 → hashed
		{"long name is hashed", "a-very-long-isolated-network-name", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := IsolatedBridgeName(c.network)
			if len(got) > maxIfaceName {
				t.Fatalf("bridge name %q is %d chars, exceeds IFNAMSIZ limit %d", got, len(got), maxIfaceName)
			}
			if c.want != "" && got != c.want {
				t.Fatalf("IsolatedBridgeName(%q) = %q, want %q", c.network, got, c.want)
			}
			// Stable: same input → same output.
			if again := IsolatedBridgeName(c.network); again != got {
				t.Fatalf("not stable: %q then %q", got, again)
			}
		})
	}

	// Distinct long names must not collide on the 8-hex suffix.
	a := IsolatedBridgeName("tenant-alpha-isolated-net")
	b := IsolatedBridgeName("tenant-beta-isolated-net")
	if a == b {
		t.Fatalf("distinct long names collided: both %q", a)
	}
}

// An isolated network's bridge is put in compose.IsolatedBridgeGroup before
// it is brought up: the group, not the name, is what the firewall holds it to
// the host by. Provision runs again for every network on a daemon's first
// pass, so a bridge an earlier build made is marked too (a re-provision of an
// existing bridge sets it as well).
//
// Mutation: drop the group command — red.
func TestProvision_IsolatedBridgeJoinsTheGroup(t *testing.T) {
	for _, exists := range []bool{false, true} {
		var calls []string
		execCommand = func(name string, args ...string) ([]byte, error) {
			calls = append(calls, strings.Join(append([]string{name}, args...), " "))
			if exists && len(args) > 1 && args[1] == "add" {
				return []byte("RTNETLINK answers: File exists"), errors.New("exit status 2")
			}
			return nil, nil
		}
		startDHCPFunc = func(bridge, gw, rangeStart, rangeEnd, mask, pidFile string) error { return nil }
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(context.Background(), db); err != nil {
			t.Fatal(err)
		}
		br, err := Provision(context.Background(), db, "internal", compose.NetworkDef{Type: "isolated", Subnet: "10.201.0.0/24"}, "", "host1")
		execCommand, startDHCPFunc = defaultExec, StartDHCP
		if err != nil {
			t.Fatalf("exists=%v: Provision: %v", exists, err)
		}
		group := fmt.Sprintf("ip link set %s group %d", br, compose.IsolatedBridgeGroup)
		gi, ui := -1, -1
		for i, c := range calls {
			if c == group && gi < 0 {
				gi = i
			}
			if c == "ip link set "+br+" up" && ui < 0 {
				ui = i
			}
		}
		if gi < 0 || ui < 0 || gi > ui {
			t.Errorf("exists=%v: want %q before the bridge is up; commands:\n%s", exists, group, strings.Join(calls, "\n"))
		}
	}
}
