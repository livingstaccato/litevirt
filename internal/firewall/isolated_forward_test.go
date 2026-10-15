package firewall

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The wildcard lines of the isolated-network forward chain: forwarded traffic
// into or out of any br-iso-* device, to or from a device that is not one,
// is dropped.
const (
	isoWildOut = `iifname "br-iso-*" oifname != "br-iso-*" drop`
	isoWildIn  = `oifname "br-iso-*" iifname != "br-iso-*" drop`
)

// TestRender_IsolatedForwardFailsClosed: the forward drop for isolated
// bridges is rendered even when the plan names none, so a bridge the database
// does not know (a deleted network whose guests are still attached, a pass
// that has not run since the bridge was made) is held in from the start.
//
// Mutation: render the chain only when IsolatedBridges is non-empty — red.
func TestRender_IsolatedForwardFailsClosed(t *testing.T) {
	out, err := Render(Plan{})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"chain isolated_forward {", "type filter hook forward priority filter; policy accept;", isoWildOut, isoWildIn} {
		if !strings.Contains(out, want) {
			t.Errorf("empty plan: missing %q:\n%s", want, out)
		}
	}
}

// TestRender_IsolatedForwardPerBridge: a known isolated bridge also gets its
// own pair of drops, so it cannot route to another isolated bridge either;
// traffic that stays on the bridge (bridged, seen here only with
// br_netfilter) still passes. Bridges are sorted and deduplicated.
//
// Mutation: drop the per-bridge lines — red.
func TestRender_IsolatedForwardPerBridge(t *testing.T) {
	out, err := Render(Plan{IsolatedBridges: []string{"br-iso-b", "br-iso-a", "br-iso-b"}})
	if err != nil {
		t.Fatal(err)
	}
	a1 := `iifname "br-iso-a" oifname != "br-iso-a" drop`
	a2 := `oifname "br-iso-a" iifname != "br-iso-a" drop`
	b1 := `iifname "br-iso-b" oifname != "br-iso-b" drop`
	for _, want := range []string{a1, a2, b1, isoWildOut, isoWildIn} {
		if n := strings.Count(out, want); n != 1 {
			t.Errorf("%q appears %d times, want 1:\n%s", want, n, out)
		}
	}
	if strings.Index(out, a1) > strings.Index(out, b1) {
		t.Errorf("per-bridge lines not sorted:\n%s", out)
	}
}

// TestRender_IsolatedForwardRefusesUnsafeName: a name is written into the
// script as text, so anything but an interface name is refused.
func TestRender_IsolatedForwardRefusesUnsafeName(t *testing.T) {
	for _, bad := range []string{"", `br"x`, "br x", "a;b", "br-iso-*"} {
		if _, err := Render(Plan{IsolatedBridges: []string{bad}}); err == nil {
			t.Errorf("bridge %q rendered, want refused", bad)
		}
	}
}

// TestPlanLoader_IsolatedBridges: the loader names the bridge of every live
// isolated network, and every br-iso-* link the host reports, and nothing
// else (a bridge or vxlan network is not isolated; host-isolation is a
// different thing).
//
// Mutation: drop the networks-table source, or the host-link source — red.
func TestPlanLoader_IsolatedBridges(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	add := func(name, typ string, def compose.NetworkDef) {
		t.Helper()
		def.Type = typ
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: name, Type: typ, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	add("internal", "isolated", compose.NetworkDef{Subnet: "10.201.0.0/24"})
	add("a-very-long-isolated-name", "isolated", compose.NetworkDef{Subnet: "10.203.0.0/24"})
	add("lan", "bridge", compose.NetworkDef{Interface: "br0", Subnet: "10.0.0.0/24"})
	add("hinet", "bridge", compose.NetworkDef{Subnet: "10.202.0.0/24", HostIsolation: true})
	add("ovl", "vxlan", compose.NetworkDef{VNI: 100, Subnet: "10.200.0.0/24"})

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{
		IsolatedBridgeLinks: func() []string { return []string{"br-iso-orphan", "br-iso-internal"} },
	})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		compose.IsolatedBridgeName("a-very-long-isolated-name"),
		"br-iso-internal",
		"br-iso-orphan",
	}
	if strings.Join(plan.IsolatedBridges, ",") != strings.Join(want, ",") {
		t.Errorf("IsolatedBridges = %v, want %v", plan.IsolatedBridges, want)
	}
}

// TestRender_HostIsolationAcceptsReplies: a host-isolated bridge's input
// drop lets through replies to connections the host opened, ahead of the
// drop, so haproxy reaches backends on the bridge.
//
// Mutation: drop the established accept — red.
func TestRender_HostIsolationAcceptsReplies(t *testing.T) {
	out, err := Render(Plan{HostIsolation: []IsolationChain{{Bridge: "hinet"}}})
	if err != nil {
		t.Fatal(err)
	}
	acc := "iifname hinet ct state established,related accept"
	i, j := strings.Index(out, acc), strings.Index(out, "iifname hinet drop")
	if i < 0 || j < 0 || i > j {
		t.Errorf("want %q before the drop:\n%s", acc, out)
	}
}
