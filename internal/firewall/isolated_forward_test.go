package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// The group lines of the isolated-network forward chain: forwarded traffic
// into or out of a device in compose.IsolatedBridgeGroup, to or from a device
// outside it, is dropped.
const (
	isoWildOut = `iifgroup 27766 oifgroup != 27766 drop`
	isoWildIn  = `oifgroup 27766 iifgroup != 27766 drop`
)

// TestRender_IsolatedForwardFailsClosed: the forward drop for isolated
// bridges is rendered even when the plan names none, so a bridge in the group
// the database does not know (a deleted network whose guests are still
// attached) is held in from the start. Nothing is matched by name: a
// `bridge` network's br-iso-* bridge is not caught.
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
	if strings.Contains(out, "br-iso") {
		t.Errorf("empty plan matches a device by name:\n%s", out)
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
// isolated network and nothing else: a bridge network is not isolated even
// when its bridge is named br-iso-* (main allowed that, and it must keep
// routing after an upgrade), and host-isolation is a different thing.
//
// Mutation: drop the networks-table source, or take every br-iso-* bridge
// name — red.
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
	add("legacy", "bridge", compose.NetworkDef{Interface: "br-iso-lan", Subnet: "10.50.0.0/24"})
	add("br-iso-web", "bridge", compose.NetworkDef{Interface: "br-iso-web", Subnet: "10.60.0.0/24", DHCP: true})
	add("hinet", "bridge", compose.NetworkDef{Subnet: "10.202.0.0/24", HostIsolation: true})
	add("ovl", "vxlan", compose.NetworkDef{VNI: 100, Subnet: "10.200.0.0/24"})

	plan, err := CorrosionPlanLoader(db, "host-a", Plan{}, LoaderOptions{})(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{compose.IsolatedBridgeName("a-very-long-isolated-name"), "br-iso-internal"}
	if strings.Join(plan.IsolatedBridges, ",") != strings.Join(want, ",") {
		t.Errorf("IsolatedBridges = %v, want %v", plan.IsolatedBridges, want)
	}
	out, err := Render(plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"br-iso-lan", "br-iso-web"} {
		if strings.Contains(out, user) {
			t.Errorf("the ruleset names the bridge network's %s:\n%s", user, out)
		}
	}
}

// TestRender_HostIsolationAcceptsReplies: a host-isolated bridge's input
// drop lets through, ahead of the drop, only reply-direction packets of
// connections the host's output marked as opened onto that same bridge, so
// haproxy reaches backends there and a guest cannot ride any other host flow.
//
// Mutation: drop the output mark, the direction or the mark match — red.
func TestRender_HostIsolationAcceptsReplies(t *testing.T) {
	out, err := Render(Plan{HostIsolation: []IsolationChain{{Bridge: "hinet"}, {Bridge: "hinet2"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, br := range []string{"hinet", "hinet2"} {
		m := isolationMark(br)
		acc := fmt.Sprintf("iifname %s ct direction reply ct mark and 0xfff0000 == %#x ct state established,related accept", br, m)
		set := fmt.Sprintf("oifname %s ct state new ct mark set ct mark and 0xf000ffff or %#x", br, m)
		i, j := strings.Index(out, acc), strings.Index(out, "iifname "+br+" drop")
		if i < 0 || j < 0 || i > j {
			t.Errorf("want %q before %s's drop:\n%s", acc, br, out)
		}
		if !strings.Contains(out, set) {
			t.Errorf("want the output mark %q:\n%s", set, out)
		}
		if m&isolationMarkMask != m || m == 0 {
			t.Errorf("%s's mark %#x is outside the mask", br, m)
		}
	}
	if isolationMark("hinet") == isolationMark("hinet2") {
		t.Error("two bridges share a mark")
	}
}
