package libvirt

import (
	"fmt"
	"strings"
	"testing"
)

// fakeVirshDumpXML returns a minimal domain XML with a single interface whose
// MAC matches mac and whose tap target device is tapDev.
func fakeVirshDumpXML(mac, tapDev string) []byte {
	return []byte(fmt.Sprintf(`<domain>
  <devices>
    <interface type='bridge'>
      <mac address='%s'/>
      <target dev='%s'/>
    </interface>
  </devices>
</domain>`, mac, tapDev))
}

// fakeBridgeVLAN answers `bridge vlan show dev <tap>` with the VLANs given
// (iproute2's layout: a header, the tap's name on its first VLAN's line) and
// records every add and del.
func fakeBridgeVLAN(t *testing.T, tapDev string, have ...string) *[]string {
	t.Helper()
	orig := execVLAN
	t.Cleanup(func() { execVLAN = orig })
	var calls []string
	execVLAN = func(name string, args ...string) ([]byte, error) {
		if len(args) >= 2 && args[0] == "vlan" && args[1] == "show" {
			out := "port              vlan-id\n"
			for i, v := range have {
				if i == 0 {
					out += tapDev + "             " + v + "\n"
				} else {
					out += "                  " + v + "\n"
				}
			}
			return []byte(out), nil
		}
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil, nil
	}
	return &calls
}

// On a fresh tap (VLAN 1 only, the bridge's default pvid) every trunk VLAN is
// added tagged — no pvid, no untagged — and VLAN 1 stays.
func TestNegotiateTrunkVLANs_FreshTapAddsEachVLANTagged(t *testing.T) {
	calls := fakeBridgeVLAN(t, "vnet0", "1 PVID Egress Untagged")
	if err := negotiateTrunkVLANs("vnet0", []int{10, 20, 30}); err != nil {
		t.Fatalf("negotiateTrunkVLANs: %v", err)
	}
	want := []string{
		"bridge vlan add dev vnet0 vid 10",
		"bridge vlan add dev vnet0 vid 20",
		"bridge vlan add dev vnet0 vid 30",
	}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", *calls, want)
	}
}

// A tap that carries VLANs the trunk no longer has is converged: those are
// removed (VLAN 1 is kept), the missing ones added, the ones it has left as
// they are. Re-applying to a converged tap does nothing.
//
// Mutations: skip the removal — red; add every desired VLAN whether present
// or not — red.
func TestNegotiateTrunkVLANs_ConvergesAStaleTap(t *testing.T) {
	calls := fakeBridgeVLAN(t, "vnet0", "1 PVID Egress Untagged", "100", "200")
	if err := negotiateTrunkVLANs("vnet0", []int{100, 300}); err != nil {
		t.Fatalf("negotiateTrunkVLANs: %v", err)
	}
	want := []string{
		"bridge vlan del dev vnet0 vid 200",
		"bridge vlan add dev vnet0 vid 300",
	}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", *calls, want)
	}

	calls = fakeBridgeVLAN(t, "vnet0", "1 PVID Egress Untagged", "100", "300")
	if err := negotiateTrunkVLANs("vnet0", []int{100, 300}); err != nil {
		t.Fatalf("negotiateTrunkVLANs on a converged tap: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("a converged tap was changed: %q", *calls)
	}
}

// An access port on a VLAN-filtering bridge ends carrying only its VLAN, as
// pvid, egress untagged. Lab 2 drill 6 found a fresh tap (the bridge gave it
// VLAN 1 as pvid, untagged) left with "1 Egress Untagged" beside
// "30 PVID Egress Untagged": the bridge's VLAN-1 floods reached the guest.
// The VLAN is added before VLAN 1 is removed, so the port always has a pvid.
//
// Mutations: skip the removal — red; remove before adding — red.
func TestConfigureAccessBridgeVLAN_TapCarriesOnlyItsVLAN(t *testing.T) {
	// `bridge vlan show` as it reads after the add, on the drill's tap.
	calls := fakeBridgeVLAN(t, "vnet1", "1 Egress Untagged", "30 PVID Egress Untagged")
	if err := configureAccessBridgeVLAN("vnet1", 30); err != nil {
		t.Fatalf("configureAccessBridgeVLAN: %v", err)
	}
	want := []string{
		"bridge vlan add dev vnet1 vid 30 pvid untagged",
		"bridge vlan del dev vnet1 vid 1",
	}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", *calls, want)
	}
}

// Re-applying (a start, a live migration's target) converges a tap that still
// has VLAN 1 or another VLAN, and leaves a converged one as it is.
func TestConfigureAccessBridgeVLAN_ReapplyConverges(t *testing.T) {
	calls := fakeBridgeVLAN(t, "vnet1", "1 Egress Untagged", "30 PVID Egress Untagged", "40")
	if err := configureAccessBridgeVLAN("vnet1", 30); err != nil {
		t.Fatalf("configureAccessBridgeVLAN: %v", err)
	}
	want := []string{
		"bridge vlan add dev vnet1 vid 30 pvid untagged",
		"bridge vlan del dev vnet1 vid 1",
		"bridge vlan del dev vnet1 vid 40",
	}
	if strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", *calls, want)
	}

	calls = fakeBridgeVLAN(t, "vnet1", "30 PVID Egress Untagged")
	if err := configureAccessBridgeVLAN("vnet1", 30); err != nil {
		t.Fatalf("configureAccessBridgeVLAN on a converged tap: %v", err)
	}
	if want := []string{"bridge vlan add dev vnet1 vid 30 pvid untagged"}; strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("a converged tap: calls = %q, want %q", *calls, want)
	}
}

// An access port on VLAN 1 keeps VLAN 1.
func TestConfigureAccessBridgeVLAN_VLAN1KeepsIt(t *testing.T) {
	calls := fakeBridgeVLAN(t, "vnet1", "1 PVID Egress Untagged")
	if err := configureAccessBridgeVLAN("vnet1", 1); err != nil {
		t.Fatalf("configureAccessBridgeVLAN: %v", err)
	}
	if want := []string{"bridge vlan add dev vnet1 vid 1 pvid untagged"}; strings.Join(*calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls = %q, want %q", *calls, want)
	}
}

// No trunk VLANs on a fresh tap: nothing to add or remove.
func TestNegotiateTrunkVLANs_EmptyList(t *testing.T) {
	calls := fakeBridgeVLAN(t, "vnet2", "1 PVID Egress Untagged")
	if err := negotiateTrunkVLANs("vnet2", nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(*calls) != 0 {
		t.Errorf("expected no bridge changes for an empty VLAN list, got %q", *calls)
	}
}
