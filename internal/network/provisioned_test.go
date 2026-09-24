package network

import (
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

func TestProvisionedHere(t *testing.T) {
	iso := compose.NetworkDef{Type: "isolated", Subnet: "172.16.50.0/24", DHCP: true}
	isoNoSubnet := compose.NetworkDef{Type: "isolated"}
	brDHCP := compose.NetworkDef{Type: "bridge", Interface: "br-lan", Subnet: "10.0.0.0/24", DHCP: true}
	brPlain := compose.NetworkDef{Type: "bridge", Interface: "br0", Subnet: "10.0.0.0/24"}
	vx := compose.NetworkDef{Type: "vxlan", VNI: 500, Subnet: "10.9.0.0/24"}

	type host struct {
		ifaces           map[string]bool
		present, alive   bool
		pidFileAskedWith string
	}
	cases := []struct {
		name    string
		net     string
		def     compose.NetworkDef
		h       host
		want    bool
		wantPID string
	}{
		{"isolated, bridge and dnsmasq up", "hc", iso,
			host{ifaces: map[string]bool{"br-iso-hc": true}, present: true, alive: true}, true, dnsmasqPidFile("br-iso-hc")},
		{"isolated, bridge gone", "hc", iso,
			host{ifaces: map[string]bool{}, present: true, alive: true}, false, ""},
		{"isolated, dnsmasq died (stale pidfile)", "hc", iso,
			host{ifaces: map[string]bool{"br-iso-hc": true}, present: true, alive: false}, false, dnsmasqPidFile("br-iso-hc")},
		{"isolated, dnsmasq never started (no pidfile)", "hc", iso,
			host{ifaces: map[string]bool{"br-iso-hc": true}}, false, dnsmasqPidFile("br-iso-hc")},
		{"isolated without a subnet needs no dnsmasq", "hc", isoNoSubnet,
			host{ifaces: map[string]bool{"br-iso-hc": true}}, true, dnsmasqPidFile("br-iso-hc")},
		{"bridge with --dhcp, no pidfile", "lan", brDHCP,
			host{ifaces: map[string]bool{"br-lan": true}}, false, dnsmasqPidFile("br-lan")},
		{"bridge without --dhcp may be an infra bridge, no pidfile is fine", "lan", brPlain,
			host{ifaces: map[string]bool{"br0": true}}, true, dnsmasqPidFile("br0")},
		{"vxlan dnsmasq died", "ov", vx,
			host{ifaces: map[string]bool{"br-vni500": true}, present: true}, false, dnsmasqPidFileVNI(500)},
		{"vxlan non-gateway host, no pidfile", "ov", vx,
			host{ifaces: map[string]bool{"br-vni500": true}}, true, dnsmasqPidFileVNI(500)},
		{"sriov is not ours to check", "fast", compose.NetworkDef{Type: "sriov", PF: "ens1f0"},
			host{}, true, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := tc.h
			p := hostProbe{
				ifaceExists: func(n string) bool { return h.ifaces[n] },
				dnsmasq: func(pf string) (bool, bool) {
					h.pidFileAskedWith = pf
					return h.present, h.alive
				},
			}
			if got := provisionedHere(tc.net, tc.def, p); got != tc.want {
				t.Errorf("provisionedHere = %v, want %v", got, tc.want)
			}
			if h.pidFileAskedWith != tc.wantPID {
				t.Errorf("checked pidfile %q, want %q", h.pidFileAskedWith, tc.wantPID)
			}
		})
	}
}
