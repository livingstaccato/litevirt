package lb

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func unicastCfg(peers ...string) Config {
	return Config{
		Name:          "app",
		VIP:           "10.0.100.100",
		VIPPrefix:     24,
		Interface:     "br-app",
		VRID:          42,
		Priority:      100,
		VRRPUnicast:   true,
		VRRPInterface: "eth0",
		UnicastSrc:    "192.168.1.10",
		UnicastPeers:  peers,
	}
}

// TestRenderKeepalived_UnicastKeepsVRRPOffTheVIPSegment: with VRRPUnicast the
// adverts go from this host's own address to its peers' over the device that
// holds it, and nothing VRRP is on the bridge the VIP (and its guests) is on:
// the VIP names its device, the bridge is only tracked, and there is no
// plaintext password to read.
//
// Mutation: render `interface {{.Interface}}` in the unicast branch — red; drop
// `dev` from the VIP line — red; keep the PASS block — red.
func TestRenderKeepalived_UnicastKeepsVRRPOffTheVIPSegment(t *testing.T) {
	got, err := RenderKeepalived(unicastCfg("192.168.1.12", "192.168.1.11"))
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	for _, want := range []string{
		"    interface eth0\n",
		"    unicast_src_ip 192.168.1.10\n",
		"    unicast_peer {\n        192.168.1.11\n        192.168.1.12\n    }\n",
		"    check_unicast_src\n",
		"    track_interface {\n        br-app\n    }\n",
		"        10.0.100.100/24 dev br-app\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("unicast render lacks %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"interface br-app", "auth_type", "auth_pass", deriveAuthPass("app")} {
		if strings.Contains(got, bad) {
			t.Errorf("unicast render carries %q:\n%s", bad, got)
		}
	}
}

// TestRenderKeepalived_UnicastSoleHost: keepalived cannot run unicast with no
// peers (it falls back to multicast on the interface, here the host network).
// A sole LB host names itself, with a TTL range no packet can be in, so it
// sends only to itself over loopback, discards that, accepts nothing from
// anyone, and becomes master on its own.
//
// Mutation: render an empty peer block for a sole host — red.
func TestRenderKeepalived_UnicastSoleHost(t *testing.T) {
	got, err := RenderKeepalived(unicastCfg())
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	if !strings.Contains(got, "    unicast_peer {\n        192.168.1.10 min_ttl 0 max_ttl 0\n    }\n") {
		t.Errorf("a sole host does not name itself as its unreachable peer:\n%s", got)
	}
}

// TestRenderKeepalived_UnicastVIPOnTheVRRPDevice: a VIP on the host's own LAN
// is on the same device the adverts use; nothing is tracked twice.
func TestRenderKeepalived_UnicastVIPOnTheVRRPDevice(t *testing.T) {
	cfg := unicastCfg("192.168.1.11")
	cfg.Interface = "eth0"
	got, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	if strings.Contains(got, "track_interface") {
		t.Errorf("the VRRP device is tracked a second time:\n%s", got)
	}
	if !strings.Contains(got, "10.0.100.100/24 dev eth0\n") {
		t.Errorf("VIP line:\n%s", got)
	}
}

// TestRenderKeepalived_LegacyUnchanged: an LB not yet on unicast renders as
// every earlier build did, so a host that has not latched vrrp_unicast_v1
// still pairs with a peer on an earlier build (the golden pins the bytes).
func TestRenderKeepalived_LegacyUnchanged(t *testing.T) {
	cfg := unicastCfg("192.168.1.11")
	cfg.VRRPUnicast = false
	got, err := RenderKeepalived(cfg)
	if err != nil {
		t.Fatalf("RenderKeepalived: %v", err)
	}
	for _, bad := range []string{"unicast", "track_interface", " dev "} {
		if strings.Contains(got, bad) {
			t.Errorf("legacy render carries %q:\n%s", bad, got)
		}
	}
	if !strings.Contains(got, "    interface br-app\n") || !strings.Contains(got, "auth_type PASS") {
		t.Errorf("legacy render changed:\n%s", got)
	}
}

// TestRenderKeepalived_UnicastRefusesWhatItCannotRender: every value it renders
// is one IPv4 literal or one device token, or the render is refused.
func TestRenderKeepalived_UnicastRefusesWhatItCannotRender(t *testing.T) {
	for name, mut := range map[string]func(*Config){
		"no source":           func(c *Config) { c.UnicastSrc = "" },
		"source not IPv4":     func(c *Config) { c.UnicastSrc = "fe80::1" },
		"source not an IP":    func(c *Config) { c.UnicastSrc = "host-a" },
		"peer not an IP":      func(c *Config) { c.UnicastPeers = []string{"192.168.1.11\n}"} },
		"peer not IPv4":       func(c *Config) { c.UnicastPeers = []string{"::1"} },
		"no VRRP device":      func(c *Config) { c.VRRPInterface = "" },
		"VRRP device escapes": func(c *Config) { c.VRRPInterface = "eth0 }" },
	} {
		cfg := unicastCfg("192.168.1.11")
		mut(&cfg)
		if _, err := RenderKeepalived(cfg); err == nil {
			t.Errorf("%s: rendered", name)
		}
	}
}

// TestParseKeepalivedVIP_UnicastNamesTheVIPDevice: Demote removes the VIP from
// the device it was put on. In a unicast render that is the VIP line's `dev`,
// not the VRRP interface, which holds the host's own address.
//
// Mutation: ignore `dev` on the VIP line — the parse answers eth0, red.
func TestParseKeepalivedVIP_UnicastNamesTheVIPDevice(t *testing.T) {
	conf, err := RenderKeepalived(unicastCfg("192.168.1.11"))
	if err != nil {
		t.Fatal(err)
	}
	vip, prefix, iface, ok := parseKeepalivedVIP(conf)
	if !ok || vip != "10.0.100.100" || prefix != 24 || iface != "br-app" {
		t.Fatalf("parse = %q/%d on %q (ok=%v), want 10.0.100.100/24 on br-app", vip, prefix, iface, ok)
	}
	legacy := unicastCfg()
	legacy.VRRPUnicast = false
	conf, err = RenderKeepalived(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, iface, ok := parseKeepalivedVIP(conf); !ok || iface != "br-app" {
		t.Fatalf("legacy parse iface = %q (ok=%v), want br-app", iface, ok)
	}
}

// TestManager_KeepalivedUnicast reads the transport of the config on disk, so
// the reconciler can find an LB still rendered for the old transport.
func TestManager_KeepalivedUnicast(t *testing.T) {
	dir := t.TempDir()
	m := NewManagerAt(dir, t.TempDir())
	if _, ok := m.KeepalivedUnicast("app"); ok {
		t.Fatal("no config on disk, yet a transport was read")
	}
	write := func(cfg Config) {
		conf, err := RenderKeepalived(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "app-keepalived.conf"), []byte(conf), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	legacy := unicastCfg()
	legacy.VRRPUnicast = false
	write(legacy)
	if u, ok := m.KeepalivedUnicast("app"); !ok || u {
		t.Fatalf("legacy config read as unicast=%v ok=%v", u, ok)
	}
	write(unicastCfg("192.168.1.11"))
	if u, ok := m.KeepalivedUnicast("app"); !ok || !u {
		t.Fatalf("unicast config read as unicast=%v ok=%v", u, ok)
	}
}
