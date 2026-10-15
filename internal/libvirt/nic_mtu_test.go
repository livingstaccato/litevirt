package libvirt

import (
	"errors"
	"strconv"
	"strings"
	"testing"
)

func mtuCfg(n NetworkConfig, read func(string) (int, error)) VMConfig {
	return VMConfig{
		Name: "vm", CPU: 1, MemoryMiB: 512,
		Networks:  []NetworkConfig{{Bridge: "br-other", Model: "virtio", MAC: "52:54:00:00:00:01"}, n},
		BridgeMTU: read,
		HostName:  "node-a",
	}
}

func bridges(m map[string]int) func(string) (int, error) {
	return func(b string) (int, error) {
		v, ok := m[b]
		if !ok {
			return 0, errors.New("no such device")
		}
		return v, nil
	}
}

// A NIC whose MTU is `bridge` renders the bridge's MTU as read from the
// injected reader; an explicit MTU must EQUAL the bridge's, larger and smaller
// both refused with the NIC, bridge and host named; no MTU never reads.
//
// Mutations: allow a smaller MTU — the "smaller" case goes red; allow a larger
// one — the "larger" case goes red; render bridge NICs from a constant — the
// bridge case goes red.
func TestGenerateDomainXML_NICMTU(t *testing.T) {
	jumbo := bridges(map[string]int{"br-j": 9000, "br-other": 1500})
	nic := func(mtu int) NetworkConfig {
		return NetworkConfig{Bridge: "br-j", Model: "virtio", MAC: "52:54:00:00:00:02", MTU: mtu}
	}

	x, err := GenerateDomainXML(mtuCfg(nic(1), jumbo))
	if err != nil || !strings.Contains(x, `<mtu size="9000">`) {
		t.Errorf("bridge NIC on a 9000 bridge: err=%v\n%s", err, x)
	}
	if strings.Count(x, "<mtu ") != 1 {
		t.Errorf("only the NIC that sets an MTU renders one:\n%s", x)
	}
	x, err = GenerateDomainXML(mtuCfg(nic(1), bridges(map[string]int{"br-j": 1500, "br-other": 1500})))
	if err != nil || !strings.Contains(x, `<mtu size="1500">`) {
		t.Errorf("bridge NIC on a 1500 bridge: err=%v\n%s", err, x)
	}
	if x, err = GenerateDomainXML(mtuCfg(nic(9000), jumbo)); err != nil || !strings.Contains(x, `<mtu size="9000">`) {
		t.Errorf("equal: err=%v\n%s", err, x)
	}
	for name, mtu := range map[string]int{"larger": 9216, "smaller": 1400} {
		_, err := GenerateDomainXML(mtuCfg(nic(mtu), jumbo))
		want := "NIC 1 MTU " + strconv.Itoa(mtu) + " does not match bridge br-j MTU 9000 on host node-a (a guest MTU must equal its bridge's)"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
	}
	// A reader error fails the render and names the bridge.
	_, err = GenerateDomainXML(mtuCfg(NetworkConfig{Bridge: "br-gone", Model: "virtio", MAC: "52:54:00:00:00:03", MTU: 1}, jumbo))
	if err == nil || !strings.Contains(err.Error(), "br-gone") || !strings.Contains(err.Error(), "no such device") {
		t.Errorf("unreadable bridge: err = %v, want one naming br-gone and the cause", err)
	}
	// No MTU anywhere: the reader is never asked.
	asked := 0
	if _, err := GenerateDomainXML(mtuCfg(NetworkConfig{Bridge: "br-j", Model: "virtio"}, func(string) (int, error) {
		asked++
		return 0, errors.New("unreachable")
	})); err != nil || asked != 0 {
		t.Errorf("no MTU: err=%v, reader asked %d times", err, asked)
	}
	// Macvtap and SR-IOV (direct) NICs, and a non-virtio model, are refused.
	if _, err := GenerateDomainXML(mtuCfg(NetworkConfig{Direct: "bond0", Model: "virtio", MTU: 9000}, jumbo)); err == nil || !strings.Contains(err.Error(), "macvtap") {
		t.Errorf("direct NIC with an MTU: %v", err)
	}
	if _, err := GenerateDomainXML(mtuCfg(NetworkConfig{Bridge: "br-j", Model: "e1000", MTU: 9000}, jumbo)); err == nil || !strings.Contains(err.Error(), "virtio") {
		t.Errorf("e1000 NIC with an MTU: %v", err)
	}
}

var _ BridgeMTUReader = (*Client)(nil)
