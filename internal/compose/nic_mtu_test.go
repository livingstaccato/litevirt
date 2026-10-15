package compose

import (
	"strings"
	"testing"
)

func mtuYAML(model, mtu string) string {
	y := "name: m\nnetworks:\n  n1: {}\nvms:\n  web:\n    image: img\n    network:\n      - name: n1\n"
	if model != "" {
		y += "        model: " + model + "\n"
	}
	if mtu != "" {
		y += "        mtu: " + mtu + "\n"
	}
	return y
}

// A NIC's mtu: a number from 576 to 65520, "bridge" (stored 1, as Proxmox
// writes mtu=1), or unset / 0 for today's behaviour. virtio only, VMs only.
//
// Mutation: accept e1000 — the model row goes red.
func TestNICMTU_Parse(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int32
	}{
		{"9000", 9000},
		{"bridge", NICMTUBridge},
		{"1", NICMTUBridge},
		{"0", 0},
		{"", 0},
		{"576", 576},
		{"65520", 65520},
	} {
		f, err := ParseBytes([]byte(mtuYAML("", c.in)))
		if err != nil {
			t.Errorf("mtu %q: %v", c.in, err)
			continue
		}
		vm := f.VMs["web"]
		spec, err := BuildVMSpec("web", "web", &vm, f)
		if err != nil {
			t.Fatal(err)
		}
		if got := spec.Network[0].Mtu; got != c.want {
			t.Errorf("mtu %q: stored %d, want %d", c.in, got, c.want)
		}
	}
	for _, bad := range []string{"575", "65521", "abc", "-1", "2"} {
		if _, err := ParseBytes([]byte(mtuYAML("", bad))); err == nil || !strings.Contains(err.Error(), "mtu") {
			t.Errorf("mtu %q: err = %v, want a refusal naming mtu", bad, err)
		}
	}
	if _, err := ParseBytes([]byte(mtuYAML("e1000", "9000"))); err == nil || !strings.Contains(err.Error(), "virtio") {
		t.Errorf("mtu on e1000: err = %v, want a refusal naming virtio", err)
	}
	if _, err := ParseBytes([]byte(mtuYAML("virtio", "9000"))); err != nil {
		t.Errorf("mtu on an explicit virtio NIC: %v", err)
	}
	for _, kind := range []string{"lxc", "oci"} {
		y := strings.Replace(mtuYAML("", "9000"), "    image: img\n", "    kind: "+kind+"\n    image: alpine:3.21\n", 1)
		if _, err := ParseBytes([]byte(y)); err == nil || !strings.Contains(err.Error(), "mtu") {
			t.Errorf("mtu on a %s entry: err = %v, want a refusal naming mtu", kind, err)
		}
	}
}

// The stored value round-trips through the file form: 1 is written as bridge.
func TestNICMTU_Marshal(t *testing.T) {
	for v, want := range map[int32]interface{}{NICMTUBridge: "bridge", 9000: int32(9000)} {
		got, err := NICMTU{N: v}.MarshalYAML()
		if err != nil || got != want {
			t.Errorf("MarshalYAML(%d) = %v, %v; want %v", v, got, err, want)
		}
	}
	if !(NICMTU{}).IsZero() || (NICMTU{N: 1}).IsZero() {
		t.Error("IsZero: only the unset value is zero")
	}
}
