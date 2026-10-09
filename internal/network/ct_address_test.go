package network

import "testing"

func TestContainerAddress(t *testing.T) {
	for _, c := range []struct{ ip, subnet, addr, gw string }{
		{"172.16.77.2", "172.16.77.0/24", "172.16.77.2/24", "172.16.77.1"},
		{"172.16.77.50/24", "172.16.77.0/24", "172.16.77.50/24", "172.16.77.1"},
		{"10.1.2.3", "10.1.0.0/16", "10.1.2.3/16", "10.1.0.1"},
		{"10.1.2.3", "", "10.1.2.3", ""},
		{"", "10.1.0.0/16", "", ""},
		{"10.1.2.3", "garbage", "10.1.2.3", ""},
		{"2001:db8::5", "2001:db8::/64", "2001:db8::5", ""},
	} {
		addr, gw := ContainerAddress(c.ip, c.subnet)
		if addr != c.addr || gw != c.gw {
			t.Errorf("ContainerAddress(%q, %q) = %q, %q; want %q, %q", c.ip, c.subnet, addr, gw, c.addr, c.gw)
		}
	}
}
