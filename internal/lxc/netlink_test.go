package lxc

import "testing"

func TestNetLinksRoundTrip(t *testing.T) {
	cfg := "lxc.net.0.type = veth\nlxc.net.0.link = lanaa\nlxc.net.0.flags = up\nlxc.net.1.link=br0\nlxc.net.10.link = x\n"
	got := parseNetLinks(cfg)
	if len(got) != 3 || got[0] != "lanaa" || got[1] != "br0" || got[10] != "x" {
		t.Fatalf("parseNetLinks = %v", got)
	}
	out, ok := setNetLink(cfg, 0, "lanbb")
	if !ok {
		t.Fatal("setNetLink found no lxc.net.0.link")
	}
	if got := parseNetLinks(out); got[0] != "lanbb" || got[1] != "br0" || got[10] != "x" {
		t.Errorf("after setNetLink: %v, want only NIC 0 moved to lanbb", got)
	}
	if _, ok := setNetLink(cfg, 3, "z"); ok {
		t.Error("setNetLink reported a link NIC 3 does not have")
	}
}
