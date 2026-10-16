package lxc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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

func TestNetLinks_PrivateConfigFile(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "ct")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "config")
	original := "# private fixture\nlxc.net.0.link = oldbr\nlxc.net.1.link = other\nlxc.apparmor.profile = unchanged\n"
	if e := os.WriteFile(path, []byte(original), 0600); e != nil {
		t.Fatal(e)
	}
	r := &LxcRunner{Lxcpath: root}
	if e := r.SetNetLink("ct", 0, "newbr"); e != nil {
		t.Fatal(e)
	}
	links, e := r.NetLinks("ct")
	if e != nil || links[0] != "newbr" || links[1] != "other" {
		t.Fatalf("links %v %v", links, e)
	}
	b, e := os.ReadFile(path)
	if e != nil || string(b) != strings.Replace(original, "oldbr", "newbr", 1) {
		t.Fatalf("unrelated config changed: %s %v", b, e)
	}
	st, e := os.Stat(path)
	if e != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("mode %v %v", st, e)
	}
	if e := r.SetNetLink("ct", 9, "bad"); e == nil {
		t.Fatal("missing NIC accepted")
	}
	if _, e := r.NetLinks("absent"); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if e := r.SetNetLink("absent", 0, "bad"); !os.IsNotExist(e) {
		t.Fatal(e)
	}
	if e := os.Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(path, 0700); e != nil {
		t.Fatal(e)
	}
	if _, e := r.NetLinks("ct"); e == nil {
		t.Fatal("directory read accepted")
	}
	if e := r.SetNetLink("ct", 0, "bad"); e == nil {
		t.Fatal("directory write accepted")
	}
}
