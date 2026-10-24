package lxc

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/safename"
)

// The staging contract with the stock AppArmor profile (lab 2, Ubuntu
// 24.04): /usr/bin/lxc-start's profile lets a pre-start hook mount only
// beneath /var/lib/lxc ("mount -> /var/lib/lxc/{**,}", abstractions/lxc/
// start-container), so a hook that binds or stages anywhere else — the old
// /run/litevirt/ct — is denied and every container with a host mount or
// device fails to start. The staging root lies beneath LXC's store, in a
// directory no container can be named (a container named like it would own
// it), and the rendered block names exactly that path and runs the hook with
// its argv.
//
// Mutation: put stagingRoot back at /run/litevirt/ct — red.
func TestStaging_UnderTheLXCStoreTheStockProfileAllows(t *testing.T) {
	if !strings.HasPrefix(stagingRoot, defaultLxcpath+"/") || filepath.Dir(stagingRoot) != defaultLxcpath {
		t.Fatalf("stagingRoot = %s; want a directory directly beneath %s (the only tree lxc-start's AppArmor profile lets a hook mount on)", stagingRoot, defaultLxcpath)
	}
	if err := safename.ValidateContainerName(filepath.Base(stagingRoot)); err == nil {
		t.Errorf("%s is a valid container name: a container of that name would own the staging root", filepath.Base(stagingRoot))
	}
	if got, want := stagingPath("c1", 2), stagingRoot+"/c1/m2"; got != want {
		t.Errorf("stagingPath = %s; want %s", got, want)
	}
	block := renderHostAccessBlock("c1", "/opt/lv/litevirt",
		[]resolvedMount{{Prefix: "/srv", Rel: "data", Target: "srv/data"}, {Prefix: "/srv", Rel: "f.conf", Target: "etc/f.conf", File: true, RW: true}}, nil)
	for _, want := range []string{
		"lxc.hook.pre-start = /opt/lv/litevirt " + HookArg + "\n",
		"lxc.hook.post-stop = /opt/lv/litevirt " + HookArg + "\n",
		"lxc.mount.entry = " + defaultLxcpath + "/.litevirt+staging/c1/m0 srv/data none bind,ro,nosuid,nodev,create=dir 0 0\n",
		"lxc.mount.entry = " + defaultLxcpath + "/.litevirt+staging/c1/m1 etc/f.conf none bind,nosuid,nodev,create=file 0 0\n",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("rendered block lacks %q:\n%s", want, block)
		}
	}
	if strings.Contains(block, "/run/litevirt") {
		t.Errorf("rendered block still names /run/litevirt:\n%s", block)
	}
}
