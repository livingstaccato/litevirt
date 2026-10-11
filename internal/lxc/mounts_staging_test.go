package lxc

import (
	"bytes"
	"log/slog"
	"os"
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

// m-5. A config an earlier build rendered names the old staging root. Its
// first daemon-driven start renders it again under the new root and says so
// at Info — it was staged at the old path until now — never as the
// "differed from its authorized record" warning a tampered block gets.
//
// Mutation: compare without mapping the old root to the new one — red.
func TestCheckHostAccessForStart_LegacyRootIsNotTampering(t *testing.T) {
	root, access := hostTree(t)
	r := &LxcRunner{Lxcpath: t.TempDir(), HostAccess: access}
	dir := containerDir(t, r, "c1", "lxc.uts.name = c1\n")
	if err := r.SetHostAccess("c1", []Mount{{HostPath: filepath.Join(root, "allowed", "data"), ContainerPath: "/srv"}}, nil); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config")
	b, _ := os.ReadFile(cfgPath)
	legacy := strings.ReplaceAll(string(b), stagingRoot+"/", legacyStagingRoot+"/")
	if legacy == string(b) {
		t.Fatal("the rendered config names no staging path")
	}
	if err := os.WriteFile(cfgPath, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	if err := r.checkHostAccessForStart("c1"); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if strings.Contains(out, "differed from its authorized record") {
		t.Errorf("an earlier build's staging root was logged as a tampered block:\n%s", out)
	}
	if !strings.Contains(out, "level=INFO") || !strings.Contains(out, "staged at the old path until") {
		t.Errorf("the move to the new staging root was not said at Info:\n%s", out)
	}
	if b, _ := os.ReadFile(cfgPath); strings.Contains(string(b), legacyStagingRoot) || !strings.Contains(string(b), stagingRoot+"/c1/m0") {
		t.Errorf("the config was not rendered again under the new root:\n%s", b)
	}
}
