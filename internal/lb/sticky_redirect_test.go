package lb

import (
	"context"
	"github.com/litevirt/litevirt/internal/lbtestproc"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func stickyRedirectConfig() Config {
	return Config{
		Name: "web", VIP: "10.0.1.100", VIPPrefix: 24, Algorithm: "roundrobin",
		Sticky:   true,
		Backends: []Backend{{Name: "vm1", IP: "10.0.1.10", Port: 8080}},
		Ports: []Port{
			{Listen: 80, Target: 8080, Protocol: "http", RedirectHTTPS: true},
			{Listen: 8080, Target: 8080, Protocol: "tcp"},
		},
	}
}

// TestRenderHAProxy_StickyAndRedirect: sticky sessions pin a client to a
// backend by its source address in every backend, and a redirect-https
// listener answers with a redirect instead of proxying. Before, lb.Config had
// neither, and both settings were dropped on every path.
//
// Mutations: drop the sticky block, or the redirect branch, from the
// template — red.
func TestRenderHAProxy_StickyAndRedirect(t *testing.T) {
	out, err := RenderHAProxy(stickyRedirectConfig())
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out, "    stick-table type ip size 100k expire 30m\n    stick on src\n"); n != 2 {
		t.Errorf("sticky in %d backends, want 2:\n%s", n, out)
	}
	redirect := "frontend web-80\n    bind 10.0.1.100:80\n    mode http\n    http-request redirect scheme https code 301\n\n"
	if !strings.Contains(out, redirect) {
		t.Errorf("listener 80 does not redirect to https:\n%s", out)
	}
	if !strings.Contains(out, "frontend web-8080\n    bind 10.0.1.100:8080\n    default_backend web-8080-be\n") {
		t.Errorf("listener 8080 without redirect should proxy:\n%s", out)
	}

	// Neither: no sticky table, no redirect.
	cfg := stickyRedirectConfig()
	cfg.Sticky = false
	cfg.Ports[0].RedirectHTTPS = false
	out, err = RenderHAProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "stick") || strings.Contains(out, "redirect") || strings.Contains(out, "mode http") {
		t.Errorf("no sticky/redirect asked for, rendered:\n%s", out)
	}
}

// A redirect on a TLS listener would send https to itself; it is ignored there.
func TestRenderHAProxy_RedirectIgnoredOnTLS(t *testing.T) {
	cfg := stickyRedirectConfig()
	cfg.Ports = []Port{{Listen: 443, Target: 8080, Protocol: "http", RedirectHTTPS: true, TLS: &TLSConfig{Cert: "/c", Key: "/k"}}}
	out, err := RenderHAProxy(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "redirect") || !strings.Contains(out, "default_backend web-443-be") {
		t.Errorf("TLS listener with redirect-https:\n%s", out)
	}
}

// TestRenderHAProxy_StickyAndRedirectValidate: haproxy itself accepts the
// rendered config. Skips where haproxy is not installed.
func TestRenderHAProxy_StickyAndRedirectValidate(t *testing.T) {
	bin, err := exec.LookPath("haproxy")
	if err != nil {
		t.Skip("haproxy not installed")
	}
	out, err := RenderHAProxy(stickyRedirectConfig())
	if err != nil {
		t.Fatal(err)
	}
	// Validation does not need the haproxy user or the stats socket's dir.
	out = strings.NewReplacer("    user haproxy\n", "", "    group haproxy\n", "").Replace(out)
	path := filepath.Join(t.TempDir(), "h.cfg")
	if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command(bin, "-c", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("haproxy -c: %v\n%s\n%s", err, b, out)
	}
}

// fakeLBBinaries puts haproxy, keepalived, sysctl and conntrackd stand-ins on
// PATH. Each records its arguments to <dir>/<name>.calls and exits 0.
func fakeLBBinaries(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, name := range []string{"haproxy", "keepalived", "sysctl", "conntrackd"} {
		script := "#!/bin/sh\necho \"$@\" >> " + filepath.Join(dir, name+".calls") + "\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir)
	resetConntrackdLookup(t)
	return dir
}

// TestApply_SNATStartsConntrackd: an LB with SNAT writes conntrackd's config
// and notify script, gives keepalived the notify hooks and starts conntrackd
// on its config; applied again without SNAT, conntrackd's files go and it is
// not started.
//
// Mutations (each red): never set startCT; leave the conntrackd config in
// place without SNAT; render conntrackd's sync interface as the VRRP one.
func TestApply_SNATStartsConntrackd(t *testing.T) {
	runtime := lbtestproc.New(t, true)
	bin := runtime.Dir
	m := testManager(t)
	m.SetProcessRuntime(runtime)
	ctx := context.Background()
	cfg := Config{
		Name: "snat-lb", VIP: "10.0.1.200", VIPPrefix: 24, Interface: "br0", VRID: 20, Priority: 100,
		Algorithm:   "roundrobin",
		Backends:    []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:       []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		SNATEnabled: true, LocalIP: "192.0.2.11", PeerIP: "192.0.2.12", Subnet: "10.0.1.0/24", SyncInterface: "eth0",
	}
	if err := m.Apply(ctx, cfg); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	ctPath := filepath.Join(m.configDir, "snat-lb-conntrackd.conf")
	ct, err := os.ReadFile(ctPath)
	if err != nil {
		t.Fatalf("conntrackd config not written: %v", err)
	}
	for _, want := range []string{"IPv4_address 192.0.2.11", "IPv4_Destination_Address 192.0.2.12", "Interface eth0", "IPv4_address 10.0.1.0/24"} {
		if !strings.Contains(string(ct), want) {
			t.Errorf("conntrackd config missing %q:\n%s", want, ct)
		}
	}
	if _, err := os.Stat(filepath.Join(m.configDir, "snat-lb-notify.sh")); err != nil {
		t.Errorf("notify script not written: %v", err)
	}
	ka, _ := os.ReadFile(filepath.Join(m.configDir, "snat-lb-keepalived.conf"))
	// The hooks name the script where this manager wrote it.
	if !strings.Contains(string(ka), `notify_master "`+filepath.Join(m.configDir, "snat-lb-notify.sh")+` MASTER"`) {
		t.Errorf("keepalived has no notify hook on %s:\n%s", m.configDir, ka)
	}
	notify, _ := os.ReadFile(filepath.Join(m.configDir, "snat-lb-notify.sh"))
	if !strings.Contains(string(notify), `CONF="`+ctPath+`"`) {
		t.Errorf("notify script does not name %s:\n%s", ctPath, notify)
	}
	calls, _ := os.ReadFile(filepath.Join(bin, "conntrackd.calls"))
	if got := strings.TrimSpace(string(calls)); got != "-C "+ctPath+" -d" {
		t.Errorf("conntrackd calls %q, want one start on %s", got, ctPath)
	}

	// SNAT off: no conntrackd, its files removed, keepalived without hooks.
	os.Remove(filepath.Join(bin, "conntrackd.calls"))
	cfg.SNATEnabled = false
	if err := m.Apply(ctx, cfg); err != nil {
		t.Fatalf("Apply without SNAT: %v", err)
	}
	if b, err := os.ReadFile(filepath.Join(bin, "conntrackd.calls")); err == nil {
		t.Errorf("conntrackd started without SNAT: %q", b)
	}
	for _, f := range []string{ctPath, filepath.Join(m.configDir, "snat-lb-notify.sh")} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s left behind without SNAT", f)
		}
	}
	ka, _ = os.ReadFile(filepath.Join(m.configDir, "snat-lb-keepalived.conf"))
	if strings.Contains(string(ka), "notify_master") {
		t.Errorf("keepalived keeps notify hooks without SNAT:\n%s", ka)
	}
}

// resetConntrackdLookup makes the next apply look conntrackd up again.
func resetConntrackdLookup(t *testing.T) {
	t.Helper()
	conntrackdOnce, conntrackdFound = sync.Once{}, false
	t.Cleanup(func() { conntrackdOnce, conntrackdFound = sync.Once{}, false })
}

// TestApply_SNATWithoutConntrackd: with conntrackd not installed, an SNAT
// apply writes its config and starts nothing, and the lookup is made once.
//
// Mutation: drop conntrackdInstalled() from startCT — red.
func TestApply_SNATWithoutConntrackd(t *testing.T) {
	runtime := lbtestproc.New(t, false)
	bin := runtime.Dir
	m := testManager(t)
	m.SetProcessRuntime(runtime)
	cfg := Config{
		Name: "nct-lb", VIP: "10.0.1.200", VIPPrefix: 24, Interface: "br0", VRID: 21, Priority: 100,
		Backends:    []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:       []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		SNATEnabled: true, LocalIP: "192.0.2.11", PeerIP: "192.0.2.12", Subnet: "10.0.1.0/24",
	}
	for i := 0; i < 2; i++ {
		if err := m.Apply(context.Background(), cfg); err != nil {
			t.Fatalf("Apply: %v", err)
		}
	}
	if _, err := os.Stat(filepath.Join(bin, "conntrackd.calls")); !os.IsNotExist(err) {
		t.Errorf("conntrackd run although not installed")
	}
	if runtime.Looks != 1 {
		t.Errorf("conntrackd looked up %d times over two applies, want once", runtime.Looks)
	}
}

// TestApply_KeepSNATLeavesTheSNATSideAlone: an apply that does not know the
// LB's snat (KeepSNAT) after one that set SNAT up leaves conntrackd's config
// and the notify script in place, starts no conntrackd and renders the same
// keepalived (hooks included); on an LB without SNAT it renders no hooks.
//
// Mutations (each red): drop the KeepSNAT case in Apply (the SNAT-off
// teardown runs); drop the notify-script stat (keepalived loses its hooks).
func TestApply_KeepSNATLeavesTheSNATSideAlone(t *testing.T) {
	runtime := lbtestproc.New(t, true)
	bin := runtime.Dir
	m := testManager(t)
	m.SetProcessRuntime(runtime)
	ctx := context.Background()
	cfg := Config{
		Name: "keep-lb", VIP: "10.0.1.200", VIPPrefix: 24, Interface: "br0", VRID: 22, Priority: 100,
		Backends:    []Backend{{Name: "b1", IP: "10.0.1.10", Port: 8080}},
		Ports:       []Port{{Listen: 80, Target: 8080, Protocol: "tcp"}},
		SNATEnabled: true, LocalIP: "192.0.2.11", PeerIP: "192.0.2.12", Subnet: "10.0.1.0/24",
	}
	if err := m.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	kaPath := filepath.Join(m.configDir, "keep-lb-keepalived.conf")
	before, _ := os.ReadFile(kaPath)
	os.Remove(filepath.Join(bin, "conntrackd.calls"))
	// Backdate the SNAT files: an apply that leaves them alone leaves these.
	old := time.Unix(1_000_000_000, 0)
	for _, f := range []string{"keep-lb-conntrackd.conf", "keep-lb-notify.sh"} {
		if err := os.Chtimes(filepath.Join(m.configDir, f), old, old); err != nil {
			t.Fatal(err)
		}
	}

	older := Config{
		Name: cfg.Name, VIP: cfg.VIP, VIPPrefix: 24, Interface: "br0", VRID: 22, Priority: 100,
		Backends: cfg.Backends, Ports: cfg.Ports, KeepSNAT: true,
	}
	if err := m.Apply(ctx, older); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(kaPath)
	if string(after) != string(before) || !strings.Contains(string(after), "notify_master") {
		t.Errorf("keepalived changed under KeepSNAT:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	for _, f := range []string{"keep-lb-conntrackd.conf", "keep-lb-notify.sh"} {
		fi, err := os.Stat(filepath.Join(m.configDir, f))
		if err != nil {
			t.Errorf("%s gone under KeepSNAT: %v", f, err)
		} else if !fi.ModTime().Equal(old) {
			t.Errorf("%s rewritten under KeepSNAT", f)
		}
	}
	if b, err := os.ReadFile(filepath.Join(bin, "conntrackd.calls")); err == nil {
		t.Errorf("conntrackd started under KeepSNAT: %q", b)
	}

	// An LB that never had SNAT: KeepSNAT renders no hooks.
	plain := older
	plain.Name = "plain-lb"
	if err := m.Apply(ctx, plain); err != nil {
		t.Fatal(err)
	}
	if ka, _ := os.ReadFile(filepath.Join(m.configDir, "plain-lb-keepalived.conf")); strings.Contains(string(ka), "notify_master") {
		t.Errorf("KeepSNAT on an LB without SNAT rendered hooks:\n%s", ka)
	}
}
