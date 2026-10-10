package firewall

import (
	"context"
	"os"
	"testing"
)

// TestBridgeConntrackAvailable_BuiltinAndModprobe (re-review m-h): a module
// built into the kernel has no /sys/module entry when it takes no parameters,
// so availability also reads modules.builtin; and a modprobe that succeeds is
// availability, whatever sysfs shows afterwards.
func TestBridgeConntrackAvailable_BuiltinAndModprobe(t *testing.T) {
	dir := t.TempDir()
	restore := setModulePaths(dir+"/sys", dir+"/modules", dir+"/builtin")
	defer restore()
	probes := 0
	defer setModprobe(func(context.Context, string) error { probes++; return nil })()

	if BridgeConntrackAvailable(context.Background(), false) {
		t.Fatal("available with nothing loaded, built in or probed")
	}
	if err := os.WriteFile(dir+"/builtin", []byte("kernel/net/bridge/netfilter/nf_conntrack_bridge.ko\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !BridgeConntrackAvailable(context.Background(), false) {
		t.Error("a built-in nf_conntrack_bridge reported missing")
	}
	_ = os.Remove(dir + "/builtin")
	if !BridgeConntrackAvailable(context.Background(), true) || probes != 1 {
		t.Errorf("a successful modprobe is not availability (probes=%d)", probes)
	}
}

// setModulePaths points module discovery at test files; it returns a restore.
func setModulePaths(sys, proc, builtin string) func() {
	s, p, b := sysModuleDir, procModulesPath, builtinListPath
	sysModuleDir, procModulesPath, builtinListPath = sys, proc, builtin
	return func() { sysModuleDir, procModulesPath, builtinListPath = s, p, b }
}

// setModprobe replaces the modprobe call; it returns a restore.
func setModprobe(f func(context.Context, string) error) func() {
	old := modprobe
	modprobe = f
	return func() { modprobe = old }
}
