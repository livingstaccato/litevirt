package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

// C4a (spec §3.2): the firewall log store's keys default to 200 records a
// second, 64 MiB on disk and 7 days; an explicit 0 turns the file or the age
// bound off; a negative value, or a rate over 100000, fails the load.
//
// Mutations: drop a default — red; accept a negative — red.
func TestLoadConfig_FirewallLogKeys(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITEVIRT_CONFIG", cp)
	load := func(body string) (*Config, error) {
		t.Helper()
		if err := os.WriteFile(cp, []byte("host_name: h\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig()
	}
	cfg, err := load("")
	if err != nil {
		t.Fatal(err)
	}
	if f := cfg.Firewall; f.LogMaxRate != 200 || f.LogRetainMiB != 64 || f.LogRetainDays != 7 {
		t.Errorf("defaults = %+v, want 200/s, 64 MiB, 7 days", f)
	}
	cfg, err = load("firewall:\n  log_max_rate: 50\n  log_retain_mib: 0\n  log_retain_days: 0\n")
	if err != nil {
		t.Fatal(err)
	}
	if f := cfg.Firewall; f.LogMaxRate != 50 || f.LogRetainMiB != 0 || f.LogRetainDays != 0 {
		t.Errorf("explicit = %+v, want 50, 0, 0", f)
	}
	for _, bad := range []string{
		"firewall:\n  log_max_rate: -1\n",
		"firewall:\n  log_max_rate: 100001\n",
		"firewall:\n  log_retain_mib: -1\n",
		"firewall:\n  log_retain_days: -1\n",
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("%q loaded", bad)
		}
	}
}
