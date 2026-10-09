package daemon

import (
	"os"
	"path/filepath"
	"testing"
)

func loadContainersConfig(t *testing.T, body string) (*Config, error) {
	t.Helper()
	cp := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITEVIRT_CONFIG", cp)
	if err := os.WriteFile(cp, []byte("host_name: h\n"+body), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadConfig()
}

func TestLoadConfig_ContainersDefaults(t *testing.T) {
	cfg, err := loadContainersConfig(t, "")
	if err != nil {
		t.Fatal(err)
	}
	c := cfg.Containers
	if c.DefaultPidsMax != 4096 || c.IDMapBase != 1_000_000_000 || c.IDMapRanges != 30000 || c.IDMappedRootfs != "auto" {
		t.Fatalf("defaults = %+v", c)
	}
	cfg, err = loadContainersConfig(t, "containers:\n  default_pids_max: 0\n  idmap_base: 2000000000\n  idmap_ranges: 100\n  idmapped_rootfs: \"off\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if c := cfg.Containers; c.DefaultPidsMax != 0 || c.IDMapBase != 2_000_000_000 || c.IDMapRanges != 100 || c.IDMappedRootfs != "off" {
		t.Fatalf("set = %+v", c)
	}
}

func TestLoadConfig_ContainersRefusesBadValues(t *testing.T) {
	for _, body := range []string{
		"containers:\n  idmapped_rootfs: maybe\n",
		"containers:\n  idmap_base: 1000\n",                              // overlaps the host's own ids
		"containers:\n  idmap_base: 4000000000\n  idmap_ranges: 30000\n", // past 2^32
		"containers:\n  default_pids_max: -5\n",
		"containers:\n  idmap_ranges: -1\n",
	} {
		if _, err := loadContainersConfig(t, body); err == nil {
			t.Errorf("accepted %q", body)
		}
	}
}
