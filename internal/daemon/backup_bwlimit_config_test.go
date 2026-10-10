package daemon

import (
	"strings"
	"testing"
)

func TestLoadConfig_BackupBWLimits(t *testing.T) {
	cfg, err := loadConfigYAML(t, "host_name: h\nbackup_bwlimits:\n  main: 100MiB\n  offsite: \"512K\"\n  free: \"0\"\n")
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	got, err := cfg.BackupBandwidthLimits()
	if err != nil {
		t.Fatal(err)
	}
	if got["main"] != 100<<20 || got["offsite"] != 512<<10 {
		t.Fatalf("limits = %v", got)
	}
	if _, ok := got["free"]; ok {
		t.Fatal("a 0 limit must mean no limit, not a zero-rate throttle")
	}
}

// A typo'd limit fails load: running unlimited while the operator believes a
// limit is in place is the failure to avoid.
func TestLoadConfig_BackupBWLimitsInvalid(t *testing.T) {
	_, err := loadConfigYAML(t, "host_name: h\nbackup_bwlimits:\n  main: fast\n")
	if err == nil || !strings.Contains(err.Error(), "backup_bwlimits.main") {
		t.Fatalf("want a load error naming backup_bwlimits.main, got %v", err)
	}
}

func TestLoadConfig_FileRestore(t *testing.T) {
	cfg, err := loadConfigYAML(t, "host_name: h\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.FileRestore.On() || cfg.FileRestore.ExtractLimit() != 0 {
		t.Fatalf("defaults: on=%v limit=%d", cfg.FileRestore.On(), cfg.FileRestore.ExtractLimit())
	}
	cfg, err = loadConfigYAML(t, "host_name: h\nfile_restore:\n  enabled: false\n  max_extract_bytes: 2G\n  memory_mib: 1024\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FileRestore.On() || cfg.FileRestore.ExtractLimit() != 2<<30 || cfg.FileRestore.MemoryMiB != 1024 {
		t.Fatalf("parsed %+v", cfg.FileRestore)
	}
	for _, bad := range []string{
		"file_restore:\n  memory_mib: 128\n",
		"file_restore:\n  max_extract_bytes: lots\n",
		"file_restore:\n  max_sessions: -1\n",
	} {
		if _, err := loadConfigYAML(t, "host_name: h\n"+bad); err == nil || !strings.Contains(err.Error(), "file_restore") {
			t.Errorf("%q: want a load error naming file_restore, got %v", bad, err)
		}
	}
}
