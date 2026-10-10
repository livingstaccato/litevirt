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
