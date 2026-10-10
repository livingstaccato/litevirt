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

// R3-M3: an explicit file_restore.uid_base inside the containers' id-map
// range is refused at load; with the default base the daemon still starts
// (file restore itself then refuses, naming the overlap).
func TestLoadConfig_FileRestoreUIDBaseVsContainers(t *testing.T) {
	if _, err := loadConfigYAML(t, "host_name: h\ncontainers:\n  idmap_base: 2000000000\nfile_restore:\n  uid_base: 3800000000\n"); err == nil ||
		!strings.Contains(err.Error(), "file_restore.uid_base") || !strings.Contains(err.Error(), "idmap") {
		t.Errorf("uid_base inside the container range: %v", err)
	}
	if _, err := loadConfigYAML(t, "host_name: h\ncontainers:\n  idmap_base: 2000000000\n"); err != nil {
		t.Errorf("the default uid_base must not stop the daemon: %v", err)
	}
	if _, err := loadConfigYAML(t, "host_name: h\ncontainers:\n  idmap_base: 2000000000\nfile_restore:\n  enabled: false\n  uid_base: 3800000000\n"); err != nil {
		t.Errorf("file restore off: %v", err)
	}
	if _, err := loadConfigYAML(t, "host_name: h\nfile_restore:\n  uid_base: 3900000000\n"); err != nil {
		t.Errorf("a uid_base clear of the default container range: %v", err)
	}
}

// Nit 6: file_restore.allow_unsandboxed lifts only the barriers it names;
// true is every one; an unknown name refuses to load.
func TestLoadConfig_FileRestoreAllowUnsandboxed(t *testing.T) {
	for _, c := range []struct {
		yaml string
		want UnsandboxedBarriers
	}{
		{"", UnsandboxedBarriers{}},
		{"  allow_unsandboxed: false\n", UnsandboxedBarriers{}},
		{"  allow_unsandboxed: true\n", UnsandboxedBarriers{Seccomp: true, MAC: true, Root: true}},
		{"  allow_unsandboxed: [seccomp]\n", UnsandboxedBarriers{Seccomp: true}},
		{"  allow_unsandboxed:\n    - mac\n    - root\n", UnsandboxedBarriers{MAC: true, Root: true}},
	} {
		cfg, err := loadConfigYAML(t, "host_name: h\nfile_restore:\n  memory_mib: 512\n"+c.yaml)
		if err != nil {
			t.Errorf("%q: %v", c.yaml, err)
			continue
		}
		if cfg.FileRestore.AllowUnsandboxed != c.want {
			t.Errorf("%q: parsed %+v, want %+v", c.yaml, cfg.FileRestore.AllowUnsandboxed, c.want)
		}
	}
	for _, bad := range []string{"  allow_unsandboxed: [apparmor]\n", "  allow_unsandboxed: maybe\n"} {
		if _, err := loadConfigYAML(t, "host_name: h\nfile_restore:\n"+bad); err == nil || !strings.Contains(err.Error(), "allow_unsandboxed") {
			t.Errorf("%q: want a load error naming allow_unsandboxed, got %v", bad, err)
		}
	}
	cfg, _ := loadConfigYAML(t, "host_name: h\nfile_restore:\n  allow_unsandboxed: [seccomp]\n  allow_shared_run_as: true\n")
	if got := strings.Join(cfg.FileRestore.ReducedBarrierKeys(), "|"); got != "allow_unsandboxed: [seccomp]|allow_shared_run_as" {
		t.Errorf("reduced-barrier keys %q", got)
	}
	cfg, _ = loadConfigYAML(t, "host_name: h\nfile_restore:\n  enabled: false\n  allow_unsandboxed: true\n")
	if keys := cfg.FileRestore.ReducedBarrierKeys(); len(keys) != 0 {
		t.Errorf("file restore off still reports %v", keys)
	}
}
