package obs

import (
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// provide-telemetry 0.11 treats `version` as a reserved wire name: with a
// service version configured it stamps service.version and drops a caller's
// bare `version` attribute. The four litevirt call sites that logged a CRL
// number, a schema number and a path under that key were renamed; this pins
// that the new names survive on a record while the bare key does not.
func TestDaemonLog_RenamedVersionFieldsSurvive(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt", Version: "v9.9.9", HostName: "node-3"}, func() {
		slog.Warn("cluster CRL published", "crl_version", 7, "installed_locally", true)
		slog.Warn("installed the cluster CRL union", "crl_version", 8, "members", 3)
		slog.Info("schema initialized", "schema_version", 42, "ledger", 5)
		slog.Error("image pointer missing", "image", "ubuntu", "image_version_path", "/images/ubuntu/x.qcow2")
		slog.Info("bare version key", "version", "caller-supplied")
	})
	for _, c := range []struct{ msg, key, val string }{
		{"cluster CRL published", "crl_version", "7"},
		{"installed the cluster CRL union", "crl_version", "8"},
		{"schema initialized", "schema_version", "42"},
		{"image pointer missing", "image_version_path", "/images/ubuntu/x.qcow2"},
	} {
		line := lineWith(lines, c.msg)
		if line == "" {
			t.Fatalf("no journal line for %q in %q", c.msg, lines)
		}
		if got := logfmtFields(line)[c.key]; got != c.val {
			t.Errorf("%q: %s=%q, want %q (line %q)", c.msg, c.key, got, c.val, line)
		}
	}
	// The reason for the rename: the vendor owns the bare key once a version
	// is configured, so a caller value cannot be relied on to survive.
	line := lineWith(lines, "bare version key")
	if strings.Contains(line, "caller-supplied") {
		t.Errorf("caller's bare version survived; the reserved-field premise changed, revisit the renames: %q", line)
	}
	// The build version logged bare at startup is carried by the stamp.
	if !strings.Contains(line, "v9.9.9") {
		t.Errorf("stamped service version v9.9.9 missing from record: %q", line)
	}
}

// Nothing in litevirt may log a bare "version" slog key again, except the two
// call sites that log the build version, which the stamped service.version
// already carries. Scans slog calls (also multi-line) across the repo.
func TestNoBareVersionSlogKey(t *testing.T) {
	re := regexp.MustCompile(`(?s)slog\.(?:Debug|Info|Warn|Error)\((?:[^()]|\([^()]*\))*?"version"\s*,`)
	allowed := map[string]bool{
		"cmd/litevirt/daemon.go":              true,
		"internal/daemon/watchdog_upgrade.go": true,
	}
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "gen" || n == ".claude" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if re.Match(b) && !allowed[filepath.ToSlash(rel)] {
			t.Errorf("%s logs a bare \"version\" slog key; provide-telemetry >= 0.11 drops it when a service version is set. Rename it (crl_version, schema_version, ...)", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// PROVIDE_LOG_INCLUDE_CALLER defaults true in provide-telemetry 0.9+, which
// adds filename/lineno to every record. Through litevirt's gRPC and stdlib log
// bridges that reports adapter frames and lengthens every journald line, so
// obs defaults it off; an operator can still opt in.
func TestSetup_IncludeCallerDefaultsOff(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt", HostName: "node-3"}, func() {
		slog.Info("caller probe")
	})
	line := lineWith(lines, "caller probe")
	if line == "" {
		t.Fatalf("no journal line: %q", lines)
	}
	f := logfmtFields(line)
	if _, ok := f["filename"]; ok {
		t.Errorf("filename on a default record: %q", line)
	}
	if _, ok := f["lineno"]; ok {
		t.Errorf("lineno on a default record: %q", line)
	}
	if v, ok := os.LookupEnv("PROVIDE_LOG_INCLUDE_CALLER"); !ok || v != "false" {
		t.Errorf("PROVIDE_LOG_INCLUDE_CALLER=%q (set=%v), want the obs default false", v, ok)
	}
}

func TestSetup_IncludeCallerOperatorOptIn(t *testing.T) {
	cleanEnv(t)
	t.Setenv("PROVIDE_LOG_INCLUDE_CALLER", "true")
	lines := captureDaemonStderrEnv(t, Config{ServiceName: "litevirt", HostName: "node-3"}, func() {
		slog.Info("caller probe")
	})
	line := lineWith(lines, "caller probe")
	f := logfmtFields(line)
	if f["filename"] == "" || f["lineno"] == "" {
		t.Errorf("operator opt-in produced no filename/lineno: %q", line)
	}
}
