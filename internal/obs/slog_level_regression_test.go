package obs

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestSetup_NoEndpointNoExplicitFormat_RealWarnKeepsLevelAndAttrs reproduces
// the real lab defect end to end: a daemon boots with no otlp_endpoint and no
// explicit telemetry.log_level/log_format (the ordinary default install), and
// a slog.Warn call downstream (internal/grpcapi/migrate_cold_fence.go's
// stale-start-lease warning, in production) must still reach the pipeline as
// a real WARN record with its attrs intact — not as a single flattened INFO
// line with "WARN" and "vm=..." folded into free text.
//
// On 1c105363 this fails: Setup left slog.Default() as Go's stock handler in
// this exact configuration, which writes the whole record (level token +
// message + attrs) as one string via the "log" package — no distinct
// level=/vm= fields for anything downstream to parse.
func TestSetup_NoEndpointNoExplicitFormat_RealWarnKeepsLevelAndAttrs(t *testing.T) {
	cleanEnv(t)
	beforeDefault := slog.Default()
	t.Cleanup(func() { slog.SetDefault(beforeDefault) })

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	origStderr := os.Stderr
	os.Stderr = w
	restored := false
	restoreStderr := func() {
		if restored {
			return
		}
		restored = true
		os.Stderr = origStderr
		_ = w.Close()
	}
	t.Cleanup(restoreStderr)

	setup(t, Config{ServiceName: "lab-repro"})

	slog.Warn("cold migration: could not renew the VM's start lease",
		"vm", "r1l", "held_by", "node-4")

	restoreStderr()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	line := string(out)

	if !strings.Contains(line, "level=WARN") {
		t.Errorf("captured pipeline output %q has no level=WARN field; the level was lost/flattened", line)
	}
	if !strings.Contains(line, "vm=r1l") {
		t.Errorf("captured pipeline output %q has no vm=r1l attribute; attrs were flattened into the message text", line)
	}
}
