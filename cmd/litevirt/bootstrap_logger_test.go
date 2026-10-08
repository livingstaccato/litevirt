package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

// TestBootstrapDefaultLogger_RealWarnKeepsLevelAndAttrs reproduces the real
// lab defect for the CLI entrypoints that never call internal/obs.Setup at
// all (e.g. `litevirt gitops`, `litevirt schema-migrate`): before main()
// called bootstrapDefaultLogger, a slog.Warn in those commands fell straight
// through to Go's stock slog handler, which writes the whole record as one
// formatted string via the standard "log" package — the level folded into
// the text, attrs stringified after it — with no distinct level=/attr
// fields for anything downstream to parse.
func TestBootstrapDefaultLogger_RealWarnKeepsLevelAndAttrs(t *testing.T) {
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

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

	bootstrapDefaultLogger()
	slog.Warn("gitops: gh post failed", "sha", "abc123", "error", "boom")

	restoreStderr()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	line := string(out)

	if !strings.Contains(line, "level=WARN") {
		t.Errorf("captured output %q has no level=WARN field; the level was lost/flattened", line)
	}
	if !strings.Contains(line, "sha=abc123") {
		t.Errorf("captured output %q has no sha=abc123 attribute; attrs were flattened into the message text", line)
	}
}
