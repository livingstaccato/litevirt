package main

import (
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/testkit/slogtest"
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
	// bootstrapDefaultLogger calls slog.SetDefault itself, so this must save
	// and restore around it, not just save/restore slog.Default() — see
	// internal/testkit/slogtest's doc for why a naive restore here would
	// permanently misroute stdlib log's output for the rest of this test
	// binary whenever slog.Default() starts out as Go's stock handler.
	slogtest.SaveRestore(t)

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

// The bootstrap logger masks secret-keyed attributes as obs.Setup's pipeline
// does (final whole-branch review M2): every LoadConfig caller and every
// one-shot CLI command logs through it, and the masking is documented to run
// in every mode. A non-secret logged under a descriptive key is untouched.
func TestBootstrapDefaultLogger_MasksSecretKeys(t *testing.T) {
	slogtest.SaveRestore(t)

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
	slog.Warn("login", "token", "s3cr3t-tok", "bmc_password", "hunter2", "config_key", "daemon.x")
	slog.With("api_key", "ak-123").Info("with attrs")

	restoreStderr()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stderr: %v", err)
	}
	text := string(out)
	for _, secret := range []string{"s3cr3t-tok", "hunter2", "ak-123"} {
		if strings.Contains(text, secret) {
			t.Errorf("bootstrap output carries the secret %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "token=[REDACTED]") {
		t.Errorf("bootstrap output %q has no token=[REDACTED]", text)
	}
	if !strings.Contains(text, "config_key=daemon.x") {
		t.Errorf("bootstrap output %q masked or dropped the non-secret config_key", text)
	}
}
