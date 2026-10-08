package slogtest

import (
	"bytes"
	"log"
	"log/slog"
	"strings"
	"testing"
)

// TestSwap_RestoresStdlibLogAndSlogDefault proves Swap closes the hole the
// naive prev/SetDefault/restore pattern leaves open: after the subtest below
// ends (and its t.Cleanup has run), both slog.Default() and the stdlib log
// package's writer/flags/prefix must be back to what they were before Swap
// ran — not left pointing at the subtest's own (by then out of scope)
// buffer, which is exactly what the naive pattern does when the original
// slog.Default() wraps the stock handler (see the package doc).
func TestSwap_RestoresStdlibLogAndSlogDefault(t *testing.T) {
	origWriter := log.Writer()
	origFlags := log.Flags()
	origPrefix := log.Prefix()
	origDefault := slog.Default()

	t.Run("swap", func(t *testing.T) {
		var buf bytes.Buffer
		Swap(t, slog.New(slog.NewTextHandler(&buf, nil)))

		slog.Info("via slog")
		log.Print("via stdlib log")

		out := buf.String()
		if !strings.Contains(out, "via slog") {
			t.Fatalf("Swap did not install the new slog default: %q", out)
		}
		if !strings.Contains(out, "via stdlib log") {
			t.Fatalf("Swap did not rewire stdlib log's output to the new handler: %q", out)
		}
	})
	// The subtest's t.Cleanup (registered inside Swap) has now run.

	if slog.Default() != origDefault {
		t.Error("Swap did not restore slog.Default() after the test ended")
	}
	if log.Writer() != origWriter {
		t.Error("Swap did not restore stdlib log's output writer after the test ended — " +
			"this is the exact misrouting the package doc describes")
	}
	if log.Flags() != origFlags {
		t.Error("Swap did not restore stdlib log's flags after the test ended")
	}
	if log.Prefix() != origPrefix {
		t.Error("Swap did not restore stdlib log's prefix after the test ended")
	}
}

// TestSaveRestore_RestoresAroundCodeThatCallsSetDefaultItself covers the
// other shape: the code under test (not the test itself) calls
// slog.SetDefault, as internal/obs.Setup and cmd/litevirt's
// bootstrapDefaultLogger do. SaveRestore must still put everything back.
func TestSaveRestore_RestoresAroundCodeThatCallsSetDefaultItself(t *testing.T) {
	origWriter := log.Writer()
	origFlags := log.Flags()
	origPrefix := log.Prefix()
	origDefault := slog.Default()

	t.Run("save-restore", func(t *testing.T) {
		SaveRestore(t)

		var buf bytes.Buffer
		// Stands in for code under test installing its own default logger.
		slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))

		slog.Info("via slog")
		log.Print("via stdlib log")

		out := buf.String()
		if !strings.Contains(out, "via slog") || !strings.Contains(out, "via stdlib log") {
			t.Fatalf("setup under test did not route through the installed handler: %q", out)
		}
	})

	if slog.Default() != origDefault {
		t.Error("SaveRestore did not restore slog.Default() after the test ended")
	}
	if log.Writer() != origWriter {
		t.Error("SaveRestore did not restore stdlib log's output writer after the test ended")
	}
	if log.Flags() != origFlags {
		t.Error("SaveRestore did not restore stdlib log's flags after the test ended")
	}
	if log.Prefix() != origPrefix {
		t.Error("SaveRestore did not restore stdlib log's prefix after the test ended")
	}
}
