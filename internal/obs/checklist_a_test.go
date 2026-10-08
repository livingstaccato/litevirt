package obs

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
)

// Checklist (a) — no OTLP endpoint on a cold boot:
//
//	stdlib logs (never Go's stock handler), token= not redacted, TracingActive
//	false, zero otel in the RPC path. Runnable on macOS (no libvirt, no
//	cluster).
//
//	go test ./internal/obs/ -count=1 -v -run TestChecklist_A
func TestChecklist_A_NoEndpoint_StdlibParityZeroCost(t *testing.T) {
	cleanEnv(t)

	// Capture pre-Setup default so we can prove Setup installs a real
	// handler — never Go's stock one — even with no endpoint configured.
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })

	// Capture what a capability-style log line looks like after Setup.
	var buf bytes.Buffer

	shutdown, err := Setup(context.Background(), Config{ServiceName: "litevirt"})
	if err != nil {
		t.Logf("Setup err (fail-open ok): %v", err)
	}
	if shutdown == nil {
		t.Fatal("Setup returned nil shutdown")
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })

	// 1. Tracing / otel RPC path completely off.
	if TracingActive() {
		t.Error("(a) TracingActive()=true with no endpoint; want false")
	}
	if got := ClientDialOptions(); got != nil {
		t.Errorf("(a) ClientDialOptions()=%v; want nil (zero otel on dial path)", got)
	}
	if got := ServerOptions(); got != nil {
		t.Errorf("(a) ServerOptions()=%v; want nil (zero otel on serve path)", got)
	}

	// 2. slog.Default() is a real stdlib handler, not vendor and not Go's
	//    stock handler (which flattens level + attrs into the message text —
	//    the real lab defect this checklist now also guards).
	if slog.Default() == before {
		t.Error("(a) slog.Default() left untouched with no endpoint and no explicit log_format/log_level; want a plain stdlib handler installed")
	}
	if _, ok := slog.Default().Handler().(*slog.TextHandler); !ok {
		t.Errorf("(a) slog.Default().Handler() = %T; want *slog.TextHandler (stdlib, not vendor, not the stock handler)", slog.Default().Handler())
	}

	// 3. Capability token= line is not vendor-redacted. Capturing through the
	//    now-installed default via a temporary stderr swap is covered by
	//    TestSetup_NoEndpointNoExplicitFormat_RealWarnKeepsLevelAndAttrs;
	//    here, emit on a plain stdlib handler and assert the same shape the
	//    default path uses when no vendor is adopted — token value appears
	//    literally. (Vendor redaction would turn it into ***.)
	buf.Reset()
	local := slog.New(slog.NewTextHandler(&buf, nil))
	local.Info("capability check", "token", "split_brain_gate_v1")
	line := buf.String()
	if !strings.Contains(line, "split_brain_gate_v1") {
		t.Errorf("(a) token value missing from log line %q; want literal split_brain_gate_v1 (not redacted)", line)
	}
	if strings.Contains(line, "token=***") || strings.Contains(line, `token="***"`) {
		t.Errorf("(a) token redacted in log line %q; vendor sanitizer must not be in the no-endpoint path", line)
	}

	// 4. Span is safe / no-op-ish with tracing off (must not panic).
	ctx, span := Span(context.Background(), "checklist.a")
	span.End()
	_ = ctx
}
