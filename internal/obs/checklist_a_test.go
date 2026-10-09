package obs

import (
	"context"
	"testing"
)

// Checklist (a) — no OTLP endpoint on a cold boot:
//
//	TracingActive false, zero otel in the RPC path (the journal shape and
//	the unredacted capability= line are pinned in journal_shape_test.go and
//	TestSetup_NoEndpoint_CapabilityAttrNotRedacted). Runnable on macOS (no libvirt,
//	no cluster).
//
//	go test ./internal/obs/ -count=1 -v -run TestChecklist_A
func TestChecklist_A_NoEndpoint_ZeroOtelCost(t *testing.T) {
	cleanEnv(t)

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

	// 2. Span is safe / no-op-ish with tracing off (must not panic).
	ctx, span := Span(context.Background(), "checklist.a")
	span.End()
	_ = ctx
}
