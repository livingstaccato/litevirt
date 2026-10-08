package obs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"math"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	oteltrace "go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/stats"
)

// ---------------------------------------------------------------------------
// Adversarial / property-style guards for the pass-2 telemetry fixes.
// Hostile inputs and ordering games — not happy-path coverage.
// ---------------------------------------------------------------------------

func TestValidEndpoint_AdversarialTable(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"   ", false},
		{"otel-collector:4317", false},
		{"otel-collector:4318", false},
		{"localhost:4318", false},
		{"//host:4318", false},
		{"ftp://collector:4318", false},
		{"grpc://collector:4317", false},
		{"http://", false},
		{"https://", false},
		{"http:///path", false},
		{"http:///", false},
		{"://missing-scheme-host", false},
		{"http://host:4318", true},
		{"https://host:4318", true},
		{"http://127.0.0.1:4318", true},
		{"https://[::1]:4318", true},
		{"http://collector.example:4318/v1/traces", true},
		// URL userinfo is rejected — credentials belong in LITEVIRT_OTEL_HEADERS.
		{"http://user:pass@collector:4318", false},
		{"http://user@collector:4318", false},
		// net/url.Parse lowercases the scheme, so HTTP:// is accepted as http.
		{"HTTP://HOST:4318", true},
		{"http://host:4318?x=1", true},
		{"http://host:4318#frag", true},
	}
	for _, tc := range cases {
		if got := validEndpoint(tc.in); got != tc.want {
			t.Errorf("validEndpoint(%q) = %v; want %v", tc.in, got, tc.want)
		}
	}
}

func TestSafeEndpointForLog_RedactsUserinfo(t *testing.T) {
	got := SafeEndpointForLog("http://u:secret@host:4318/path")
	if strings.Contains(got, "secret") || strings.Contains(got, "u:") {
		t.Errorf("SafeEndpointForLog leaked credentials: %q", got)
	}
	if !strings.Contains(got, "REDACTED") {
		t.Errorf("SafeEndpointForLog(%q) missing REDACTED placeholder", got)
	}
	if plain := SafeEndpointForLog("http://host:4318"); plain != "http://host:4318" {
		t.Errorf("SafeEndpointForLog plain = %q; want unchanged", plain)
	}
	if plain := SafeEndpointForLog("not a url"); plain != "not a url" {
		t.Errorf("SafeEndpointForLog non-url = %q; want unchanged", plain)
	}
}

func TestValidSampleRate_AdversarialTable(t *testing.T) {
	cases := []struct {
		in      string
		wantOK  bool
		wantVal float64
	}{
		{"", false, 0},
		{" ", false, 0},
		{"NaN", false, 0},
		{"nan", false, 0},
		{"Inf", false, 0},
		{"+Inf", false, 0},
		{"-Inf", false, 0},
		{"-1", false, 0},
		{"1.0000001", false, 0},
		{"7", false, 0},
		{"1e9", false, 0},
		{"abc", false, 0},
		{"0.5x", false, 0},
		{"0.5 ", false, 0},
		{" 0.5", false, 0},
		{"0", true, 0},
		{"0.0", true, 0},
		{"1", true, 1},
		{"1.0", true, 1},
		{"0.25", true, 0.25},
		{"1e-1", true, 0.1},
		{"+0.5", true, 0.5},
	}
	for _, tc := range cases {
		got, ok := validSampleRate(tc.in)
		if ok != tc.wantOK {
			t.Errorf("validSampleRate(%q) ok=%v; want %v", tc.in, ok, tc.wantOK)
			continue
		}
		if ok && got != tc.wantVal {
			t.Errorf("validSampleRate(%q) = %v; want %v", tc.in, got, tc.wantVal)
		}
	}
	// -0 is IEEE-legal; Go treats -0 < 0 as false, so it currently passes.
	// Pin the actual behavior so a future clamp is intentional.
	if r, ok := validSampleRate("-0"); !ok || r != 0 {
		t.Errorf("validSampleRate(\"-0\") = (%v, %v); want (0, true) under current IEEE rules", r, ok)
	}
	_ = math.NaN()
}

// LITEVIRT_OTEL_ENDPOINT with a schemeless value must win over a valid config
// endpoint (LITEVIRT_* precedence) AND still be rejected — export off, not
// "config wins because env is invalid".
func TestSetup_InvalidLitevirtEndpoint_BeatsValidConfig_DisablesExport(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_OTEL_ENDPOINT", "otel-collector:4317")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318"})

	if TracingActive() {
		t.Error("invalid LITEVIRT_OTEL_ENDPOINT must disable tracing even when config endpoint is valid")
	}
	if got := ClientDialOptions(); got != nil {
		t.Error("ClientDialOptions must be nil when env endpoint is invalid")
	}
	if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got != "" {
		t.Errorf("OTEL_EXPORTER_OTLP_ENDPOINT left as %q; invalid env must be unset", got)
	}
	if got := os.Getenv("PROVIDE_LOG_OTLP_ENABLED"); got != "" {
		t.Errorf("PROVIDE_LOG_OTLP_ENABLED left as %q; must not stay enabled", got)
	}
}

// Invalid sample-rate env must not feed 7 into TraceIDRatioBased (which clamps
// to AlwaysSample and looks "healthy") AND must not skip past a valid
// configured rate to the library default: a configured SampleRate=0 (sampling
// disabled) must win over a bogus override, not be flipped to a 100% firehose.
func TestSetup_InvalidSampleRateEnv_FallsBackToConfiguredRate(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	// Env maps first to "7"; validation rejects and unsets it, then the fix
	// re-applies the range-checked config value (0) rather than leaving the
	// library default (1.0).
	_ = os.Setenv("LITEVIRT_TRACES_SAMPLE_RATE", "7")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL, SampleRate: f64p(0)})

	if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "0" {
		t.Fatalf("PROVIDE_SAMPLING_TRACES_RATE = %q after invalid env; want \"0\" (configured rate as fallback, not library default)", got)
	}
	ctx, span := Span(context.Background(), "rate-fallback")
	sc := oteltrace.SpanContextFromContext(ctx)
	span.End()
	if sc.IsSampled() {
		t.Error("configured sample_rate=0 must disable sampling; a bogus env override must not flip it to a 100% firehose")
	}
}

func TestSetup_ExoticButValidEndpoints_ActivateTracing(t *testing.T) {
	cases := []string{
		"https://127.0.0.1:4318",
		"http://[::1]:4318",
		"http://127.0.0.1:5080/api/default",
	}
	for _, ep := range cases {
		t.Run(ep, func(t *testing.T) {
			cleanEnv(t)
			setup(t, Config{ServiceName: "s", OTLPEndpoint: ep})
			if !TracingActive() {
				t.Errorf("TracingActive()=false for valid endpoint %q", ep)
			}
		})
	}
}

// Credential scrub must not remove endpoint or resource attrs — only header secrets.
func TestSetup_CredentialScrub_PreservesNonSecretEnv(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	t.Setenv("LITEVIRT_OTEL_HEADERS", "Authorization=Bearer secret-xyz")
	setup(t, Config{
		ServiceName: "s", Version: "9.9.9", HostName: "node-a",
		OTLPEndpoint: srv.URL, SampleRate: f64p(1),
	})

	for _, k := range credentialEnvVars {
		if got := os.Getenv(k); got != "" {
			t.Errorf("credential env %s still set to %q after Setup", k, got)
		}
	}
	if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got != srv.URL {
		t.Errorf("endpoint scrubbed or lost: got %q want %q", got, srv.URL)
	}
	if !strings.Contains(os.Getenv("OTEL_RESOURCE_ATTRIBUTES"), "host.name=node-a") {
		t.Errorf("resource attrs lost: %q", os.Getenv("OTEL_RESOURCE_ATTRIBUTES"))
	}
	if got := os.Getenv("PROVIDE_TELEMETRY_VERSION"); got != "9.9.9" {
		t.Errorf("version lost: %q", got)
	}
}

func TestTraceFilter_AdversarialMethodNames(t *testing.T) {
	for _, m := range []string{
		"/litevirt.v1.LiteVirt/Ping",
		"/anything/PushMutations",
		"GetHostHealth",
	} {
		if traceFilter(&stats.RPCTagInfo{FullMethodName: m}) {
			t.Errorf("traceFilter(%q)=true; want false (noisy)", m)
		}
	}
	for _, m := range []string{
		"/litevirt.v1.LiteVirt/MigrateVM",
		"/litevirt.v1.LiteVirt/CreateVM",
		"/litevirt.v1.LiteVirt/InspectVM",
		"/litevirt.v1.LiteVirt/PingExtra",
		"/litevirt.v1.LiteVirt/NotPing",
		"/x/pushmutations",
		"",
		"/",
	} {
		if !traceFilter(&stats.RPCTagInfo{FullMethodName: m}) {
			t.Errorf("traceFilter(%q)=false; want true (not noisy)", m)
		}
	}
}

// ParentBased: child of unsampled remote parent stays unsampled even at rate 1.0.
func TestSetup_ParentBased_UnsampledParentStaysUnsampled(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL, SampleRate: f64p(1)})

	parentSC := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID:    mustTraceID(t, "0102030405060708090a0b0c0d0e0f10"),
		SpanID:     mustSpanID(t, "0102030405060708"),
		TraceFlags: 0,
		Remote:     true,
	})
	parentCtx := oteltrace.ContextWithSpanContext(context.Background(), parentSC)
	ctx, span := Span(parentCtx, "child.of.unsampled")
	childSC := oteltrace.SpanContextFromContext(ctx)
	span.End()

	if childSC.IsSampled() {
		t.Error("child of remote unsampled parent was sampled; ParentBased must honor parent decision")
	}
}

func TestTracingOptions_ConcurrentWithActiveFlip_RaceSafe(t *testing.T) {
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = ClientDialOptions()
					_ = ServerOptions()
					_ = TracingActive()
				}
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		tracingActive.Store(i%2 == 0)
	}
	close(stop)
	wg.Wait()
	tracingActive.Store(false)
}

func TestSetup_InjectedProvider_IsSDKTracerProvider(t *testing.T) {
	cleanEnv(t)
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL, SampleRate: f64p(0.5)})

	tp := otel.GetTracerProvider()
	if _, ok := tp.(*sdktrace.TracerProvider); !ok {
		t.Errorf("otel.GetTracerProvider() type = %T; want *sdktrace.TracerProvider", tp)
	}
}

// litevirt's capability lines carry capability=<name>, which is not a
// secret; the local journal line must show it literally, not redacted.
func TestSetup_NoEndpoint_CapabilityAttrNotRedacted(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "s"}, func() {
		slog.Info("capability check", "capability", "split_brain_gate_v1")
	})
	line := lineWith(lines, "capability check")
	if logfmtFields(line)["capability"] != "split_brain_gate_v1" {
		t.Fatalf("capability attribute redacted or missing: %q", line)
	}
}

// Off → on adopts a new (exporting) logger.
func TestSetup_OffThenOn_AdoptsVendorLogger(t *testing.T) {
	cleanEnv(t)
	before := slog.Default()
	t.Cleanup(func() { slog.SetDefault(before) })
	setup(t, Config{ServiceName: "s"})
	off := slog.Default()
	srv, _ := otelHTTPServer(t)
	setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL})
	if slog.Default() == off {
		t.Error("second (on) Setup did not adopt a new logger")
	}
}

func TestSetup_MetricsForcedOff_WithEndpoint(t *testing.T) {
	t.Run("unset forces false", func(t *testing.T) {
		cleanEnv(t)
		srv, _ := otelHTTPServer(t)
		setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL})
		if got := os.Getenv("PROVIDE_METRICS_ENABLED"); got != "false" {
			t.Errorf("PROVIDE_METRICS_ENABLED=%q; want false", got)
		}
	})
	t.Run("operator true is preserved", func(t *testing.T) {
		cleanEnv(t)
		srv, _ := otelHTTPServer(t)
		_ = os.Setenv("PROVIDE_METRICS_ENABLED", "true")
		setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL})
		if got := os.Getenv("PROVIDE_METRICS_ENABLED"); got != "true" {
			t.Errorf("operator PROVIDE_METRICS_ENABLED clobbered: %q", got)
		}
	})
}

func TestSetup_SamplerEndpoints_ManyRoots(t *testing.T) {
	srv, _ := otelHTTPServer(t)

	t.Run("rate0", func(t *testing.T) {
		cleanEnv(t)
		setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL, SampleRate: f64p(0)})
		for i := 0; i < 50; i++ {
			ctx, span := Span(context.Background(), "r")
			if oteltrace.SpanContextFromContext(ctx).IsSampled() {
				span.End()
				t.Fatalf("sample %d sampled at rate 0", i)
			}
			span.End()
		}
	})
	t.Run("rate1", func(t *testing.T) {
		cleanEnv(t)
		setup(t, Config{ServiceName: "s", OTLPEndpoint: srv.URL, SampleRate: f64p(1)})
		for i := 0; i < 50; i++ {
			ctx, span := Span(context.Background(), "r")
			if !oteltrace.SpanContextFromContext(ctx).IsSampled() {
				span.End()
				t.Fatalf("sample %d unsampled at rate 1", i)
			}
			span.End()
		}
	})
}

func TestTraceExportErrors_ConcurrentIncrement_RaceSafe(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				traceExportErrors.Add(1)
				_ = ExportErrors()
				_ = Health()
			}
		}()
	}
	wg.Wait()
}

// Dead collector must not block Setup return (fail-open boot).
func TestSetup_DeadCollector_ReturnsPromptly(t *testing.T) {
	cleanEnv(t)
	t.Setenv("LITEVIRT_OTEL_TIMEOUT", "1")
	t.Setenv("LITEVIRT_OTEL_RETRIES", "0")
	t.Setenv("LITEVIRT_OTEL_SHUTDOWN_TIMEOUT", "1")

	done := make(chan struct{})
	go func() {
		defer close(done)
		shutdown, err := Setup(context.Background(), Config{
			ServiceName: "dead", OTLPEndpoint: "http://127.0.0.1:1", SampleRate: f64p(1),
		})
		if err != nil {
			t.Logf("Setup err (fail-open ok): %v", err)
		}
		if shutdown != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			_ = shutdown(ctx)
			cancel()
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Setup+shutdown against dead collector did not return within 10s")
	}
}

// Direct OTEL_EXPORTER_OTLP_ENDPOINT invalid value is cleared even without
// going through LITEVIRT_* mapping (finding 5 close-the-hole).
func TestSetup_DirectInvalidOTELEndpoint_UnsetAndTracingOff(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "grpc://collector:4317")
	_ = os.Setenv("PROVIDE_LOG_OTLP_ENABLED", "true")
	setup(t, Config{ServiceName: "s"})

	if TracingActive() {
		t.Error("grpc:// endpoint must not activate tracing")
	}
	if got := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); got != "" {
		t.Errorf("invalid direct OTEL endpoint survived: %q", got)
	}
	if got := os.Getenv("PROVIDE_LOG_OTLP_ENABLED"); got != "" {
		t.Errorf("PROVIDE_LOG_OTLP_ENABLED survived invalid endpoint: %q", got)
	}
}

// Explicit log_format=json with no endpoint must not redact capability=
// (the value sanitizer defaults off in every mode).
func TestSetup_NoEndpointJSON_CapabilityNotRedacted(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "s", LogFormat: "json"}, func() {
		slog.Info("gate", "capability", "split_brain_gate_v1")
	})
	var rec map[string]any
	if err := json.Unmarshal([]byte(lineWith(lines, `"gate"`)), &rec); err != nil {
		t.Fatalf("not a JSON record: %v (%q)", err, lines)
	}
	if rec["capability"] != "split_brain_gate_v1" {
		t.Fatalf("capability redacted or missing: %v", rec)
	}
}

func mustTraceID(t *testing.T, h string) oteltrace.TraceID {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 16 {
		t.Fatalf("bad trace id hex %q: %v", h, err)
	}
	var id oteltrace.TraceID
	copy(id[:], b)
	return id
}

func mustSpanID(t *testing.T, h string) oteltrace.SpanID {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != 8 {
		t.Fatalf("bad span id hex %q: %v", h, err)
	}
	var id oteltrace.SpanID
	copy(id[:], b)
	return id
}
