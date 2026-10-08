package obs

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
)

// A bogus operator-exported LITEVIRT_TRACES_SAMPLE_RATE must not silently
// discard a valid configured sample_rate. obs rejects the env value, then
// falls back to the config rate (already range-checked by normalizeTelemetry)
// rather than the library default (1.0) — otherwise a stale/malformed override
// flips sampling back to 100% while the operator believes it is capped.
func TestSetup_InvalidSampleRateEnv_FallsBackToConfigRate(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_TRACES_SAMPLE_RATE", "abc")
	setup(t, Config{ServiceName: "s", OTLPEndpoint: "http://127.0.0.1:4318", SampleRate: f64p(0.1)})

	if got := os.Getenv("PROVIDE_SAMPLING_TRACES_RATE"); got != "0.1" {
		t.Errorf("PROVIDE_SAMPLING_TRACES_RATE = %q; a bogus env override must fall back to the configured 0.1, not the library default (100%%)", got)
	}
}

// With no endpoint, an operator who sets the log format only via env
// (LITEVIRT_LOG_FORMAT=json, cfg.LogFormat empty) must still get JSON records —
// the resolved format lives in PROVIDE_LOG_FORMAT, not the cfg field, so
// building the handler from cfg alone would silently drop it.
func TestSetup_NoEndpointEnvJSONFormat_WritesJSONRecords(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_LOG_FORMAT", "json")
	lines := captureDaemonStderrEnv(t, Config{ServiceName: "s"}, func() {
		slog.Warn("env json probe", "k", "v")
	})
	var rec map[string]any
	if err := json.Unmarshal([]byte(lineWith(lines, "env json probe")), &rec); err != nil {
		t.Fatalf("env-set LITEVIRT_LOG_FORMAT=json did not produce JSON records: %v (%q)", err, lines)
	}
	if rec["level"] != "WARN" || rec["k"] != "v" {
		t.Fatalf("JSON record not structured: %v", rec)
	}
}

// With no endpoint, an operator who sets the log level only via env
// (LITEVIRT_LOG_LEVEL=DEBUG, cfg.LogLevel empty) must get a handler that
// actually emits DEBUG. Building the handler from the empty cfg field drops to
// INFO and swallows exactly the diagnostics the operator turned on.
func TestSetup_NoEndpointEnvLogLevel_HandlerHonorsLevel(t *testing.T) {
	cleanEnv(t)
	_ = os.Setenv("LITEVIRT_LOG_LEVEL", "DEBUG")
	setup(t, Config{ServiceName: "s"})

	if !slog.Default().Handler().Enabled(context.Background(), slog.LevelDebug) {
		t.Error("handler does not honor env-set LITEVIRT_LOG_LEVEL=DEBUG; debug records would be dropped")
	}
}
