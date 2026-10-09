package obs

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// M2: with the vendor's line sanitizer off, attributes whose KEY names
// secret material are still masked, in every mode. Other attributes, and
// litevirt's non-secret capability names, stay literal.
func TestDaemonLog_SecretKeysRedacted(t *testing.T) {
	for _, format := range []string{"", "json"} {
		lines := captureDaemonStderr(t, Config{ServiceName: "litevirt", LogFormat: format}, func() {
			slog.Info("redact probe",
				"password", "hunter2", "Password", "hunter3", "ipmi_pass", "ipmi-pw", "ipmi_password", "ipmi-pw2",
				"token", "tok-123", "session_token", "sess-1", "secret", "shh", "client_secret", "shh2",
				"key", "k-1", "api_key", "ak-1", "private_key", "pk-1", "bearer", "brr", "authorization", "Bearer x",
				"keyring", "kr-1", "credentials", "cr-1",
				slog.Group("ipmi", "password", "grp-pw", "user", "admin"),
				"user", "alice", "capability", "split_brain_gate_v1", "host", "node-3")
		})
		line := lineWith(lines, "redact probe")
		if line == "" {
			t.Fatalf("format %q: no line: %q", format, lines)
		}
		for _, secret := range []string{"hunter2", "hunter3", "ipmi-pw", "tok-123", "sess-1", "shh", "k-1", "ak-1", "pk-1", "brr", "Bearer x", "kr-1", "cr-1", "grp-pw"} {
			if strings.Contains(line, secret) {
				t.Errorf("format %q: secret value %q printed: %s", format, secret, line)
			}
		}
		for _, keep := range []string{"alice", "split_brain_gate_v1", "node-3", "admin"} {
			if !strings.Contains(line, keep) {
				t.Errorf("format %q: non-secret value %q was masked: %s", format, keep, line)
			}
		}
		if format == "json" {
			var rec map[string]any
			if err := json.Unmarshal([]byte(line), &rec); err != nil {
				t.Fatalf("json: %v", err)
			}
			if rec["password"] != redactedValue {
				t.Errorf("password = %v, want %q", rec["password"], redactedValue)
			}
		}
	}
}

// A secret attached with Logger.With, and one from obs.Logger, is masked too.
func TestDaemonLog_SecretKeysRedactedOnWithAndNamedLogger(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt"}, func() {
		slog.Default().With("password", "with-pw").Info("with probe")
		Logger(t.Context(), "unit").Info("named probe", "token", "named-tok")
	})
	for _, c := range []struct{ msg, secret string }{{"with probe", "with-pw"}, {"named probe", "named-tok"}} {
		line := lineWith(lines, c.msg)
		if line == "" || strings.Contains(line, c.secret) {
			t.Errorf("%q: secret printed or line missing: %q", c.msg, line)
		}
	}
}

// m6: the OTLP export path carries the masked value too: the redactor sits
// in front of the handler that both prints and exports.
func TestOTLPExport_SecretKeysRedacted(t *testing.T) {
	cleanEnv(t)
	var mu sync.Mutex
	var bodies bytes.Buffer
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var rd io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			if zr, err := gzip.NewReader(r.Body); err == nil {
				rd = zr
			}
		}
		b, _ := io.ReadAll(rd)
		mu.Lock()
		bodies.Write(b)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })
	shutdown, err := Setup(context.Background(), Config{ServiceName: "litevirt", OTLPEndpoint: srv.URL})
	if err != nil {
		t.Logf("Setup (fail-open): %v", err)
	}
	slog.Info("otlp redact probe", "marker", "otlp-marker-7f3", "password", "otlp-secret-9c1", "token", "otlp-tok-2b8")
	if shutdown != nil {
		_ = shutdown(context.Background())
	}
	mu.Lock()
	got := bodies.String()
	mu.Unlock()
	if !strings.Contains(got, "otlp-marker-7f3") {
		t.Fatalf("the probe record was not exported (%d bytes received); the test proves nothing", len(got))
	}
	for _, secret := range []string{"otlp-secret-9c1", "otlp-tok-2b8"} {
		if strings.Contains(got, secret) {
			t.Errorf("secret %q exported over OTLP", secret)
		}
	}
}
