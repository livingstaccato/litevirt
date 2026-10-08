package obs

import (
	"log/slog"
	"testing"

	"google.golang.org/grpc/grpclog"
)

// gRPC's own logger writes "ERROR: [core] ..." text straight to stderr,
// outside slog. After Setup its records reach the daemon's handler as real
// records at their own level; below gRPC's default ERROR severity they stay
// quiet, as they were.
func TestSetup_GRPCLogsAreStructuredRecords(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt"}, func() {
		grpclog.Errorf("[transport] probe %s failed", "grpc-error-probe")
		grpclog.Warning("grpc-warning-probe")
		grpclog.Info("grpc-info-probe")
		slog.Info("after grpc probes")
	})
	line := lineWith(lines, "grpc-error-probe")
	if line == "" {
		t.Fatalf("gRPC error did not reach the daemon log handler: %q", lines)
	}
	f := logfmtFields(line)
	if f["level"] != "ERROR" || f["message"] != "[transport] probe grpc-error-probe failed" || f["component"] != "grpc" {
		t.Fatalf("gRPC error not a structured ERROR record: %q", line)
	}
	for _, quiet := range []string{"grpc-warning-probe", "grpc-info-probe"} {
		if l := lineWith(lines, quiet); l != "" {
			t.Errorf("gRPC below its default ERROR severity was logged: %q", l)
		}
	}
}

// GRPC_GO_LOG_SEVERITY_LEVEL=warning opens warnings, at WARN.
func TestSetup_GRPCSeverityEnvHonoured(t *testing.T) {
	cleanEnv(t)
	t.Setenv("GRPC_GO_LOG_SEVERITY_LEVEL", "warning")
	lines := captureDaemonStderrEnv(t, Config{ServiceName: "litevirt"}, func() {
		grpclog.Warning("grpc-warning-probe")
		grpclog.Info("grpc-info-probe")
	})
	if f := logfmtFields(lineWith(lines, "grpc-warning-probe")); f["level"] != "WARN" {
		t.Fatalf("warning not logged at WARN with severity=warning: %q", lines)
	}
	if l := lineWith(lines, "grpc-info-probe"); l != "" {
		t.Errorf("info logged with severity=warning: %q", l)
	}
}
