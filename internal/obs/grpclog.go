package obs

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"google.golang.org/grpc/grpclog"
)

// gRPC keeps its own logger, which writes "ERROR: [core] ..." text straight
// to stderr: outside slog, with its level inside the text. grpcSlog routes it
// into the slog default instead, so a gRPC line is a record like any other,
// at its own level, tagged component=grpc.
//
// gRPC's default severity is kept: only errors, unless the operator opens
// GRPC_GO_LOG_SEVERITY_LEVEL (info|warning|error) — exactly what gRPC's own
// logger honours — so routing it adds no lines a default install did not
// already print. GRPC_GO_LOG_VERBOSITY_LEVEL sets V() the same way.
type grpcSlog struct{}

var (
	grpcLogOnce     sync.Once
	grpcMinSeverity atomic.Int64 // slog.Level of the lowest gRPC record logged
	grpcVerbosity   atomic.Int64
)

// installGRPCLogger points gRPC's logger at slog. grpclog.SetLoggerV2 is a
// plain unsynchronised assignment that gRPC reads from its own goroutines, so
// it is made once per process; later Setup calls only refresh the severity.
func installGRPCLogger() {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("GRPC_GO_LOG_SEVERITY_LEVEL"))) {
	case "info":
		grpcMinSeverity.Store(int64(slog.LevelInfo))
	case "warning":
		grpcMinSeverity.Store(int64(slog.LevelWarn))
	default:
		grpcMinSeverity.Store(int64(slog.LevelError))
	}
	v, _ := strconv.Atoi(os.Getenv("GRPC_GO_LOG_VERBOSITY_LEVEL"))
	grpcVerbosity.Store(int64(v))
	grpcLogOnce.Do(func() { grpclog.SetLoggerV2(grpcSlog{}) })
}

func (grpcSlog) log(level slog.Level, msg string) {
	if int64(level) < grpcMinSeverity.Load() {
		return
	}
	slog.Log(context.Background(), level, strings.TrimRight(msg, "\n"), "component", "grpc")
}

func (g grpcSlog) Info(args ...any)   { g.log(slog.LevelInfo, fmt.Sprint(args...)) }
func (g grpcSlog) Infoln(args ...any) { g.log(slog.LevelInfo, fmt.Sprintln(args...)) }
func (g grpcSlog) Infof(format string, args ...any) {
	g.log(slog.LevelInfo, fmt.Sprintf(format, args...))
}
func (g grpcSlog) Warning(args ...any)   { g.log(slog.LevelWarn, fmt.Sprint(args...)) }
func (g grpcSlog) Warningln(args ...any) { g.log(slog.LevelWarn, fmt.Sprintln(args...)) }
func (g grpcSlog) Warningf(format string, args ...any) {
	g.log(slog.LevelWarn, fmt.Sprintf(format, args...))
}
func (g grpcSlog) Error(args ...any)   { g.log(slog.LevelError, fmt.Sprint(args...)) }
func (g grpcSlog) Errorln(args ...any) { g.log(slog.LevelError, fmt.Sprintln(args...)) }
func (g grpcSlog) Errorf(format string, args ...any) {
	g.log(slog.LevelError, fmt.Sprintf(format, args...))
}

// Fatal keeps gRPC's contract: log, then exit(1).
func (g grpcSlog) Fatal(args ...any)   { g.fatal(fmt.Sprint(args...)) }
func (g grpcSlog) Fatalln(args ...any) { g.fatal(fmt.Sprintln(args...)) }
func (g grpcSlog) Fatalf(format string, args ...any) {
	g.fatal(fmt.Sprintf(format, args...))
}

func (grpcSlog) fatal(msg string) {
	slog.Log(context.Background(), slog.LevelError, strings.TrimRight(msg, "\n"), "component", "grpc", "fatal", true)
	os.Exit(1)
}

func (grpcSlog) V(l int) bool { return int64(l) <= grpcVerbosity.Load() }
