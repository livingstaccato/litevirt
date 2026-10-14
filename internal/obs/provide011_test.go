package obs

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// provide-telemetry reserves service, env, version, trace_id and span_id: a
// caller attribute with one of those keys is dropped once the matching stamped
// field exists. No litevirt log call may use them as an attribute key. The scan
// is AST based, so it covers package-level slog functions, *slog.Logger
// methods, slog.Log/LogAttrs, With and Group arguments and the slog.String/Int/
// Any... attr constructors, multi-line calls included. The one exception is
// named exactly: the daemon's startup line logs before obs.Setup runs, so the
// default logger keeps the key.
func TestNoReservedSlogKeys(t *testing.T) {
	reserved := map[string]bool{"service": true, "env": true, "version": true, "trace_id": true, "span_id": true}
	logFuncs := map[string]bool{
		"Debug": true, "Info": true, "Warn": true, "Error": true,
		"DebugContext": true, "InfoContext": true, "WarnContext": true, "ErrorContext": true,
		"Log": true, "LogAttrs": true, "With": true, "Group": true,
		"String": true, "Int": true, "Int64": true, "Uint64": true, "Float64": true,
		"Bool": true, "Duration": true, "Time": true, "Any": true,
	}
	// file | first string literal argument (the message) of the exempt call.
	allowed := map[string]bool{
		"cmd/litevirt/daemon.go|starting litevirt daemon": true,
	}
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	scanned := 0
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if n := d.Name(); n == ".git" || n == "gen" || n == ".claude" || n == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			return perr
		}
		scanned++
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !logFuncs[sel.Sel.Name] {
				return true
			}
			var first string
			for i, a := range call.Args {
				lit, ok := a.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				v, uerr := strconv.Unquote(lit.Value)
				if uerr != nil {
					continue
				}
				if i == 0 || first == "" {
					first = v
				}
				if i > 0 && reserved[v] && !allowed[rel+"|"+first] {
					t.Errorf("%s: %s(...) uses reserved key %q; provide-telemetry drops it when the stamped field exists. Use a specific key (crl_version, build_version, ...)",
						fset.Position(call.Pos()), sel.Sel.Name, v)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if scanned < 100 {
		t.Fatalf("scanned only %d files; the walk root is wrong", scanned)
	}
}

// log_level CRITICAL was accepted before provide-telemetry 0.8 and meant ERROR.
// Since 0.8 it is a level above ERROR that litevirt never emits, so it would
// silence every line. obs maps it to ERROR (from config and from env) and says so.
func TestSetup_CriticalLogLevelMappedToError(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		env  map[string]string
	}{
		{"config", Config{ServiceName: "litevirt", LogLevel: "CRITICAL"}, nil},
		{"litevirt env", Config{ServiceName: "litevirt"}, map[string]string{"LITEVIRT_LOG_LEVEL": "critical"}},
		{"vendor env", Config{ServiceName: "litevirt"}, map[string]string{"PROVIDE_LOG_LEVEL": "CRITICAL"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			// The WARN goes through the pre-Setup default logger.
			var pre bytes.Buffer
			prev := slog.Default()
			t.Cleanup(func() { slog.SetDefault(prev) })
			slog.SetDefault(slog.New(slog.NewTextHandler(&pre, nil)))
			lines := captureDaemonStderrEnv(t, tc.cfg, func() {
				slog.Info("info below error")
				slog.Error("an error line", "k", "v")
			})
			if n := countWith(lines, "an error line"); n != 1 {
				t.Fatalf("ERROR record emitted %d times under CRITICAL, want 1 (silenced?): %q", n, lines)
			}
			if n := countWith(lines, "info below error"); n != 0 {
				t.Errorf("INFO record emitted under a CRITICAL->ERROR level: %q", lines)
			}
			if got := os.Getenv("PROVIDE_LOG_LEVEL"); got != "ERROR" {
				t.Errorf("PROVIDE_LOG_LEVEL=%q, want ERROR", got)
			}
			if n := strings.Count(pre.String(), "treated as ERROR"); n != 1 {
				t.Errorf("startup WARN count=%d, want 1: %q", n, pre.String())
			}
		})
	}
}

// PROVIDE_LOG_INCLUDE_CALLER defaults true in provide-telemetry 0.9+, which
// adds filename/lineno to every record. Through litevirt's gRPC and stdlib log
// bridges that reports adapter frames and lengthens every journald line, so
// obs defaults it off; an operator can still opt in.
func TestSetup_IncludeCallerDefaultsOff(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt", HostName: "node-3"}, func() {
		slog.Info("caller probe")
	})
	line := lineWith(lines, "caller probe")
	if line == "" {
		t.Fatalf("no journal line: %q", lines)
	}
	f := logfmtFields(line)
	if _, ok := f["filename"]; ok {
		t.Errorf("filename on a default record: %q", line)
	}
	if _, ok := f["lineno"]; ok {
		t.Errorf("lineno on a default record: %q", line)
	}
	if v, ok := os.LookupEnv("PROVIDE_LOG_INCLUDE_CALLER"); !ok || v != "false" {
		t.Errorf("PROVIDE_LOG_INCLUDE_CALLER=%q (set=%v), want the obs default false", v, ok)
	}
}

// captureDaemonStderr runs Setup the way the daemon does, with os.Stderr (the
// daemon's journal stream) swapped for a pipe, then runs emit and returns
// every line the installed handler chain wrote. The slog default and the
// stdlib log output are restored afterwards.
func captureDaemonStderr(t *testing.T, cfg Config, emit func()) []string {
	t.Helper()
	cleanEnv(t)
	return captureDaemonStderrEnv(t, cfg, emit)
}

// captureDaemonStderrEnv is captureDaemonStderr without the env reset, for a
// test that has called cleanEnv and then exported operator variables.
func captureDaemonStderrEnv(t *testing.T, cfg Config, emit func()) []string {
	t.Helper()
	prevDefault, prevWriter, prevFlags := slog.Default(), log.Writer(), log.Flags()
	t.Cleanup(func() {
		slog.SetDefault(prevDefault)
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
	})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	prevStderr := os.Stderr
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()

	shutdown, serr := Setup(context.Background(), cfg)
	if serr != nil {
		t.Logf("Setup (fail-open): %v", serr)
	}
	emit()
	if shutdown != nil {
		_ = shutdown(context.Background())
	}
	os.Stderr = prevStderr
	_ = w.Close()
	out := <-done
	_ = r.Close()
	return strings.Split(strings.TrimSpace(string(bytes.TrimSpace(out))), "\n")
}

// countWith counts the lines containing needle.
func countWith(lines []string, needle string) int {
	n := 0
	for _, l := range lines {
		if strings.Contains(l, needle) {
			n++
		}
	}
	return n
}

func lineWith(lines []string, needle string) string {
	for _, l := range lines {
		if strings.Contains(l, needle) {
			return l
		}
	}
	return ""
}

// logfmtFields splits one text-handler line into key -> value, unquoting
// quoted values. Enough for the shapes slog's TextHandler writes.
func logfmtFields(line string) map[string]string {
	f := map[string]string{}
	for len(line) > 0 {
		line = strings.TrimLeft(line, " ")
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			break
		}
		key := line[:eq]
		line = line[eq+1:]
		var val string
		if strings.HasPrefix(line, `"`) {
			end := 1
			for end < len(line) && (line[end] != '"' || line[end-1] == '\\') {
				end++
			}
			val = strings.ReplaceAll(line[1:end], `\"`, `"`)
			line = line[min(end+1, len(line)):]
		} else {
			sp := strings.IndexByte(line, ' ')
			if sp < 0 {
				sp = len(line)
			}
			val = line[:sp]
			line = line[sp:]
		}
		f[key] = val
	}
	return f
}
