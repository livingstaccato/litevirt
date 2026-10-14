package obs

import (
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Nothing in litevirt may log a bare "version" slog key again, except the two
// call sites that log the build version, which the stamped service.version
// already carries. Scans slog calls (also multi-line) across the repo.
func TestNoBareVersionSlogKey(t *testing.T) {
	re := regexp.MustCompile(`(?s)slog\.(?:Debug|Info|Warn|Error)\((?:[^()]|\([^()]*\))*?"version"\s*,`)
	allowed := map[string]bool{
		"cmd/litevirt/daemon.go":              true,
		"internal/daemon/watchdog_upgrade.go": true,
	}
	root := filepath.Join("..", "..")
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
		rel, _ := filepath.Rel(root, p)
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if re.Match(b) && !allowed[filepath.ToSlash(rel)] {
			t.Errorf("%s logs a bare \"version\" slog key; provide-telemetry >= 0.11 drops it when a service version is set. Rename it (crl_version, schema_version, ...)", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
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
