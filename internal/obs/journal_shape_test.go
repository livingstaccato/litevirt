package obs

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"os"
	"strings"
	"testing"
)

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

// The daemon's journal line for slog.Error must carry level=ERROR as a field,
// the bare message, and each attribute as its own key. The lab saw
// level=INFO message="INFO container deleted name=lxt2 host=node-3": a whole
// record rendered to text and re-logged as the message of a new INFO record.
func TestDaemonLog_DefaultConsole_RecordsAreStructured(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt", HostName: "node-3"}, func() {
		slog.Error("container deleted", "name", "lxt2", "host", "node-3")
		slog.Warn("lease drifted", "ct", "lxt4")
		slog.Info("container created", "name", "lxt3")
	})
	for _, c := range []struct{ msg, level, key, val string }{
		{"container deleted", "ERROR", "name", "lxt2"},
		{"lease drifted", "WARN", "ct", "lxt4"},
		{"container created", "INFO", "name", "lxt3"},
	} {
		if n := countWith(lines, c.msg); n != 1 {
			t.Fatalf("%d journal lines for %q, want exactly 1: %q", n, c.msg, lines)
		}
		line := lineWith(lines, c.msg)
		f := logfmtFields(line)
		if f["level"] != c.level {
			t.Errorf("%q: level=%q, want %q (line %q)", c.msg, f["level"], c.level, line)
		}
		if f["message"] != c.msg {
			t.Errorf("%q: message=%q, want the bare message (line %q)", c.msg, f["message"], line)
		}
		if f[c.key] != c.val {
			t.Errorf("%q: attribute %s=%q, want %q as its own field (line %q)", c.msg, c.key, f[c.key], c.val, line)
		}
	}
}

// log_format: json gives one JSON object per record with the same fields.
func TestDaemonLog_JSON_RecordsAreStructured(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt", LogFormat: "json"}, func() {
		slog.Error("container deleted", "name", "lxt2", "host", "node-3")
	})
	if n := countWith(lines, "container deleted"); n != 1 {
		t.Fatalf("%d JSON records for one call, want 1: %q", n, lines)
	}
	line := lineWith(lines, "container deleted")
	var rec map[string]any
	if err := json.Unmarshal([]byte(line), &rec); err != nil {
		t.Fatalf("not one JSON record per line: %v (%q)", err, line)
	}
	if rec["level"] != "ERROR" || rec["message"] != "container deleted" ||
		rec["name"] != "lxt2" || rec["host"] != "node-3" {
		t.Fatalf("record not structured: %v", rec)
	}
}

// A line from the stdlib log package (third-party libraries that use it) is
// one record, not a record wrapped in another.
func TestDaemonLog_StdlibLogIsOneRecord(t *testing.T) {
	lines := captureDaemonStderr(t, Config{ServiceName: "litevirt"}, func() {
		log.Print("stdlib says hello")
	})
	if n := countWith(lines, "stdlib says hello"); n != 1 {
		t.Fatalf("%d lines for one log.Print, want 1: %q", n, lines)
	}
	line := lineWith(lines, "stdlib says hello")
	f := logfmtFields(line)
	if f["message"] != "stdlib says hello" {
		t.Fatalf("stdlib log line was re-wrapped: message=%q (line %q)", f["message"], line)
	}
}
