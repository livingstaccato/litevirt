package corrosion

import (
	"bytes"
	"encoding/json"
	"log"
	"log/slog"
	"strings"
	"testing"
)

// memberlist writes "<date> <time> [LEVEL] memberlist: ..." lines to its
// LogOutput. Each must reach slog as one record at memberlist's own level,
// with the text after the level tag as the message — not every line at
// DEBUG with the stdlib prefix and level tag inside the message.
func TestSlogWriter_CarriesMemberlistLevel(t *testing.T) {
	var buf bytes.Buffer
	// slog.SetDefault also rewires the stdlib log package, and restoring the
	// stock default does not undo that, so the log output is restored too.
	prev, prevW, prevF := slog.Default(), log.Writer(), log.Flags()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() {
		slog.SetDefault(prev)
		log.SetOutput(prevW)
		log.SetFlags(prevF)
	})

	w := &slogWriter{}
	for _, line := range []string{
		"2026/10/08 12:50:01 [ERR] memberlist: Failed to send ping: write udp: network is unreachable\n",
		"2026/10/08 12:50:02 [WARN] memberlist: Refuting a suspect message (from: node-2)\n",
		"2026/10/08 12:50:03 [INFO] memberlist: Marking node-4 as failed, suspect timeout reached (2 peer confirmations)\n",
		"2026/10/08 12:50:04 [DEBUG] memberlist: Stream connection from=10.77.0.12:41234\n",
		"no level tag at all\n",
	} {
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	want := []struct{ level, msg string }{
		{"ERROR", "memberlist: Failed to send ping: write udp: network is unreachable"},
		{"WARN", "memberlist: Refuting a suspect message (from: node-2)"},
		{"INFO", "memberlist: Marking node-4 as failed, suspect timeout reached (2 peer confirmations)"},
		{"DEBUG", "memberlist: Stream connection from=10.77.0.12:41234"},
		{"DEBUG", "no level tag at all"},
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != len(want) {
		t.Fatalf("got %d records, want %d: %q", len(lines), len(want), lines)
	}
	for i, l := range lines {
		var rec map[string]any
		if err := json.Unmarshal([]byte(l), &rec); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
		if rec["level"] != want[i].level || rec["msg"] != want[i].msg {
			t.Errorf("record %d: level=%v msg=%q, want level=%s msg=%q", i, rec["level"], rec["msg"], want[i].level, want[i].msg)
		}
	}
}
