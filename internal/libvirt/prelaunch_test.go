package libvirt

import "testing"

// QEMU's query-status reply is read exactly: only a status it names is
// returned; an error reply, or none, is an error, never a status.
func TestParseQueryStatus(t *testing.T) {
	for reply, want := range map[string]string{
		`{"return": {"status": "prelaunch", "singlestep": false, "running": false}, "id": "libvirt-12"}`: "prelaunch",
		`{"return": {"status": "paused", "running": false}}`:                                             "paused",
		`{"return": {"status": "running", "running": true}}`:                                             "running",
	} {
		if got, err := parseQueryStatus(reply); err != nil || got != want {
			t.Errorf("parseQueryStatus(%s) = %q, %v; want %q", reply, got, err, want)
		}
	}
	for _, reply := range []string{``, `not json`, `{"return": {}}`, `{"error": {"class": "GenericError", "desc": "x"}}`} {
		if got, err := parseQueryStatus(reply); err == nil {
			t.Errorf("parseQueryStatus(%q) = %q, want an error", reply, got)
		}
	}
}
