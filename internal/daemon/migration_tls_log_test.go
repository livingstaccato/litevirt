package daemon

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// The start-up line says "installed" only when the install wrote something;
// a set already in place is "already up to date", which is what an operator
// reading a restart's log needs to tell apart.
func TestLogMigrationTLSInstall_Branches(t *testing.T) {
	cases := []struct {
		name       string
		ok, wrote  bool
		err        error
		want, deny string
	}{
		{"wrote", true, true, nil, "credentials installed for QEMU", "already up to date"},
		{"unchanged", true, false, nil, "already up to date", "installed for QEMU"},
		{"none", false, false, nil, "has no migration credentials", "installed for QEMU"},
		{"error", false, false, errors.New("boom"), "not installed", "installed for QEMU"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			old := slog.Default()
			slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
			defer slog.SetDefault(old)
			logMigrationTLSInstall(c.ok, c.wrote, c.err)
			got := buf.String()
			if !strings.Contains(got, c.want) || strings.Contains(got, c.deny) {
				t.Fatalf("log %q: want %q, not %q", got, c.want, c.deny)
			}
		})
	}
}
