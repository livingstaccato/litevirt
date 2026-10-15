package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func guestsCheck(t *testing.T, file *string, unit string, unitErr error) error {
	t.Helper()
	g := libvirtGuests{
		File: filepath.Join(t.TempDir(), "libvirt-guests"),
		unit: func(_ context.Context, verb string) (string, error) {
			if unitErr != nil {
				return "", unitErr
			}
			if verb == "is-enabled" {
				return unit, nil
			}
			return "inactive", nil
		},
	}
	if file != nil {
		if err := os.WriteFile(g.File, []byte(*file), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return g.Check(context.Background())
}

func str(s string) *string { return &s }

// D-9. Mutations: ignore ON_SHUTDOWN, ignore ON_BOOT, ignore the unit state,
// treat an absent key as "no", or pass on an unreadable input; each row it
// owns goes red.
func TestLibvirtGuests(t *testing.T) {
	cases := []struct {
		name    string
		file    *string
		unit    string
		unitErr error
		refuse  bool
	}{
		{"unit disabled", str("ON_SHUTDOWN=suspend\nON_BOOT=start\n"), "disabled", nil, false},
		{"unit masked", str("ON_SHUTDOWN=suspend\n"), "masked", nil, false},
		{"unit absent (not-found)", nil, "not-found", nil, false},
		{"enabled, shutdown suspend", str("ON_SHUTDOWN=suspend\nON_BOOT=ignore\n"), "enabled", nil, true},
		{"enabled, boot start", str("ON_SHUTDOWN=shutdown\nON_BOOT=start\n"), "enabled", nil, true},
		{"enabled, quoted values", str("ON_SHUTDOWN=\"suspend\"\nON_BOOT='ignore'\n"), "enabled", nil, true},
		{"enabled, shutdown and ignore", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\n"), "enabled", nil, false},
		{"enabled, commented defaults", str("#ON_SHUTDOWN=suspend\n#ON_BOOT=start\nON_SHUTDOWN=shutdown\nON_BOOT=ignore\n"), "enabled", nil, false},
		{"enabled, keys absent: libvirt's defaults save and start", str("# nothing set\n"), "enabled", nil, true},
		{"enabled, file absent: defaults", nil, "enabled", nil, true},
		{"enabled-runtime counts", str("ON_BOOT=start\n"), "enabled-runtime", nil, true},
		{"last assignment wins", str("ON_SHUTDOWN=suspend\nON_SHUTDOWN=shutdown\nON_BOOT=ignore\n"), "enabled", nil, false},
		{"unit state unreadable", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\n"), "", errors.New("systemctl: exec failed"), true},
		{"unit state unrecognised", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\n"), "weird", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := guestsCheck(t, c.file, c.unit, c.unitErr)
			if (err != nil) != c.refuse {
				t.Fatalf("Check = %v, refuse want %v", err, c.refuse)
			}
		})
	}
}

// An unreadable file (not merely absent) fails closed.
//
// Mutation: treat every read error like ENOENT — red.
func TestLibvirtGuests_UnreadableFileRefuses(t *testing.T) {
	dir := t.TempDir()
	g := libvirtGuests{
		File: dir, // a directory: reading it is an error that is not ENOENT
		unit: func(context.Context, string) (string, error) { return "enabled", nil },
	}
	err := g.Check(context.Background())
	if err == nil || !strings.Contains(err.Error(), "unreadable") {
		t.Fatalf("an unreadable /etc/default/libvirt-guests: %v, want an \"unreadable\" refusal", err)
	}
}

// Active counts as in force even when is-enabled says static.
//
// Mutation: drop the is-active read — red.
func TestLibvirtGuests_ActiveUnitCounts(t *testing.T) {
	g := libvirtGuests{
		File: filepath.Join(t.TempDir(), "absent"),
		unit: func(_ context.Context, verb string) (string, error) {
			if verb == "is-active" {
				return "active", nil
			}
			return "static", nil
		},
	}
	if err := g.Check(context.Background()); err == nil {
		t.Fatal("an active libvirt-guests unit with default actions passed")
	}
}
