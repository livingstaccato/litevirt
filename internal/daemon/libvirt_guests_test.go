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
		Files: []string{filepath.Join(t.TempDir(), "libvirt-guests")},
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
		if err := os.WriteFile(g.Files[0], []byte(*file), 0o644); err != nil {
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
		{"inline comment after suspend", str("ON_SHUTDOWN=suspend # keep\nON_BOOT=ignore\n"), "enabled", nil, true},
		{"inline comment after start, quoted", str("ON_SHUTDOWN=shutdown\nON_BOOT=\"start\" # c\n"), "enabled", nil, true},
		{"export prefix", str("export ON_SHUTDOWN=suspend\nexport ON_BOOT=ignore\n"), "enabled", nil, true},
		{"export prefix, safe values", str("export ON_SHUTDOWN=shutdown\nexport ON_BOOT=ignore # c\n"), "enabled", nil, false},
		{"indented assignment", str("  ON_SHUTDOWN=shutdown\n\tON_BOOT=ignore\n"), "enabled", nil, false},
		{"expansion refused", str("ON_SHUTDOWN=$X\nON_BOOT=ignore\n"), "enabled", nil, true},
		{"unclosed quote refused", str("ON_SHUTDOWN=shutdown\nON_BOOT=\"ignore\n"), "enabled", nil, true},
		{"trailing word refused", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore now\n"), "enabled", nil, true},
		{"later expansion overrides a safe value", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\nON_BOOT=$X\n"), "enabled", nil, true},
		{"later trailing word overrides a safe value", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\nON_BOOT=ignore now\n"), "enabled", nil, true},
		{"later quoted trailing word", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\nON_BOOT=\"ignore\" now\n"), "enabled", nil, true},
		{"later quoted expansion overrides a safe value", str("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\nON_BOOT=\"$X\"\n"), "enabled", nil, true},
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
		Files: []string{dir}, // a directory: reading it is an error that is not ENOENT
		unit:  func(context.Context, string) (string, error) { return "enabled", nil },
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
		Files: []string{filepath.Join(t.TempDir(), "absent")},
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

// RHEL family: the unit reads /etc/sysconfig/libvirt-guests, and the first
// file that exists is the one read.
//
// Mutations: read only the first path - the sysconfig row goes red; read every
// file (later wins) - the first-wins row goes red.
func TestLibvirtGuests_SysconfigPath(t *testing.T) {
	dir := t.TempDir()
	deb, rh := filepath.Join(dir, "default"), filepath.Join(dir, "sysconfig")
	unit := func(_ context.Context, verb string) (string, error) {
		if verb == "is-enabled" {
			return "enabled", nil
		}
		return "inactive", nil
	}
	g := libvirtGuests{Files: []string{deb, rh}, unit: unit}
	if err := os.WriteFile(rh, []byte("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("sysconfig file with safe values refused: %v", err)
	}
	if err := os.WriteFile(rh, []byte("ON_SHUTDOWN=suspend\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(context.Background()); err == nil {
		t.Fatal("sysconfig file with ON_SHUTDOWN=suspend passed")
	}
	// The Debian file exists: it alone is read.
	if err := os.WriteFile(deb, []byte("ON_SHUTDOWN=shutdown\nON_BOOT=ignore\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := g.Check(context.Background()); err != nil {
		t.Fatalf("the first existing file is not the one read: %v", err)
	}
}
