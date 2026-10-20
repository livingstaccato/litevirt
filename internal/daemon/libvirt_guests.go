package daemon

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// libvirtGuestsFiles are the sysconfig files of libvirt's libvirt-guests unit.
// (Debian family; RHEL family keeps it under /etc/sysconfig).
var libvirtGuestsFiles = []string{"/etc/default/libvirt-guests", "/etc/sysconfig/libvirt-guests"}

// libvirtGuests reads whether libvirt-guests would save or restore guests
// behind litevirt's back (D-9): the unit enabled or active, with
// ON_SHUTDOWN=suspend or ON_BOOT=start. Keys the file does not set take the
// unit's defaults, which are suspend and start.
type libvirtGuests struct {
	Files []string // the first that exists is read
	// unit answers `systemctl <verb> libvirt-guests.service`: its trimmed
	// stdout, or an error when there is none.
	unit func(ctx context.Context, verb string) (string, error)
}

// CheckLibvirtGuests is the live D-9 check on this host: nil when
// libvirt-guests neither saves nor restores guests, else the reason. It
// fails closed: an unreadable file or unit state refuses. The source's stage A
// and the target's Prepare call it; the label asserts it too.
func CheckLibvirtGuests(ctx context.Context) error {
	return libvirtGuests{Files: libvirtGuestsFiles, unit: systemctlUnit}.Check(ctx)
}

func systemctlUnit(ctx context.Context, verb string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// is-enabled and is-active exit non-zero for a disabled or inactive unit
	// and still print its state.
	out, err := exec.CommandContext(ctx, "systemctl", verb, "libvirt-guests.service").CombinedOutput()
	s := strings.TrimSpace(string(out))
	if s == "" && err != nil {
		return "", err
	}
	if strings.Contains(s, "No such file") || strings.Contains(s, "not-found") || strings.Contains(s, "could not be found") {
		return "not-found", nil
	}
	return strings.Fields(s)[0], nil
}

// Check is nil when libvirt-guests does not save or restore guests.
func (g libvirtGuests) Check(ctx context.Context) error {
	enabled, err := g.unit(ctx, "is-enabled")
	if err != nil {
		return fmt.Errorf("libvirt-guests: unit state unreadable: %w", err)
	}
	inForce := false
	switch enabled {
	case "enabled", "enabled-runtime":
		inForce = true
	case "disabled", "masked", "masked-runtime", "static", "linked", "linked-runtime",
		"indirect", "generated", "transient", "alias", "not-found":
		active, err := g.unit(ctx, "is-active")
		if err != nil {
			return fmt.Errorf("libvirt-guests: unit state unreadable: %w", err)
		}
		inForce = active == "active" || active == "activating"
	default:
		return fmt.Errorf("libvirt-guests: unrecognised unit state %q", enabled)
	}
	if !inForce {
		return nil
	}
	onShutdown, onBoot := "suspend", "start"
	for _, f := range g.Files {
		b, err := os.ReadFile(f)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return fmt.Errorf("libvirt-guests: %s unreadable: %w", f, err)
		}
		for _, line := range strings.Split(string(b), "\n") {
			k, v, ok, err := shellAssignment(line)
			if err != nil {
				return fmt.Errorf("libvirt-guests: %s: %w", f, err)
			}
			switch {
			case ok && k == "ON_SHUTDOWN":
				onShutdown = v
			case ok && k == "ON_BOOT":
				onBoot = v
			}
		}
		break // the first file that exists is the one the unit sources
	}
	if onShutdown == "suspend" {
		return fmt.Errorf("libvirt-guests is enabled with ON_SHUTDOWN=suspend: it would save guests at shutdown (set ON_SHUTDOWN=shutdown or disable the unit)")
	}
	if onBoot == "start" {
		return fmt.Errorf("libvirt-guests is enabled with ON_BOOT=start: it would start guests at boot outside litevirt (set ON_BOOT=ignore or disable the unit)")
	}
	return nil
}

// shellAssignment reads one line of the sysconfig file as a shell would for
// KEY=value: blank lines, comments and non-assignments are ok=false; an
// optional leading `export`; a quoted value runs to its closing quote; an
// unquoted one ends at whitespace, so a trailing `# comment` is not part of
// it. A value it cannot read the way a shell would (expansions, escapes, an
// unclosed quote, trailing words) is an error, never a guess: the caller
// refuses.
func shellAssignment(line string) (key, val string, ok bool, err error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false, nil
	}
	if rest, found := strings.CutPrefix(line, "export"); found && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
		line = strings.TrimSpace(rest)
	}
	k, v, found := strings.Cut(line, "=")
	if !found || k == "" || strings.ContainsAny(k, " \t") {
		return "", "", false, nil
	}
	if k != "ON_SHUTDOWN" && k != "ON_BOOT" {
		return "", "", false, nil
	}
	if v == "" {
		return k, "", true, nil
	}
	if q := v[0]; q == '"' || q == '\'' {
		end := strings.IndexByte(v[1:], q)
		if end < 0 {
			return "", "", false, fmt.Errorf("%s: unclosed quote", k)
		}
		val, rest := v[1:1+end], strings.TrimSpace(v[2+end:])
		if rest != "" && !strings.HasPrefix(rest, "#") && !strings.HasPrefix(rest, ";") {
			return "", "", false, fmt.Errorf("%s: unreadable value %q", k, v)
		}
		if strings.ContainsAny(val, "$`\\") {
			return "", "", false, fmt.Errorf("%s: unreadable value %q", k, v)
		}
		return k, val, true, nil
	}
	if i := strings.IndexAny(v, " \t"); i >= 0 {
		rest := strings.TrimSpace(v[i:])
		if !strings.HasPrefix(rest, "#") {
			return "", "", false, fmt.Errorf("%s: unreadable value %q", k, v)
		}
		v = v[:i]
	}
	if strings.ContainsAny(v, "$`\\\"';&|<>(){}*?~") {
		return "", "", false, fmt.Errorf("%s: unreadable value %q", k, v)
	}
	return k, v, true, nil
}
