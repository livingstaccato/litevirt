package daemon

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// libvirtGuestsFile is the sysconfig file of libvirt's libvirt-guests unit.
const libvirtGuestsFile = "/etc/default/libvirt-guests"

// libvirtGuests reads whether libvirt-guests would save or restore guests
// behind litevirt's back (D-9): the unit enabled or active, with
// ON_SHUTDOWN=suspend or ON_BOOT=start. Keys the file does not set take the
// unit's defaults, which are suspend and start.
type libvirtGuests struct {
	File string
	// unit answers `systemctl <verb> libvirt-guests.service`: its trimmed
	// stdout, or an error when there is none.
	unit func(ctx context.Context, verb string) (string, error)
}

// CheckLibvirtGuests is the live D-9 check on this host: nil when
// libvirt-guests neither saves nor restores guests, else the reason. It
// fails closed: an unreadable file or unit state refuses. The source's stage A
// and the target's Prepare call it; the label asserts it too.
func CheckLibvirtGuests(ctx context.Context) error {
	return libvirtGuests{File: libvirtGuestsFile, unit: systemctlUnit}.Check(ctx)
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
	switch b, err := os.ReadFile(g.File); {
	case err == nil:
		sc := bufio.NewScanner(strings.NewReader(string(b)))
		for sc.Scan() {
			k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
			if !ok {
				continue
			}
			v = strings.Trim(strings.TrimSpace(v), `"'`)
			switch strings.TrimSpace(k) {
			case "ON_SHUTDOWN":
				onShutdown = v
			case "ON_BOOT":
				onBoot = v
			}
		}
	case os.IsNotExist(err):
	default:
		return fmt.Errorf("libvirt-guests: %s unreadable: %w", g.File, err)
	}
	if onShutdown == "suspend" {
		return fmt.Errorf("libvirt-guests is enabled with ON_SHUTDOWN=suspend: it would save guests at shutdown (set ON_SHUTDOWN=shutdown or disable the unit)")
	}
	if onBoot == "start" {
		return fmt.Errorf("libvirt-guests is enabled with ON_BOOT=start: it would start guests at boot outside litevirt (set ON_BOOT=ignore or disable the unit)")
	}
	return nil
}
