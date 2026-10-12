// Package smart reads disk SMART health through smartctl. It never fails the
// caller: a host without smartctl, a virtual disk with no SMART support, or
// output it cannot parse all come back as "unknown" rather than an error or a
// guessed "failing" — a monitoring gap must not page as a dying disk, and it
// must never reach anything that fences.
package smart

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"time"

	"github.com/litevirt/litevirt/internal/cmdbound"
)

// Status is a disk's SMART verdict.
type Status int

const (
	Unknown Status = iota // no SMART data (no smartctl, virtual disk, unreadable)
	OK
	Warning // SMART passes, but the drive reports a non-fatal warning (NVMe over-temperature)
	Prefail // SMART passes but a prefailure attribute has tripped or the NVMe critical warning is set
	Failing // SMART overall-health self-assessment FAILED
)

func (s Status) String() string {
	switch s {
	case OK:
		return "ok"
	case Warning:
		return "warning"
	case Prefail:
		return "prefail"
	case Failing:
		return "failing"
	default:
		return "unknown"
	}
}

// Detail is a one-line operator explanation.
func (s Status) Detail() string {
	switch s {
	case Failing:
		return "SMART overall-health self-assessment FAILED: the drive reports it is failing; replace it"
	case Warning:
		return "SMART reports a drive warning that is not a failure sign (NVMe temperature above its threshold); check cooling"
	case Prefail:
		return "SMART reports a prefailure condition (a prefail attribute crossed its threshold, or the NVMe critical-warning flag is set); plan a replacement"
	case OK:
		return "SMART overall-health self-assessment PASSED"
	default:
		return "SMART health unavailable"
	}
}

// Disk is one disk's result.
type Disk struct {
	Device string
	Model  string
	// ID identifies the physical disk across renames (sdb -> sdc after a
	// reboot): "serial:<serial>" or "wwn:<wwn>" when smartctl reports one,
	// else the device name.
	ID     string
	Status Status
}

// Report is one pass over every disk smartctl can see.
type Report struct {
	// Available is false when smartctl is not installed (or could not scan).
	Available bool
	Disks     []Disk
}

// Runner runs smartctl with args and returns stdout. smartctl's exit status is
// a bitmask that is non-zero for a failing disk while the JSON is still valid,
// so an *exec.ExitError alongside output is not a failure.
type Runner func(ctx context.Context, args ...string) ([]byte, error)

// ExecRunner runs the real smartctl binary.
func ExecRunner(ctx context.Context, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	out, err := cmdbound.Command(ctx, "smartctl", args...).Output()
	return out, err
}

type scanOut struct {
	Devices []struct {
		Name string `json:"name"`
		Type string `json:"type"`
	} `json:"devices"`
}

type healthOut struct {
	ModelName    string `json:"model_name"`
	SerialNumber string `json:"serial_number"`
	WWN          *struct {
		NAA int64 `json:"naa"`
		OUI int64 `json:"oui"`
		ID  int64 `json:"id"`
	} `json:"wwn"`
	SmartSupport *struct {
		Available bool `json:"available"`
		Enabled   bool `json:"enabled"`
	} `json:"smart_support"`
	SmartStatus *struct {
		Passed bool `json:"passed"`
	} `json:"smart_status"`
	ATA *struct {
		Table []struct {
			Flags struct {
				Prefailure bool `json:"prefailure"`
			} `json:"flags"`
			WhenFailed string `json:"when_failed"`
		} `json:"table"`
	} `json:"ata_smart_attributes"`
	NVMe *struct {
		CriticalWarning int `json:"critical_warning"`
	} `json:"nvme_smart_health_information_log"`
}

// Check scans for disks and classifies each. Safe on a host with no smartctl.
func Check(ctx context.Context, run Runner) Report {
	out, err := run(ctx, "--scan", "--json")
	if err != nil && len(out) == 0 {
		// Not installed, or the scan could not run at all.
		return Report{}
	}
	var sc scanOut
	if json.Unmarshal(out, &sc) != nil {
		return Report{}
	}
	r := Report{Available: true}
	for _, d := range sc.Devices {
		disk := Disk{Device: d.Name, ID: d.Name, Status: Unknown}
		// -n standby: never spin up a sleeping disk to read it (smartd does the
		// same). A disk in standby exits with no SMART data, which is Unknown
		// and so keeps whatever state we last saw. -i adds the information
		// section: without it smartctl prints no model_name or serial_number, so
		// the model label stays empty and the serial-based disk ID is never set.
		args := []string{"--json", "-n", "standby", "-i", "-H", "-A"}
		if d.Type != "" {
			args = append(args, "-d", d.Type)
		}
		args = append(args, d.Name)
		o, err := run(ctx, args...)
		var ee *exec.ExitError
		if err != nil && !errors.As(err, &ee) && len(o) == 0 {
			r.Disks = append(r.Disks, disk)
			continue
		}
		var id string
		disk.Model, id, disk.Status = classify(o)
		if id != "" {
			disk.ID = id
		}
		r.Disks = append(r.Disks, disk)
	}
	sort.Slice(r.Disks, func(i, j int) bool { return r.Disks[i].Device < r.Disks[j].Device })
	return r
}

func classify(raw []byte) (model, id string, st Status) {
	var h healthOut
	if json.Unmarshal(raw, &h) != nil {
		return "", "", Unknown
	}
	model = h.ModelName
	switch {
	case h.SerialNumber != "":
		id = "serial:" + h.SerialNumber
	case h.WWN != nil:
		id = fmt.Sprintf("wwn:%x-%x-%x", h.WWN.NAA, h.WWN.OUI, h.WWN.ID)
	}
	if h.SmartSupport != nil && !h.SmartSupport.Available {
		return model, id, Unknown
	}
	if h.SmartStatus == nil {
		return model, id, Unknown
	}
	if !h.SmartStatus.Passed {
		return model, id, Failing
	}
	if h.NVMe != nil {
		// Bit 0x02 is "temperature above/below threshold": a cooling problem,
		// not a dying drive. Every other bit (spare low, reliability degraded,
		// read-only, backup failed) is a prefailure signal.
		if h.NVMe.CriticalWarning&^0x02 != 0 {
			return model, id, Prefail
		}
	}
	if h.ATA != nil {
		for _, a := range h.ATA.Table {
			if a.Flags.Prefailure && (a.WhenFailed == "now" || a.WhenFailed == "in_the_past") {
				return model, id, Prefail
			}
		}
	}
	if h.NVMe != nil && h.NVMe.CriticalWarning&0x02 != 0 {
		return model, id, Warning
	}
	return model, id, OK
}
