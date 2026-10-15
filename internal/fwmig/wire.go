package fwmig

import (
	"errors"
	"fmt"
	"os"
	"strings"

	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/safename"
)

// Virt is the libvirt side of the firmware move guard: libvirt.Client in the
// daemon, libvirtfake.Fake in the fleet harness.
type Virt interface {
	SetFirmwareMoveGuard(lv.FirmwareMoveGuard)
}

// Wire installs the firmware move guard (spec §5.1) over this host's records
// on virt and on store, the host's one firmware store, whose data directory
// holds the records. The daemon calls it right after connecting to libvirt,
// before anything can start a domain; the fleet harness calls it for each
// node. It is the only place the guard is installed.
func Wire(virt Virt, store *lv.FirmwareStore) {
	if virt == nil || store == nil {
		panic("fwmig.Wire: no libvirt client or no firmware store")
	}
	g := lv.NewFirmwareMoveGuard(New(store.DataDir).Lookup)
	virt.SetFirmwareMoveGuard(g)
	store.SetFirmwareMoveGuard(g)
}

// Lookup returns every marker and hold that names the VM: the record under
// name, and, when uuid is set, any record of that uuid under any name. A
// record that cannot be read — corrupt, of a value this build does not know,
// in a directory that cannot be listed — is an error, which the guard takes
// as a record present and refuses on. A record of another incarnation or
// attempt is a record present: the raw readers do not check the binding.
//
// A name that is not a valid VM name names no record (none can be written
// under it). The owed-discard record is not a marker and vetoes nothing.
//
// The guard reads only the phase or state, the binding and, for a cleaning
// marker, whether the retained bundle is on disk; it never reads the hashes,
// so the phase-to-hash consistency of a record is checked by the steps that
// consume the hashes (Verify, Release, cleanup, recovery), not here.
func (r *Records) Lookup(name, uuid string) ([]lv.FirmwareMoveRecord, error) {
	var out []lv.FirmwareMoveRecord
	seen := map[string]bool{}
	addMarker := func(m Marker) error {
		if seen["m/"+m.VM] {
			return nil
		}
		seen["m/"+m.VM] = true
		rec, err := r.markerRecord(m)
		if err != nil {
			return err
		}
		out = append(out, rec)
		return nil
	}
	addHold := func(h Hold) {
		if seen["h/"+h.VM] {
			return
		}
		seen["h/"+h.VM] = true
		out = append(out, holdRecord(h))
	}
	if name != "" && safename.ValidateVMName(name) == nil {
		m, ok, err := r.GetMarker(name)
		if err != nil {
			return nil, err
		}
		if ok {
			if err := addMarker(m); err != nil {
				return nil, err
			}
		}
		h, ok, err := r.GetHold(name)
		if err != nil {
			return nil, err
		}
		if ok {
			addHold(h)
		}
	}
	if uuid != "" {
		ms, err := r.ListMarkers()
		if err != nil {
			return nil, err
		}
		for _, m := range ms {
			if strings.EqualFold(m.UUID, uuid) {
				if err := addMarker(m); err != nil {
					return nil, err
				}
			}
		}
		hs, err := r.ListHolds()
		if err != nil {
			return nil, err
		}
		for _, h := range hs {
			if strings.EqualFold(h.UUID, uuid) {
				addHold(h)
			}
		}
	}
	return out, nil
}

func (r *Records) markerRecord(m Marker) (lv.FirmwareMoveRecord, error) {
	rec := lv.FirmwareMoveRecord{
		Kind: lv.FirmwareMarker, VM: m.VM, UUID: m.UUID, Attempt: m.Attempt,
		Peer: m.Target, State: string(m.Phase), PreCutover: m.BeforeCutover(),
	}
	if m.Phase != PhaseCleaning {
		return rec, nil
	}
	p, err := r.RetainedPath(m.VM, m.Attempt)
	if err != nil {
		return rec, err
	}
	fi, err := os.Lstat(p)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return rec, fmt.Errorf("fwmig: retained bundle %s: %w", p, err)
	default:
		rec.RetainedBundle = fi.Mode().IsRegular() && fi.Size() > 0
	}
	return rec, nil
}

func holdRecord(h Hold) lv.FirmwareMoveRecord {
	return lv.FirmwareMoveRecord{
		Kind: lv.FirmwareHold, VM: h.VM, UUID: h.UUID, Attempt: h.Attempt,
		Peer: h.Source, State: string(h.State),
	}
}
