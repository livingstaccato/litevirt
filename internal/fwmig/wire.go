package fwmig

import (
	"errors"
	"os"
	"path/filepath"
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
	if store.DataDir == "" {
		// No records can be read without a data dir: every guarded call
		// would be refused at runtime.
		panic("fwmig.Wire: the firmware store has no data dir")
	}
	g := lv.NewFirmwareMoveGuard(New(store.DataDir).Lookup)
	virt.SetFirmwareMoveGuard(g)
	store.SetFirmwareMoveGuard(g)
}

// UnreadableRecordError is a record file, or record directory, that cannot be
// read (the guard's own type, so it can name the file in its refusal).
type UnreadableRecordError = lv.FirmwareRecordUnreadableError

// Lookup returns every marker and hold that names the VM: the record under
// name, and, when uuid is set, any record of that uuid under any name. A
// record that cannot be read — corrupt, of a value this build does not know,
// in a directory that cannot be listed — is an *UnreadableRecordError naming
// the file, which the guard takes as a record present and refuses on. A
// record of another incarnation or attempt is a record present: the raw
// readers do not check the binding.
//
// Lookup only reads: unlike List*, it sweeps no temp files (SweepTemps does,
// at startup), so the guard never takes the write lock or deletes anything.
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
		p, err := r.vmPath(InflightDir, name)
		if err != nil {
			return nil, err
		}
		m, ok, err := r.readMarker(p, name)
		if err != nil {
			return nil, &UnreadableRecordError{Path: p, Err: err}
		}
		if ok {
			if err := addMarker(m); err != nil {
				return nil, err
			}
		}
		if p, err = r.vmPath(HoldDir, name); err != nil {
			return nil, err
		}
		h, ok, err := r.readHold(p, name)
		if err != nil {
			return nil, &UnreadableRecordError{Path: p, Err: err}
		}
		if ok {
			addHold(h)
		}
	}
	if uuid != "" {
		var err error
		walkErr := r.eachRecord(InflightDir, func(p, vm string) error {
			m, ok, rerr := r.readMarker(p, vm)
			if rerr != nil {
				return &UnreadableRecordError{Path: p, Err: rerr}
			}
			if ok && strings.EqualFold(m.UUID, uuid) {
				return addMarker(m)
			}
			return nil
		})
		if walkErr == nil {
			walkErr = r.eachRecord(HoldDir, func(p, vm string) error {
				h, ok, rerr := r.readHold(p, vm)
				if rerr != nil {
					return &UnreadableRecordError{Path: p, Err: rerr}
				}
				if ok && strings.EqualFold(h.UUID, uuid) {
					addHold(h)
				}
				return nil
			})
		}
		if err = walkErr; err != nil {
			return nil, err
		}
	}
	return out, nil
}

// eachRecord calls fn for each record file in sub, without sweeping temp
// files. A directory that cannot be listed is an *UnreadableRecordError; an
// absent one has no records.
func (r *Records) eachRecord(sub string, fn func(path, vm string) error) error {
	root, err := r.root()
	if err != nil {
		return err
	}
	dir := filepath.Join(root, sub)
	ents, err := r.fs.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return &UnreadableRecordError{Path: dir, Err: err}
	}
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") {
			continue
		}
		if err := fn(filepath.Join(dir, n), strings.TrimSuffix(n, ".json")); err != nil {
			return err
		}
	}
	return nil
}

// Unreadable is every marker and hold file (and record directory) on this
// host that cannot be read: what the guard would refuse on. The daemon raises
// firmware_migration_record_unreadable from it.
func (r *Records) Unreadable() []*UnreadableRecordError {
	var out []*UnreadableRecordError
	for _, sub := range []string{InflightDir, HoldDir} {
		read := func(p, vm string) error {
			var err error
			if sub == InflightDir {
				_, _, err = r.readMarker(p, vm)
			} else {
				_, _, err = r.readHold(p, vm)
			}
			if err != nil {
				out = append(out, &UnreadableRecordError{Path: p, Err: err})
			}
			return nil
		}
		var ue *UnreadableRecordError
		if err := r.eachRecord(sub, read); errors.As(err, &ue) {
			out = append(out, ue)
		} else if err != nil {
			out = append(out, &UnreadableRecordError{Path: sub, Err: err})
		}
	}
	return out
}

func (r *Records) markerRecord(m Marker) (lv.FirmwareMoveRecord, error) {
	rec := lv.FirmwareMoveRecord{
		Kind: lv.FirmwareMarker, VM: m.VM, UUID: m.UUID, Attempt: m.Attempt,
		Peer: m.Target, State: string(m.Phase), PreCutover: m.BeforeCutover(),
		ParkedPreCutover: m.Phase.Parked() && preCutover(m.ParkedFrom), Parked: m.Phase.Parked(),
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
		return rec, &UnreadableRecordError{Path: p, Err: err}
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
