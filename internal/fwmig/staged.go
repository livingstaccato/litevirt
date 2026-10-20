package fwmig

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Staged firmware state (D2-18 re-review 4, m-2). The reconciler gathers a
// leftover's NVRAM and swtpm tree in <QuarantineDir>/<vm>-reconciling-<uuid>
// before it renames the directory to <vm>-reconciled-<unix>, and a restore
// (lv host superseded-disks --restore) renames a quarantine to
// <vm>-restoring-<uuid> before it moves the state back. While either exists
// the domain's own paths may be empty, so the guard refuses a start, resume or
// define of the VM (lv.FirmwareStaged): the VM never boots on blank firmware
// state. <uuid> is "nouuid" for a definition that gave none.

// Stage kinds.
const (
	StageReconciling = "reconciling"
	StageRestoring   = "restoring"
	StageNoUUID      = "nouuid"
)

var stageNameRe = regexp.MustCompile(`^(.+)-(reconciling|restoring)-([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|nouuid)$`)

// StageName is the directory name of vm's stage of kind for uuid ("" = none).
func StageName(vm, kind, uuid string) string {
	if uuid == "" {
		uuid = StageNoUUID
	}
	return vm + "-" + kind + "-" + uuid
}

// ParseStageName splits a stage directory name; uuid is "" for nouuid.
func ParseStageName(base string) (vm, kind, uuid string, ok bool) {
	m := stageNameRe.FindStringSubmatch(base)
	if m == nil {
		return "", "", "", false
	}
	if m[3] != StageNoUUID {
		uuid = m[3]
	}
	return m[1], m[2], uuid, true
}

// Staged returns a FirmwareStaged record for every stage directory of the VM:
// one named for name, or one keyed by uuid under any name. A quarantine
// directory that cannot be listed is an *UnreadableRecordError.
func (r *Records) Staged(name, uuid string) ([]lv.FirmwareMoveRecord, error) {
	root, err := r.root()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(root, QuarantineDir)
	ents, err := r.fs.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, &UnreadableRecordError{Path: dir, Err: err}
	}
	var out []lv.FirmwareMoveRecord
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		vm, kind, id, ok := ParseStageName(e.Name())
		if !ok || !((name != "" && vm == name) || (uuid != "" && strings.EqualFold(id, uuid))) {
			continue
		}
		out = append(out, lv.FirmwareMoveRecord{Kind: lv.FirmwareStaged, VM: vm, UUID: id, State: kind,
			Path: filepath.Join(dir, e.Name())})
	}
	return out, nil
}

// guardLookup is what the guard reads: every move record (Lookup) and every
// stage of the VM (Staged).
func (r *Records) guardLookup(name, uuid string) ([]lv.FirmwareMoveRecord, error) {
	recs, err := r.Lookup(name, uuid)
	if err != nil {
		return nil, err
	}
	staged, err := r.Staged(name, uuid)
	if err != nil {
		return nil, err
	}
	return append(recs, staged...), nil
}
