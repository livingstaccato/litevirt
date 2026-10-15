package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A firmware move record (fwmig) that cannot be read makes the firmware move
// guard refuse every operation it might name on this host: the guard cannot
// tell whether the file binds the VM, so it fails closed. That reach is
// host-wide for every call that carries a uuid (a define, a firmware state
// restore, a wipe), so it is raised here, naming the files and the remedy,
// rather than left to the refusals' error text.
const (
	firmwareMoveEvaluator         = "firmware_move"
	condFirmwareRecordUnreadable  = "firmware_migration_record_unreadable"
	eventFirmwareStateWipeRefused = "vm.firmware_wipe_refused"
	// maxFirmwareWipesNamed bounds the refused wipes the evidence lists (the
	// newest); wipes_refused_total counts them all. Each is also an event.
	maxFirmwareWipesNamed          = 64
	firmwareRecordUnreadableRemedy = "repair the file, or move it out of its directory once no firmware move on this host needs it " +
		"(a marker under fwmig-inflight/ or a hold under fwmig-hold/ is that move's start veto and its record of the state to keep); " +
		"the condition resolves within a pass once every file reads"
)

// judgeFirmwareMoveRecords raises firmware_migration_record_unreadable for
// this host while any marker or hold file cannot be read, naming each file,
// the remedy, and every firmware state wipe such a file refused (each also a
// vm.firmware_wipe_refused event on its VM: the state it was to remove is
// still on disk). It resolves the condition once every file reads.
func (s *Server) judgeFirmwareMoveRecords(ctx context.Context) {
	fw := s.fw()
	refused := fw.TakeRefusedWipes()
	for _, w := range refused {
		detail := fmt.Sprintf("the firmware state of %s (uuid %s) was not removed: %v; it is still on disk, and %s names it",
			w.VM, w.UUID, w.Err, condFirmwareRecordUnreadable)
		slog.Warn("firmware state wipe refused for an unreadable firmware move record", "vm", w.VM, "uuid", w.UUID, "error", w.Err)
		if w.VM != "" {
			s.recordVMEventSeverity(ctx, w.VM, eventFirmwareStateWipeRefused, "error", "error", detail)
		}
	}
	bad := fwmig.New(fw.DataDir).Unreadable()

	s.fwRecordsMu.Lock()
	s.fwWipesRefused = append(s.fwWipesRefused, refused...)
	s.fwWipesRefusedTotal += len(refused)
	if n := len(s.fwWipesRefused); n > maxFirmwareWipesNamed {
		s.fwWipesRefused = append([]lv.RefusedWipe(nil), s.fwWipesRefused[n-maxFirmwareWipesNamed:]...)
	}
	if len(bad) == 0 {
		s.fwWipesRefused, s.fwWipesRefusedTotal = nil, 0
	}
	wipes, wipesTotal := toRefusedWipes(s.fwWipesRefused), s.fwWipesRefusedTotal
	s.fwRecordsMu.Unlock()
	if s.db == nil {
		return
	}

	subject := s.hostName
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, firmwareMoveEvaluator, condFirmwareRecordUnreadable, "host", subject)
	if err != nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if len(bad) == 0 {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("firmware move: resolve the unreadable record condition", "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: firmwareMoveEvaluator, Code: condFirmwareRecordUnreadable,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityCritical
	type file struct {
		Path  string `json:"path"`
		Error string `json:"error"`
	}
	var files []file
	for _, b := range bad {
		files = append(files, file{Path: b.Path, Error: fmt.Sprint(b.Err)})
	}
	ev, _ := json.Marshal(map[string]any{
		"host": s.hostName, "files": files, "wipes_refused": wipes, "wipes_refused_total": wipesTotal,
		"detail": fmt.Sprintf("%d firmware move record file(s) under %s cannot be read; until each reads, the firmware move guard refuses "+
			"every operation such a file might name on %s — any define, firmware state restore or wipe that carries a uuid, and any "+
			"operation on the VM a file is named after", len(files), fw.DataDir, s.hostName),
		"remedy": firmwareRecordUnreadableRemedy,
		"dirs":   []string{filepath.Join(fw.DataDir, fwmig.InflightDir), filepath.Join(fw.DataDir, fwmig.HoldDir)},
	})
	row.Evidence = string(ev)
	row.Hosts = []string{s.hostName}
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("firmware move: raise the unreadable record condition", "error", err)
	}
}

// lvRefusedWipe is a refused wipe as the condition's evidence names it.
type lvRefusedWipe struct {
	VM    string `json:"vm,omitempty"`
	UUID  string `json:"uuid,omitempty"`
	At    string `json:"at"`
	Error string `json:"error"`
}

func toRefusedWipes(ws []lv.RefusedWipe) []lvRefusedWipe {
	out := make([]lvRefusedWipe, 0, len(ws))
	for _, w := range ws {
		out = append(out, lvRefusedWipe{VM: w.VM, UUID: w.UUID, At: w.At.UTC().Format(time.RFC3339), Error: fmt.Sprint(w.Err)})
	}
	return out
}
