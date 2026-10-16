package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The conditions of a live firmware move (spec §14): evaluator
// firmware_migration, subject the VM. Each names the VM, the attempt, both
// hosts, the hashes and the paths it is about. Critical unless the spec says
// otherwise: discard_owed and quarantine are warnings (a refused owed DISCARD
// raises discard_owed as critical, by Severity), and so is held, which a long
// storage copy reaches in a move that is going well.
const (
	firmwareMigrationEvaluator = "firmware_migration"

	condFwmigUnverified         = "firmware_migration_unverified"
	condFwmigSourceStateMissing = "firmware_migration_source_state_missing"
	condFwmigSourceStateSuspect = "firmware_migration_source_state_suspect"
	condFwmigTargetRan          = "firmware_migration_target_ran"
	condFwmigSourcePaused       = "firmware_migration_source_paused"
	condFwmigDiscardOwed        = "firmware_migration_discard_owed"
	condFwmigTargetUnreachable  = "firmware_migration_target_unreachable"
	condFwmigNvramUnconfirmed   = "firmware_migration_nvram_unconfirmed"
	condFwmigHeld               = "firmware_migration_held"
	condFwmigQuarantine         = "firmware_migration_quarantine"
)

// firmwareMigrationConditionSeverity is each code's default severity.
var firmwareMigrationConditionSeverity = map[string]string{
	condFwmigUnverified:         corrosion.SeverityCritical,
	condFwmigSourceStateMissing: corrosion.SeverityCritical,
	condFwmigSourceStateSuspect: corrosion.SeverityCritical,
	condFwmigTargetRan:          corrosion.SeverityCritical,
	condFwmigSourcePaused:       corrosion.SeverityCritical,
	condFwmigDiscardOwed:        corrosion.SeverityWarning,
	condFwmigTargetUnreachable:  corrosion.SeverityCritical,
	condFwmigNvramUnconfirmed:   corrosion.SeverityCritical,
	condFwmigHeld:               corrosion.SeverityWarning,
	condFwmigQuarantine:         corrosion.SeverityWarning,
}

// fwmigCondition is one raise of a firmware move condition.
type fwmigCondition struct {
	Code     string
	VM       string
	Attempt  string
	Source   string
	Target   string
	Severity string            // "" = the code's default
	Hashes   map[string]string // every hash the condition is about, by name
	Paths    []string          // the records, quarantine or state it names
	Detail   string
	Action   string // what resolves it, when an operator must
}

// raiseFirmwareMigrationCondition raises c (or refreshes it), from this host.
// A move's condition is a fact the move recorded, not a scan's observation,
// so it is confirmed at once.
func (s *Server) raiseFirmwareMigrationCondition(ctx context.Context, c fwmigCondition) error {
	def, ok := firmwareMigrationConditionSeverity[c.Code]
	if !ok {
		return fmt.Errorf("firmware move condition %q is not one of the move's codes", c.Code)
	}
	if c.VM == "" {
		return fmt.Errorf("firmware move condition %s: no VM", c.Code)
	}
	sev := c.Severity
	if sev == "" {
		sev = def
	}
	if s.db == nil {
		return nil
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, c.Code, "vm", c.VM)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: firmwareMigrationEvaluator, Code: c.Code, SubjectKind: "vm", SubjectID: c.VM,
			FirstSeen: now, ConfirmedAt: now}
	}
	row.Lifecycle, row.Severity = corrosion.ConditionConfirmed, sev
	if row.ConfirmedAt == "" {
		row.ConfirmedAt = now
	}
	row.ObserveCount++
	row.CleanCount = 0
	ev, err := json.Marshal(map[string]any{
		"vm": c.VM, "attempt": c.Attempt, "source": c.Source, "target": c.Target, "host": s.hostName,
		"hashes": c.Hashes, "paths": c.Paths, "detail": c.Detail, "action": c.Action,
	})
	if err != nil {
		return err
	}
	row.Evidence = string(ev)
	row.Hosts = []string{s.hostName}
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	return corrosion.UpsertHealthCondition(ctx, s.db, row)
}

// resolveFirmwareMigrationCondition resolves code for vm; absent or already
// resolved is nothing to do.
func (s *Server) resolveFirmwareMigrationCondition(ctx context.Context, code, vm string) error {
	if _, ok := firmwareMigrationConditionSeverity[code]; !ok {
		return fmt.Errorf("firmware move condition %q is not one of the move's codes", code)
	}
	if s.db == nil {
		return nil
	}
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, firmwareMigrationEvaluator, code, "vm", vm)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		return err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
	row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
	return corrosion.UpsertHealthCondition(ctx, s.db, row)
}
