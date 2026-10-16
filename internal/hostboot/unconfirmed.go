package hostboot

import (
	"context"
	"encoding/json"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The condition a host raises about itself while it is recorded 'upgrading'
// past UpgradingTimeout although its daemon runs: the boot's serving check
// has not recorded it active (its own Ping does not answer, or the write
// fails). Peers that reach it never fence it, so nothing else would show it:
// it stays unplaceable, listed as draining, until the check succeeds or an
// operator undrains it. One writer per row (the host it is about).
const (
	BootEvaluator            = "host_boot"
	CondUpgradingUnconfirmed = "upgrading_unconfirmed"
)

// UnconfirmedRemedy is what the condition and the log tell an operator.
const UnconfirmedRemedy = "fix what the cause names (the daemon's own mTLS client, its listener on 127.0.0.1, " +
	"or the write); once this daemon confirms it serves it records the host active by itself. " +
	"Or run 'lv host undrain <host>' to record it active now"

// UpgradingState reports whether host is recorded 'upgrading' in db and, if
// so, since when (corrosion.HostStateSince; zero when unreadable). err is a
// read error, which decides nothing.
func UpgradingState(ctx context.Context, db *corrosion.Client, host string) (since time.Time, upgrading bool, err error) {
	h, err := corrosion.GetHost(ctx, db, host)
	if err != nil {
		return time.Time{}, false, err
	}
	if h == nil || h.State != "upgrading" {
		return time.Time{}, false, nil
	}
	at, ok, err := corrosion.HostStateSince(ctx, db, host)
	if err != nil || !ok {
		return time.Time{}, true, nil
	}
	return at, true, nil
}

// RaiseUpgradingUnconfirmed raises (or refreshes) host's
// upgrading_unconfirmed condition, warning severity, with cause and since in
// its evidence.
func RaiseUpgradingUnconfirmed(ctx context.Context, db *corrosion.Client, host, cause string, since, now time.Time) error {
	b, _ := json.Marshal(struct {
		Cause          string `json:"cause"`
		UpgradingSince string `json:"upgrading_since"`
		Remedy         string `json:"remedy"`
	}{cause, since.UTC().Format(time.RFC3339), UnconfirmedRemedy})
	return writeHostCondition(ctx, db, CondUpgradingUnconfirmed, host, string(b), now, false)
}

// ResolveUpgradingUnconfirmed resolves host's upgrading_unconfirmed condition
// if one is open, including one an earlier process left.
func ResolveUpgradingUnconfirmed(ctx context.Context, db *corrosion.Client, host string, now time.Time) error {
	return writeHostCondition(ctx, db, CondUpgradingUnconfirmed, host, "", now, true)
}

// writeHostCondition raises (resolve=false) or resolves host's host_boot
// condition code about itself.
func writeHostCondition(ctx context.Context, db *corrosion.Client, code, host, evidence string, now time.Time, resolve bool) error {
	ts := now.UTC().Format(time.RFC3339)
	row, ok, err := corrosion.GetHealthCondition(ctx, db, BootEvaluator, code, "host", host)
	if err != nil {
		return err
	}
	if !ok {
		if resolve {
			return nil
		}
		row = corrosion.HealthCondition{Evaluator: BootEvaluator, Code: code,
			SubjectKind: "host", SubjectID: host, FirstSeen: ts}
	}
	if resolve {
		if row.Lifecycle == corrosion.ConditionResolved {
			return nil
		}
		row.Lifecycle, row.ResolvedAt, row.ObserveCount, row.CleanCount = corrosion.ConditionResolved, ts, 0, 1
	} else {
		if row.Lifecycle == corrosion.ConditionResolved {
			row.FirstSeen, row.ConfirmedAt, row.ObserveCount = ts, "", 0
		}
		row.Lifecycle, row.ResolvedAt, row.CleanCount = corrosion.ConditionConfirmed, "", 0
		if row.ConfirmedAt == "" {
			row.ConfirmedAt = ts
		}
		row.ObserveCount++
		row.Evidence = evidence
	}
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = corrosion.SeverityWarning, []string{host}, ts, host
	return corrosion.UpsertHealthCondition(ctx, db, row)
}
