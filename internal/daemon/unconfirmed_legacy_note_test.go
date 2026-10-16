package daemon

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostboot"
	"github.com/litevirt/litevirt/internal/metrics"
)

// The remaining legacy note-only path resolves an earlier process's durable
// diagnostic from actual non-upgrading state before Ping, even without a dial.
func TestLegacyActiveBootNoteResolvesPersistedUnconfirmed(t *testing.T) {
	for _, dialFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "unanswered-ping", true: "unavailable-dial"}[dialFails], func(t *testing.T) {
			d, db, ctx := upgradingHost(t)
			since, ok, err := corrosion.HostStateSince(ctx, db, "h")
			if err != nil || !ok {
				t.Fatalf("upgrading time: %v %v", ok, err)
			}
			if err := hostboot.RaiseUpgradingUnconfirmed(ctx, db, "h", "legacy predecessor", since, time.Now()); err != nil {
				t.Fatal(err)
			}
			prior, _ := unconfirmedRow(t, ctx, db)
			metrics.SetUpgradingUnconfirmed(true)
			if err := corrosion.UpdateHostState(ctx, db, "h", "active"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hostboot.AwaitingPath(d.cfg.DataDir), []byte("legacy awaiting note"), 0o600); err != nil {
				t.Fatal(err)
			}
			serving := make(chan struct{})
			d.selfPinger = func() (pinger, func(), error) {
				if dialFails {
					return nil, nil, errors.New("private fixture dial unavailable")
				}
				return &gatedPinger{open: serving}, func() {}, nil
			}
			cctx, cancel := context.WithCancel(ctx)
			done := make(chan struct{})
			go func() {
				defer close(done)
				d.awaitServingThenNote(cctx)
			}()
			t.Cleanup(func() { cancel(); waitCheckDone(t, done) })
			waitLifecycle(t, "legacy non-upgrading diagnostic resolution before Ping", func() bool {
				row, ok := unconfirmedRow(t, ctx, db)
				return ok && row.Lifecycle == corrosion.ConditionResolved && row.FirstSeen == prior.FirstSeen && row.Evidence == prior.Evidence && unconfirmedGauge(t) == 0
			})
			if _, err := os.Stat(hostboot.AwaitingPath(d.cfg.DataDir)); err != nil {
				t.Fatalf("note was removed without serving evidence: %v", err)
			}
			close(serving)
			waitCheckDone(t, done)
			if !dialFails {
				if _, err := os.Stat(hostboot.AwaitingPath(d.cfg.DataDir)); !os.IsNotExist(err) {
					t.Fatalf("successful own Ping left legacy note: %v", err)
				}
			}
		})
	}
}
