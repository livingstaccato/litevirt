package daemon

import (
	"context"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/firewall"
)

// openFirewallLogStore opens this host's firewall log store under
// <data_dir>/firewall-log/ with the config's bounds. A directory it cannot
// use leaves a store that keeps records in memory only.
func openFirewallLogStore(cfg *Config, counter firewall.LogCounter) *firewall.LogStore {
	opts := firewall.LogStoreOptions{
		Dir:          filepath.Join(cfg.DataDir, "firewall-log"),
		MaxRate:      cfg.Firewall.LogMaxRate,
		RetainBytes:  int64(cfg.Firewall.LogRetainMiB) << 20,
		RetainAge:    time.Duration(cfg.Firewall.LogRetainDays) * 24 * time.Hour,
		Counter:      counter,
		SeqFromClock: true,
	}
	s, err := firewall.OpenLogStore(opts)
	if err == nil {
		return s
	}
	slog.Warn("firewall log: cannot use the log directory; records are kept in memory only", "error", err)
	opts.Dir = ""
	s, _ = firewall.OpenLogStore(opts)
	return s
}

// pruneFirewallLog applies the store's age bound while no record arrives.
func pruneFirewallLog(ctx context.Context, s *firewall.LogStore) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			s.Close()
			return
		case <-t.C:
			s.Prune()
		}
	}
}

// firewallLogging is the daemon's firewall-logging wiring: the loader's
// Logging answers through a firewall.LogGate (available only while the
// probe passed and the listener holds the group), the listener's bind report
// feeds the gate and the condition, and each change runs a pass now and a
// follow-up one, so a pass that loaded its plan before the change cannot
// leave the old one applied.
type firewallLogging struct {
	gate      *firewall.LogGate
	reconcile func(context.Context) error
	record    func(error)
	followUp  time.Duration
}

func newFirewallLogging(ctx context.Context, group uint16, probeErr error, reconcile func(context.Context) error, record func(error)) *firewallLogging {
	f := &firewallLogging{reconcile: reconcile, record: record, followUp: 2 * time.Second}
	f.gate = firewall.NewLogGate(group, probeErr, func() { go f.passes(ctx) })
	return f
}

// Logging is LoaderOptions.Logging.
func (f *firewallLogging) Logging() (bool, uint16) { return f.gate.Logging() }

// OnBind is LogListener.OnBind.
func (f *firewallLogging) OnBind(err error) {
	f.gate.OnBind(err)
	f.record(err)
}

func (f *firewallLogging) passes(ctx context.Context) {
	for i := 0; i < 2; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(f.followUp):
			}
		}
		if err := f.reconcile(ctx); err != nil {
			slog.Warn("firewall: the pass after a log listener change failed; the next tick retries", "error", err)
		}
	}
}

// Stop turns logging off for good and, when lines may have been rendered,
// runs one pass at once to remove them (a daemon that is stopping holds the
// group no longer).
func (f *firewallLogging) Stop(ctx context.Context) {
	if !f.gate.Stop() {
		return
	}
	if err := f.reconcile(ctx); err != nil {
		slog.Warn("firewall: could not remove the log lines at stop; another program could take the NFLOG group while litevirtd is down", "error", err)
	}
}
