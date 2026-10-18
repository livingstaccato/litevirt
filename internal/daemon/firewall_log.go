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
