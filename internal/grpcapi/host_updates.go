package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostupdates"
	"github.com/litevirt/litevirt/internal/notify"
)

// HostUpdatesConfig is host_updates in the daemon config.
type HostUpdatesConfig struct {
	Enabled      bool
	Interval     time.Duration
	RefreshIndex bool
	// Check replaces the package-manager probe (tests only).
	Check func(context.Context) hostupdates.Status
}

// SetHostUpdates configures the pending-OS-update check (host_updates).
func (s *Server) SetHostUpdates(cfg HostUpdatesConfig) { s.hostUpdates = cfg }

// RunHostUpdateLoop checks this host's pending OS package updates on an
// interval and publishes the result as host labels, a metric (the collector
// reads the labels back) and a notification. It is read-only: nothing is
// installed, and the package index is refreshed only when host_updates.
// refresh_index is set.
func (s *Server) RunHostUpdateLoop(ctx context.Context) {
	cfg := s.hostUpdates
	if !cfg.Enabled {
		return
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Minute):
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		s.CheckHostUpdatesOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// CheckHostUpdatesOnce runs one check and publishes it. A notification goes
// out only when the counts differ from what this host last published (read
// back off its own record, so a daemon restart does not repeat itself), and
// only when something is pending: security updates are a warning, the rest
// info. A check that failed publishes "unknown" and notifies nothing.
func (s *Server) CheckHostUpdatesOnce(ctx context.Context) {
	cfg := s.hostUpdates
	check := cfg.Check
	if check == nil {
		check = func(ctx context.Context) hostupdates.Status {
			cctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
			defer cancel()
			return hostupdates.Check(cctx, hostupdates.Options{RefreshIndex: cfg.RefreshIndex})
		}
	}
	st := check(ctx)
	if !st.Supported {
		return
	}
	var prevP, prevS int
	prevKnown := false
	if h, err := corrosion.GetHost(ctx, s.db, s.hostName); err == nil && h != nil {
		prevP, prevS, prevKnown = hostupdates.FromLabels(h.Labels)
	}
	for k, v := range st.Labels() {
		if err := corrosion.SetHostLabel(ctx, s.db, s.hostName, k, v); err != nil {
			slog.Warn("host updates: publish label failed", "label", k, "error", err)
		}
	}
	if st.Err != "" {
		slog.Warn("host updates: check incomplete", "manager", st.Manager, "error", st.Err)
	}
	if st.Pending == 0 || (st.Err != "" && len(st.Packages) == 0) {
		return
	}
	if prevKnown && prevP == st.Pending && prevS == st.Security {
		return
	}
	kind, sev := "host.updates", notify.SevInfo
	detail := fmt.Sprintf("%d package update(s) pending via %s", st.Pending, st.Manager)
	if st.Security > 0 {
		kind, sev = "host.security_updates", notify.SevWarn
		detail = fmt.Sprintf("%d package update(s) pending via %s, %d of them security", st.Pending, st.Manager, st.Security)
	}
	if names := st.Names(8); len(names) > 0 {
		detail += ": " + strings.Join(names, ", ")
		if st.Pending > len(names) {
			detail += ", ..."
		}
	}
	s.notify(ctx, notify.Notification{Kind: kind, Severity: sev, Subject: s.hostName, Detail: detail})
}
