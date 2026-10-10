package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/notify"
	"github.com/litevirt/litevirt/internal/smart"
)

// SMART notification Kinds (stable — routes subscribe to them; see
// docs/notifications.md).
const (
	kindDiskSMARTFailing   = "disk.smart.failing"
	kindDiskSMARTWarning   = "disk.smart.warning"
	kindDiskSMARTPrefail   = "disk.smart.prefail"
	kindDiskSMARTRecovered = "disk.smart.recovered"
)

// SetSMARTMetrics attaches the per-host disk SMART gauges.
func (s *Server) SetSMARTMetrics(m *metrics.SMARTMetrics) { s.smartMetrics = m }

// smartTransitions turns one SMART pass into the notifications it warrants and
// the new per-device state. A device pages when it ENTERS (or worsens into) a
// bad state and says so once when it recovers; it does not re-page every pass.
// "unknown" never changes state: a smartctl hiccup must neither page nor
// clear a standing failure.
func smartTransitions(host string, prev map[string]smart.Status, disks []smart.Disk) ([]notify.Notification, map[string]smart.Status) {
	next := make(map[string]smart.Status, len(disks))
	var out []notify.Notification
	for _, d := range disks {
		// Keyed by the disk's identity (serial/WWN) so a rename across a reboot
		// neither re-pages a standing failure nor strands its state.
		key := d.ID
		if key == "" {
			key = d.Device
		}
		old, seen := prev[key]
		st := d.Status
		if st == smart.Unknown {
			if seen {
				next[key] = old
			}
			continue
		}
		next[key] = st
		if seen && old == st {
			continue
		}
		model := d.Model
		if model == "" {
			model = "unknown model"
		}
		n := notify.Notification{Subject: fmt.Sprintf("%s:%s", host, d.Device), Detail: fmt.Sprintf("%s (%s, id %s)", st.Detail(), model, key)}
		switch st {
		case smart.Failing:
			n.Kind, n.Severity = kindDiskSMARTFailing, notify.SevError
		case smart.Warning:
			n.Kind, n.Severity = kindDiskSMARTWarning, notify.SevWarn
		case smart.Prefail:
			n.Kind, n.Severity = kindDiskSMARTPrefail, notify.SevWarn
		case smart.OK:
			if old != smart.Prefail && old != smart.Failing && old != smart.Warning {
				continue // first sighting of a healthy disk is not news
			}
			n.Kind, n.Severity = kindDiskSMARTRecovered, notify.SevInfo
		}
		out = append(out, n)
	}
	return out, next
}

// RunSMARTMonitor checks this host's disks every interval, publishes the
// litevirt_disk_smart_* gauges and notifies on a disk going prefail/failing.
// Informational only: nothing here fences, drains or blocks a workload, and a
// host with no smartctl simply reports unknown.
func (s *Server) RunSMARTMonitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	run := s.smartRunner
	if run == nil {
		run = smart.ExecRunner
	}
	prev := map[string]smart.Status{}
	warnedMissing := false
	pass := func() {
		rep := smart.Check(ctx, run)
		if !rep.Available && !warnedMissing {
			slog.Info("smart: smartctl not available; disk SMART health will report unknown")
			warnedMissing = true
		}
		md := make([]metrics.SMARTDisk, 0, len(rep.Disks))
		for _, d := range rep.Disks {
			md = append(md, metrics.SMARTDisk{Device: d.Device, Model: d.Model, Status: d.Status.String()})
		}
		s.smartMetrics.Set(rep.Available, md)
		var ns []notify.Notification
		ns, prev = smartTransitions(s.hostName, prev, rep.Disks)
		for _, n := range ns {
			slog.Warn("smart: disk health change", "subject", n.Subject, "kind", n.Kind)
			s.notify(ctx, n)
		}
	}
	pass()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pass()
		}
	}
}
