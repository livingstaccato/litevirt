package daemon

import (
	"context"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pooltrust"
)

// openPoolTrust opens this host's pool trust ledger, gives it the pools
// config.yaml defines, and on the first start of a build that keeps the
// ledger adopts the existing pools this host's disk shows in use
// (pooltrust.AdoptOnUpgrade). A ledger that cannot be read trusts none of
// its entries; the pools it held are named by pool_row_untrusted.
func (d *Daemon) openPoolTrust(ctx context.Context) {
	pt, err := pooltrust.Open(d.cfg.DataDir, d.cfg.PKIDir)
	if err != nil {
		slog.Error("storage pool trust ledger unreadable; the pools it held are untrusted until confirmed with `lv pool trust`", "error", err)
	}
	cfg := map[string]pooltrust.Binding{}
	for name, r := range d.storagePoolRefs() {
		cfg[name] = pooltrust.BindingOf(r.Driver, r.Source, r.Target)
	}
	pt.SetConfig(cfg)
	if d.db != nil {
		a, err := pt.AdoptOnUpgrade(ctx, d.db, d.cfg.HostName)
		switch {
		case err != nil:
			slog.Error("storage pool trust: existing pools not adopted; retried at the next start", "error", err)
		case a.Ran:
			slog.Info("storage pool trust: first start with the ledger; existing pools adopted",
				"ledger", pt.Path(), "adopted", a.Adopted, "held_untrusted", a.Held)
			for _, h := range a.Held {
				slog.Warn("storage pool trust: an existing pool row is held untrusted; check it and confirm with `lv pool trust <pool>` if it is this host's", "pool", h)
			}
		}
	}
	d.poolTrust = pt
}

// poolRowTrusted reports whether this host acts on its row r. With no store
// (a daemon built in a unit test without Run) every row is acted on.
func (d *Daemon) poolRowTrusted(r corrosion.StoragePoolRecord) bool {
	return d.poolTrust.Judge(r.Name, pooltrust.BindingOf(r.Driver, r.Source, r.Target)).Trusted
}

// trustedOwnPools is this host's pool rows that it trusts.
func (d *Daemon) trustedOwnPools(ctx context.Context) ([]corrosion.StoragePoolRecord, error) {
	rows, err := corrosion.ListStoragePoolsForHost(ctx, d.db, d.cfg.HostName)
	if err != nil {
		return nil, err
	}
	out := rows[:0:0]
	for _, r := range rows {
		if d.poolRowTrusted(r) {
			out = append(out, r)
		}
	}
	return out, nil
}
