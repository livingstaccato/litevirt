package daemon

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/pooltrust"
	"github.com/litevirt/litevirt/internal/storage"
)

// openPoolTrust opens this host's pool trust ledger, gives it the pools
// config.yaml defines, and until the ledger records that the adoption ran
// adopts the existing pools this host's disk shows in use
// (pooltrust.AdoptOnUpgrade). A ledger
// that cannot be read is kept aside and trusts none of its entries; the
// pools it held are named by pool_row_untrusted.
//
// The daemon's own pools — the implicit default pool (registered as
// "default") and the global ISO library — are recorded in the ledger by the
// code that writes their rows (ensureOwnPoolTrusted), so they never depend
// on where <data_dir>/pools or <data_dir>/disks resolve.
func (d *Daemon) openPoolTrust(ctx context.Context) {
	pt, err := pooltrust.Open(d.cfg.DataDir, d.cfg.PKIDir)
	if err != nil {
		slog.Error("storage pool trust ledger unreadable; it was kept aside, and the pools it held are untrusted until confirmed with `lv pool trust`", "error", err)
	}
	cfg := map[string]pooltrust.Binding{}
	for name, r := range d.storagePoolRefs() {
		cfg[name] = pooltrust.BindingOf(r.Driver, r.Source, r.Target, r.Options)
	}
	for _, p := range d.cfg.StoragePools {
		cfg[p.Name] = pooltrust.BindingOf(p.Driver, p.Source, p.Target, p.Options)
	}
	// With no storage_pools in config, the in-memory map names the implicit
	// pool "litevirt" (storagePoolRefs) while registerStoragePools writes its
	// row as "default": both names are this host's config pool.
	if len(d.cfg.StoragePools) == 0 && d.db != nil {
		cfg["default"] = pooltrust.BindingOf("local", "", d.defaultPoolDir(ctx), nil)
	}
	pt.SetConfig(cfg)
	d.poolTrust = pt
	if d.db != nil {
		// The adoption first, then the daemon's own rows, whatever the
		// adoption made of them. (The adoption runs until the ledger records
		// that it ran, so the order is a second guard, not the only one.)
		a, err := pt.AdoptOnUpgrade(ctx, d.db, d.cfg.HostName)
		d.ensureOwnPoolsTrusted(ctx)
		switch {
		case err != nil:
			slog.Error("storage pool trust: existing pools not adopted; retried at the next start", "error", err)
		case a.Ran:
			slog.Info("storage pool trust: upgrade adoption ran (the ledger did not record one: first start with the ledger, or it was removed); existing pools adopted",
				"ledger", pt.Path(), "adopted", a.Adopted, "held_untrusted", a.Held)
			for _, h := range a.Held {
				slog.Warn("storage pool trust: an existing pool row is held untrusted; check it and confirm with `lv pool trust <pool>` if it is this host's", "pool", h)
			}
		}
	}
}

// ensureOwnPoolsTrusted records the daemon's own pools in the ledger: the
// implicit default pool (when config names none) at the directory the daemon
// registers it with, and the global ISO library when its row is exactly the
// one the daemon makes (dir, no project, <data_dir>/pools/isos). A row of
// either name that the daemon would not have written is not recorded.
func (d *Daemon) ensureOwnPoolsTrusted(ctx context.Context) {
	if len(d.cfg.StoragePools) == 0 {
		d.ensureOwnPoolTrusted("default", "local", "", d.defaultPoolDir(ctx), nil)
	}
	if rec, ok, err := corrosion.GetStoragePool(ctx, d.db, d.cfg.HostName, grpcapi.GlobalISOLibraryName); err == nil && ok && d.isDaemonISOLibraryRow(rec) {
		d.ensureOwnPoolTrusted(rec.Name, rec.Driver, rec.Source, rec.Target, rec.Options)
	}
}

// isDaemonISOLibraryRow reports whether rec is the global ISO library row
// this daemon makes: dir, global, at exactly <data_dir>/pools/isos.
func (d *Daemon) isDaemonISOLibraryRow(rec corrosion.StoragePoolRecord) bool {
	return rec.Name == grpcapi.GlobalISOLibraryName && rec.Project == "" && strings.EqualFold(rec.Driver, "dir") &&
		rec.Source == "" && filepath.Clean(rec.Target) == filepath.Join(d.cfg.DataDir, storage.ISOLibraryDir)
}

// ensureOwnPoolTrusted records in the ledger one of the daemon's own pools,
// with the binding the daemon writes (or finds written by itself) for it.
func (d *Daemon) ensureOwnPoolTrusted(name, driver, source, target string, opts map[string]string) {
	if d.poolTrust == nil {
		return
	}
	if err := d.poolTrust.Ensure(name, pooltrust.BindingOf(driver, source, target, opts), pooltrust.HowDaemon); err != nil {
		slog.Warn("storage pool trust: the daemon's own pool not recorded in the ledger", "pool", name, "error", err)
	}
}

// poolRowTrusted reports whether this host acts on its row r. With no store
// (a daemon built in a unit test without Run) every row is acted on.
func (d *Daemon) poolRowTrusted(r corrosion.StoragePoolRecord) bool {
	return d.poolTrust.Judge(r.Name, pooltrust.BindingOf(r.Driver, r.Source, r.Target, r.Options)).Trusted
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
