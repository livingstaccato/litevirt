package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	upgradeWatchdogOnce  sync.Once
	upgradeWatchdogTotal *prometheus.CounterVec
)

// UpgradeWatchdogOutcome records a post-upgrade health-watchdog outcome:
//
//	confirmed | confirm_failed | rollback | giveup | no_old
//
// It registers lazily on the default registry on first use, so it works even
// when called before the metrics HTTP server is constructed — the watchdog arms
// very early in daemon startup (and may roll back + exit before that server runs).
func UpgradeWatchdogOutcome(outcome string) {
	upgradeWatchdogOnce.Do(func() {
		upgradeWatchdogTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_upgrade_watchdog_total",
			Help: "Post-upgrade health-watchdog outcomes (confirmed, confirm_failed, rollback, giveup, no_old).",
		}, []string{"outcome"})
		prometheus.DefaultRegisterer.MustRegister(upgradeWatchdogTotal)
	})
	upgradeWatchdogTotal.WithLabelValues(outcome).Inc()
}

var (
	upgradingUnconfirmedOnce  sync.Once
	upgradingUnconfirmedGauge prometheus.Gauge
)

// SetUpgradingUnconfirmed sets litevirt_host_upgrading_unconfirmed: 1 while
// this host is recorded 'upgrading' past its upgrading window although its
// daemon runs, and the boot's serving check has not recorded it active
// (hostboot.CondUpgradingUnconfirmed). Registered lazily, as
// UpgradeWatchdogOutcome.
func SetUpgradingUnconfirmed(on bool) {
	upgradingUnconfirmedOnce.Do(func() {
		upgradingUnconfirmedGauge = prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_host_upgrading_unconfirmed",
			Help: "1 while this host is recorded upgrading past its upgrading window although its daemon runs, and has not recorded itself active.",
		})
		prometheus.DefaultRegisterer.MustRegister(upgradingUnconfirmedGauge)
	})
	v := 0.0
	if on {
		v = 1
	}
	upgradingUnconfirmedGauge.Set(v)
}
