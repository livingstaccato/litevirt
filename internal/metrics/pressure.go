package metrics

import (
	"strings"

	"github.com/litevirt/litevirt/internal/pressure"
	"github.com/prometheus/client_golang/prometheus"
)

// PressureMetrics exposes this host's resource-pressure sampler
// (internal/pressure). Every method is nil-safe.
type PressureMetrics struct {
	level *prometheus.GaugeVec
	free  *prometheus.GaugeVec
	ttf   *prometheus.GaugeVec
}

// NewPressureMetrics registers the series on the default registry.
func NewPressureMetrics() *PressureMetrics { return newPressureMetrics(prometheus.DefaultRegisterer) }

// NewPressureMetricsWith registers on the given registry (tests).
func NewPressureMetricsWith(reg prometheus.Registerer) *PressureMetrics {
	return newPressureMetrics(reg)
}

func newPressureMetrics(reg prometheus.Registerer) *PressureMetrics {
	m := &PressureMetrics{
		level: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_host_pressure_level",
			Help: "This host's resource-pressure level per resource (0 ok, 1 warn, 2 degrade, 3 critical); resource=\"host\" is the worst over all of them.",
		}, []string{"resource"}),
		free: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_host_free_bytes",
			Help: "Bytes free to the daemon (f_bavail) on the filesystem of the data directory (fs=\"data_dir\") or of a storage pool (fs=\"pool.<name>\").",
		}, []string{"fs"}),
		ttf: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_host_time_to_full_seconds",
			Help: "Projected seconds until a filesystem resource has nothing free at its fill rate over pressure.trend_window_sec; absent while it is not filling.",
		}, []string{"resource"}),
	}
	reg.MustRegister(m.level, m.free, m.ttf)
	return m
}

// Observe publishes one sampler report. A resource no longer sampled (a
// removed pool) drops its series.
func (m *PressureMetrics) Observe(r pressure.Report) {
	if m == nil {
		return
	}
	m.level.Reset()
	m.free.Reset()
	m.ttf.Reset()
	m.level.WithLabelValues("host").Set(float64(r.Level))
	for _, res := range r.Resources {
		m.level.WithLabelValues(res.Name).Set(float64(res.Level))
		if fs, ok := strings.CutSuffix(res.Name, ".space"); ok && res.Err == "" {
			m.free.WithLabelValues(fs).Set(float64(res.Free))
		}
		if res.TimeToFull > 0 {
			m.ttf.WithLabelValues(res.Name).Set(res.TimeToFull.Seconds())
		}
	}
}
