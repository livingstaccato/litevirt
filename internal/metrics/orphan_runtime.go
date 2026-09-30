package metrics

import "github.com/prometheus/client_golang/prometheus"

// OrphanRuntimeMetrics exports the orphan-runtime report
// (internal/health/orphan_runtime.go): one series per litevirt runtime this
// host is running with no live record, labelled with the host and the
// workload's name. A series exists only while its orphan is reported, so an
// alert on `litevirt_orphan_runtime > 0` names what to look at.
type OrphanRuntimeMetrics struct {
	gauge *prometheus.GaugeVec
}

// OrphanRuntimeSample is one reported orphan, as the gauge labels it.
type OrphanRuntimeSample struct {
	Name string
	Row  string // "missing" | "tombstoned"
}

// NewOrphanRuntimeMetrics registers litevirt_orphan_runtime on the default
// registry. Call once at daemon startup.
func NewOrphanRuntimeMetrics() *OrphanRuntimeMetrics {
	return newOrphanRuntimeMetrics(prometheus.DefaultRegisterer)
}

func newOrphanRuntimeMetrics(reg prometheus.Registerer) *OrphanRuntimeMetrics {
	m := &OrphanRuntimeMetrics{
		gauge: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_orphan_runtime",
			Help: "1 for each litevirt-created runtime this host runs with no live record " +
				"(kind vm|ct, host, name, row missing|tombstoned). Report-only: nothing reaps it.",
		}, []string{"kind", "host", "name", "row"}),
	}
	reg.MustRegister(m.gauge)
	return m
}

// Set replaces every series of one kind with the pass's complete set.
func (m *OrphanRuntimeMetrics) Set(kind, host string, orphans []OrphanRuntimeSample) {
	m.gauge.DeletePartialMatch(prometheus.Labels{"kind": kind})
	for _, o := range orphans {
		m.gauge.WithLabelValues(kind, host, o.Name, o.Row).Set(1)
	}
}
