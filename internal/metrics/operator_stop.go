package metrics

import "github.com/prometheus/client_golang/prometheus"

// OperatorStopMetrics is the operator-stop marker gauge (docs/upgrades.md,
// "`lv stop --force` on a quarantined host").
type OperatorStopMetrics struct {
	markers *prometheus.GaugeVec
}

// NewOperatorStopMetrics registers the gauge on the default registry. Call
// once at daemon startup.
func NewOperatorStopMetrics() *OperatorStopMetrics {
	return newOperatorStopMetrics(prometheus.DefaultRegisterer)
}

func newOperatorStopMetrics(reg prometheus.Registerer) *OperatorStopMetrics {
	m := &OperatorStopMetrics{
		markers: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_operator_stop_markers",
			Help: "Forced stops this host made under write quarantine and holds in local markers. state=pending: " +
				"not yet recorded on the VM (recorded once the quarantine lifts); state=corrupt: a marker that " +
				"cannot be read, whose VM is held stopped here until an operator acts. Alert on corrupt > 0.",
		}, []string{"state"}),
	}
	reg.MustRegister(m.markers)
	return m
}

// Observe sets the gauge from one replay pass.
func (m *OperatorStopMetrics) Observe(pending, corrupt int) {
	m.markers.WithLabelValues("pending").Set(float64(pending))
	m.markers.WithLabelValues("corrupt").Set(float64(corrupt))
}
