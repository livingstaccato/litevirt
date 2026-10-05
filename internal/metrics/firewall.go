package metrics

import "github.com/prometheus/client_golang/prometheus"

// FirewallMetrics exports what the firewall reconciler could not enforce as
// written. One series per security-group name that more than one live group
// holds and that a NIC on this host is bound to; its value is how many of
// this host's NICs are held at drop for it. A series exists only while that
// is true, so an alert on `litevirt_firewall_sg_duplicate_name_nics > 0` names
// the group to remove or rename.
type FirewallMetrics struct {
	dupNICs *prometheus.GaugeVec
}

// NewFirewallMetrics registers the firewall metrics on the default registry.
// Call once at daemon startup.
func NewFirewallMetrics() *FirewallMetrics {
	return newFirewallMetrics(prometheus.DefaultRegisterer)
}

func newFirewallMetrics(reg prometheus.Registerer) *FirewallMetrics {
	m := &FirewallMetrics{
		dupNICs: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_firewall_sg_duplicate_name_nics",
			Help: "NICs on this host held at drop because a security-group name they are bound to " +
				"is held by more than one live group (label sg). Remove or rename one of the groups.",
		}, []string{"sg"}),
	}
	reg.MustRegister(m.dupNICs)
	return m
}

// SetDuplicateSGNICs replaces every series with one reconcile pass's result.
func (m *FirewallMetrics) SetDuplicateSGNICs(nicsByName map[string]int) {
	m.dupNICs.Reset()
	for name, n := range nicsByName {
		m.dupNICs.WithLabelValues(name).Set(float64(n))
	}
}
