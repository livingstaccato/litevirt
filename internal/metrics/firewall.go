package metrics

import "github.com/prometheus/client_golang/prometheus"

// FirewallMetrics exports what the firewall reconciler could not enforce as
// written. One series per security-group name that more than one live group
// holds and that a NIC on this host is bound to; its value is how many of
// this host's NICs are held at drop for it. A series exists only while that
// is true, so an alert on `litevirt_firewall_sg_duplicate_name_nics > 0` names
// the group to remove or rename.
type FirewallMetrics struct {
	dupNICs    *prometheus.GaugeVec
	tagMembers *prometheus.GaugeVec
	logRecords *prometheus.CounterVec
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
		tagMembers: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_firewall_tag_group_members",
			Help: "Member workloads of each tag group (label group) in this host's current view of the cluster; " +
				"0 for a group this host cannot read.",
		}, []string{"group"}),
		logRecords: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_firewall_log_records_total",
			Help: "Firewall log records this host's listener received, by outcome: kept, rate_limited " +
				"(over firewall.log_max_rate) or overflow (dropped by the kernel before the listener read them).",
		}, []string{"outcome"}),
	}
	for _, o := range []string{"kept", "rate_limited", "overflow"} {
		m.logRecords.WithLabelValues(o)
	}
	reg.MustRegister(m.dupNICs, m.tagMembers, m.logRecords)
	return m
}

// LogRecords counts n firewall log records with outcome (firewall.LogCounter).
func (m *FirewallMetrics) LogRecords(outcome string, n int) {
	m.logRecords.WithLabelValues(outcome).Add(float64(n))
}

// SetTagGroupMembers replaces every tag-group series with one reconcile
// pass's result.
func (m *FirewallMetrics) SetTagGroupMembers(membersByGroup map[string]int) {
	m.tagMembers.Reset()
	for name, n := range membersByGroup {
		m.tagMembers.WithLabelValues(name).Set(float64(n))
	}
}

// SetDuplicateSGNICs replaces every series with one reconcile pass's result.
func (m *FirewallMetrics) SetDuplicateSGNICs(nicsByName map[string]int) {
	m.dupNICs.Reset()
	for name, n := range nicsByName {
		m.dupNICs.WithLabelValues(name).Set(float64(n))
	}
}
