package metrics

import "github.com/prometheus/client_golang/prometheus"

// HADisarmMetrics are the cluster HA policy's gauges
// (docs/migration-failover.md, "Disarming HA for planned maintenance").
type HADisarmMetrics struct {
	disarmed prometheus.Gauge
	peerVeto prometheus.Gauge
}

// NewHADisarmMetrics registers the HA policy gauges on the default registry.
// Call once at daemon startup.
func NewHADisarmMetrics() *HADisarmMetrics { return newHADisarmMetrics(prometheus.DefaultRegisterer) }

func newHADisarmMetrics(reg prometheus.Registerer) *HADisarmMetrics {
	m := &HADisarmMetrics{
		disarmed: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_ha_disarmed",
			Help: "1 while THIS node's replica says cluster HA is disarmed (lv cluster ha disarm), or holds an " +
				"HA policy it cannot read: no host is fenced and no workload recovered automatically. 0 when armed.",
		}),
		peerVeto: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_ha_peer_veto",
			Help: "1 on the failover lease holder while its own replica says HA is armed and a live voter's " +
				"answer held a fence or a recovery back (condition ha_disarm_peer_veto). 0 otherwise.",
		}),
	}
	reg.MustRegister(m.disarmed, m.peerVeto)
	return m
}

func boolGauge(g prometheus.Gauge, on bool) {
	if on {
		g.Set(1)
		return
	}
	g.Set(0)
}

// Disarmed sets litevirt_ha_disarmed.
func (m *HADisarmMetrics) Disarmed(on bool) { boolGauge(m.disarmed, on) }

// PeerVeto sets litevirt_ha_peer_veto.
func (m *HADisarmMetrics) PeerVeto(on bool) { boolGauge(m.peerVeto, on) }
