package metrics

import "github.com/prometheus/client_golang/prometheus"

// SMARTDisk is one disk's gauge label set.
type SMARTDisk struct {
	Device string
	Model  string
	Status string // ok | prefail | failing | unknown
}

// SMARTMetrics exposes this host's periodic disk SMART check.
type SMARTMetrics struct {
	// status{device,model,status} = 1 for each disk's CURRENT verdict, rebuilt
	// every pass so a replaced or healed disk drops its old series.
	status *prometheus.GaugeVec
	// available = 1 when smartctl is installed and could scan, 0 when not. A
	// host without smartctl reports 0 and no disk series: unknown, not healthy.
	available prometheus.Gauge
}

// NewSMARTMetrics registers the gauges on the default registry.
func NewSMARTMetrics() *SMARTMetrics { return newSMARTMetrics(prometheus.DefaultRegisterer) }

// NewSMARTMetricsWith registers on the given registry (tests).
func NewSMARTMetricsWith(reg prometheus.Registerer) *SMARTMetrics { return newSMARTMetrics(reg) }

func newSMARTMetrics(reg prometheus.Registerer) *SMARTMetrics {
	m := &SMARTMetrics{
		status: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_disk_smart_status",
			Help: "This host's disk SMART verdict (1 for the current status: ok, prefail, failing or unknown), rebuilt each check.",
		}, []string{"device", "model", "status"}),
		available: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_disk_smart_available",
			Help: "1 when smartctl is installed on this host and the last SMART scan ran, else 0.",
		}),
	}
	reg.MustRegister(m.status, m.available)
	return m
}

// Set rebuilds the gauges from one pass. Nil-safe.
func (m *SMARTMetrics) Set(available bool, disks []SMARTDisk) {
	if m == nil {
		return
	}
	m.status.Reset()
	if available {
		m.available.Set(1)
	} else {
		m.available.Set(0)
	}
	for _, d := range disks {
		m.status.WithLabelValues(d.Device, d.Model, d.Status).Set(1)
	}
}
