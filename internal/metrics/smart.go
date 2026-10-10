package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// SMARTDisk is one disk's gauge label set.
type SMARTDisk struct {
	Device string
	Model  string
	Status string // ok | warning | prefail | failing | unknown
}

// SMARTMetrics exposes this host's periodic disk SMART check. It is a custom
// collector over an immutable snapshot, so a pass swaps the whole series set in
// ONE step: a scrape never lands between "reset" and "repopulated" and sees
// every disk vanish.
type SMARTMetrics struct {
	mu        sync.RWMutex
	set       bool
	available bool
	disks     []SMARTDisk

	statusDesc    *prometheus.Desc
	availableDesc *prometheus.Desc
}

// NewSMARTMetrics registers the collector on the default registry.
func NewSMARTMetrics() *SMARTMetrics { return newSMARTMetrics(prometheus.DefaultRegisterer) }

// NewSMARTMetricsWith registers on the given registry (tests).
func NewSMARTMetricsWith(reg prometheus.Registerer) *SMARTMetrics { return newSMARTMetrics(reg) }

func newSMARTMetrics(reg prometheus.Registerer) *SMARTMetrics {
	m := &SMARTMetrics{
		statusDesc: prometheus.NewDesc("litevirt_disk_smart_status",
			"This host's disk SMART verdict (1 for the current status: ok, warning, prefail, failing or unknown), replaced atomically each check.",
			[]string{"device", "model", "status"}, nil),
		availableDesc: prometheus.NewDesc("litevirt_disk_smart_available",
			"1 when smartctl is installed on this host and the last SMART scan ran, else 0.", nil, nil),
	}
	reg.MustRegister(m)
	return m
}

func (m *SMARTMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.statusDesc
	ch <- m.availableDesc
}

func (m *SMARTMetrics) Collect(ch chan<- prometheus.Metric) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if !m.set {
		return
	}
	v := 0.0
	if m.available {
		v = 1
	}
	ch <- prometheus.MustNewConstMetric(m.availableDesc, prometheus.GaugeValue, v)
	for _, d := range m.disks {
		ch <- prometheus.MustNewConstMetric(m.statusDesc, prometheus.GaugeValue, 1, d.Device, d.Model, d.Status)
	}
}

// Set replaces the published series with one pass's result. Nil-safe.
func (m *SMARTMetrics) Set(available bool, disks []SMARTDisk) {
	if m == nil {
		return
	}
	cp := append([]SMARTDisk(nil), disks...)
	m.mu.Lock()
	m.set, m.available, m.disks = true, available, cp
	m.mu.Unlock()
}
