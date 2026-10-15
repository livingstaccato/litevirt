package metrics

import "github.com/prometheus/client_golang/prometheus"

// ReservationMetrics exposes this host's reservation sweep: what it released,
// what it declined, and the in-flight capacity reservations counted against
// this host. Every method is nil-safe.
type ReservationMetrics struct {
	releases *prometheus.CounterVec
	skipped  *prometheus.CounterVec
	vcpu     prometheus.Gauge
	memMiB   prometheus.Gauge
	oldest   prometheus.Gauge
}

// NewReservationMetrics registers the series on the default registry.
func NewReservationMetrics() *ReservationMetrics {
	return newReservationMetrics(prometheus.DefaultRegisterer)
}

// NewReservationMetricsWith registers on the given registry (tests).
func NewReservationMetricsWith(reg prometheus.Registerer) *ReservationMetrics {
	return newReservationMetrics(reg)
}

func newReservationMetrics(reg prometheus.Registerer) *ReservationMetrics {
	m := &ReservationMetrics{
		releases: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_host_reservation_releases_total",
			Help: "Host capacity reservations this node released, by reason (terminal_past_header, vm_gone, admin).",
		}, []string{"reason"}),
		skipped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "litevirt_host_reservation_sweep_skipped_total",
			Help: "Reservation sweep passes (replica_untrusted) or reservations (vm_busy) the sweep declined.",
		}, []string{"reason"}),
		vcpu: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_host_reserved_vcpu",
			Help: "vCPUs of the in-flight reservations counted against this host.",
		}),
		memMiB: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_host_reserved_memory_mib",
			Help: "Memory (MiB) of the in-flight reservations counted against this host.",
		}),
		oldest: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "litevirt_host_reservation_oldest_seconds",
			Help: "Age of the oldest reservation counted against this host that no operation holds in flight; 0 when there is none.",
		}),
	}
	reg.MustRegister(m.releases, m.skipped, m.vcpu, m.memMiB, m.oldest)
	return m
}

// Released counts one reservation this node released.
func (m *ReservationMetrics) Released(reason string) {
	if m == nil {
		return
	}
	m.releases.WithLabelValues(reason).Inc()
}

// Skipped counts one pass or reservation the sweep declined.
func (m *ReservationMetrics) Skipped(reason string) {
	if m == nil {
		return
	}
	m.skipped.WithLabelValues(reason).Inc()
}

// SetHostReserved sets this host's counted reservation gauges.
func (m *ReservationMetrics) SetHostReserved(vcpu, memMiB int, oldestSeconds float64) {
	if m == nil {
		return
	}
	m.vcpu.Set(float64(vcpu))
	m.memMiB.Set(float64(memMiB))
	m.oldest.Set(oldestSeconds)
}
