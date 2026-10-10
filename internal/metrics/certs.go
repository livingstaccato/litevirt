package metrics

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// CertMetrics exports the expiry of the certificates this node serves, so an
// alert can fire well before one lapses:
//
//	litevirt_certificate_expiry_timestamp_seconds - time() < 30*86400
//
// cert is "host" (the cluster mTLS identity, `lv host renew-cert`) or "ui"
// (the web UI's custom certificate, `lv host ui-cert set`). Only certificates
// actually in use are exported; a cleared UI certificate's series is deleted
// rather than left reporting a date nothing serves.
type CertMetrics struct {
	expiry *prometheus.GaugeVec
}

// NewCertMetrics registers the certificate gauges against the default registry.
func NewCertMetrics() *CertMetrics { return newCertMetrics(prometheus.DefaultRegisterer) }

func newCertMetrics(reg prometheus.Registerer) *CertMetrics {
	m := &CertMetrics{
		expiry: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_certificate_expiry_timestamp_seconds",
			Help: "NotAfter of a certificate this node serves, as a Unix timestamp, by certificate (host, ui).",
		}, []string{"cert"}),
	}
	reg.MustRegister(m.expiry)
	return m
}

// SetExpiry records cert's NotAfter. Nil-safe.
func (m *CertMetrics) SetExpiry(cert string, notAfter time.Time) {
	if m == nil {
		return
	}
	m.expiry.WithLabelValues(cert).Set(float64(notAfter.Unix()))
}

// Clear drops cert's series. Nil-safe.
func (m *CertMetrics) Clear(cert string) {
	if m == nil {
		return
	}
	m.expiry.DeleteLabelValues(cert)
}
