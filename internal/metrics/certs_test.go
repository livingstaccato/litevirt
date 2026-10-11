package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// The gauge carries NotAfter as a Unix timestamp per certificate, and a
// cleared certificate's series goes away rather than reporting a stale date.
func TestCertMetrics_ExpiryGauge(t *testing.T) {
	m := newCertMetrics(prometheus.NewRegistry())
	na := time.Date(2031, 1, 2, 3, 4, 5, 0, time.UTC)
	m.SetExpiry("host", na)
	if got := testutil.ToFloat64(m.expiry.WithLabelValues("host")); got != float64(na.Unix()) {
		t.Fatalf("host expiry = %v, want %v", got, na.Unix())
	}
	m.SetExpiry("ui", na)
	m.Clear("ui")
	if n := testutil.CollectAndCount(m.expiry); n != 1 {
		t.Fatalf("%d series after clearing ui, want 1", n)
	}
	var nilM *CertMetrics
	nilM.SetExpiry("host", na) // nil-safe
	nilM.Clear("host")
}
