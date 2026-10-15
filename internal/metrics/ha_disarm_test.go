package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// litevirt_ha_disarmed and litevirt_ha_peer_veto read 1 or 0, and go back to
// 0.
func TestHADisarmMetrics_Gauges(t *testing.T) {
	m := newHADisarmMetrics(prometheus.NewRegistry())
	for _, step := range []struct{ disarmed, veto bool }{{true, false}, {true, true}, {false, false}} {
		m.Disarmed(step.disarmed)
		m.PeerVeto(step.veto)
		want := func(b bool) float64 {
			if b {
				return 1
			}
			return 0
		}
		if got := testutil.ToFloat64(m.disarmed); got != want(step.disarmed) {
			t.Errorf("litevirt_ha_disarmed = %v, want %v", got, want(step.disarmed))
		}
		if got := testutil.ToFloat64(m.peerVeto); got != want(step.veto) {
			t.Errorf("litevirt_ha_peer_veto = %v, want %v", got, want(step.veto))
		}
	}
}
