package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Managed fence SSH probe, lazily registered: the probe runs from the
// daemon's fence ssh agent, independently of the metrics server.
var (
	fenceSSHOnce    sync.Once
	fenceSSHProbeOK *prometheus.GaugeVec
)

func fenceSSHInit() {
	fenceSSHOnce.Do(func() {
		fenceSSHProbeOK = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_fence_ssh_probe_ok",
			Help: "1 if this host's last check of the managed fence SSH path to the peer passed (pin, key, " +
				"source address and forced command), 0 if it failed or the peer has no managed path. " +
				"A check never powers anything off, and does not prove the power-off itself works.",
		}, []string{"peer"})
		prometheus.DefaultRegisterer.MustRegister(fenceSSHProbeOK)
	})
}

// FenceSSHProbe records one peer's managed fence path check.
func FenceSSHProbe(peer string, ok bool) {
	fenceSSHInit()
	v := 0.0
	if ok {
		v = 1
	}
	fenceSSHProbeOK.WithLabelValues(peer).Set(v)
}

// FenceSSHProbeGauge is litevirt_fence_ssh_probe_ok, for a test to read.
func FenceSSHProbeGauge() *prometheus.GaugeVec {
	fenceSSHInit()
	return fenceSSHProbeOK
}
