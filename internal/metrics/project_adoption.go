package metrics

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

// Project adoption, lazily registered: the pass runs from the daemon,
// independently of the metrics server.
var (
	projectAdoptionOnce    sync.Once
	projectAdoptionBlocked *prometheus.GaugeVec
)

func projectAdoptionInit() {
	projectAdoptionOnce.Do(func() {
		projectAdoptionBlocked = prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "litevirt_project_adoption_blocked",
			Help: "Projects created before project_incarnation_v1 latched that this host's adoption pass " +
				"cannot adopt, by reason. reason=\"spellings\": more than one spelling of the name is live " +
				"(\"acme\" beside \"/acme\"); `lv doctor project-spellings` lists them. " +
				"reason=\"fallback_clock\": projects this host would adopt as a fallback for another holder, " +
				"skipped because its first-latched file in the data directory cannot be read or written.",
		}, []string{"reason"})
		prometheus.DefaultRegisterer.MustRegister(projectAdoptionBlocked)
	})
}

// ProjectAdoptionBlocked records how many projects the last adoption pass
// could not adopt for reason.
func ProjectAdoptionBlocked(reason string, n int) {
	projectAdoptionInit()
	projectAdoptionBlocked.WithLabelValues(reason).Set(float64(n))
}

// ProjectAdoptionBlockedGauge is litevirt_project_adoption_blocked, for a test
// to read.
func ProjectAdoptionBlockedGauge() *prometheus.GaugeVec {
	projectAdoptionInit()
	return projectAdoptionBlocked
}
