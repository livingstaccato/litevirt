package metrics

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// Each pass replaces its kind's series wholesale: a reaped orphan's series
// goes, and the other kind's series are left alone.
func TestOrphanRuntimeMetrics_SetReplacesOneKind(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newOrphanRuntimeMetrics(reg)

	m.Set("vm", "node-4", []OrphanRuntimeSample{{"claimvm", "tombstoned"}, {"ghostvm", "missing"}})
	m.Set("ct", "node-4", []OrphanRuntimeSample{{"web", "missing"}})
	m.Set("vm", "node-4", []OrphanRuntimeSample{{"ghostvm", "missing"}})

	want := `
# HELP litevirt_orphan_runtime 1 for each litevirt-created runtime this host runs with no live record (kind vm|ct, host, name, row missing|tombstoned). Report-only: nothing reaps it.
# TYPE litevirt_orphan_runtime gauge
litevirt_orphan_runtime{host="node-4",kind="ct",name="web",row="missing"} 1
litevirt_orphan_runtime{host="node-4",kind="vm",name="ghostvm",row="missing"} 1
`
	if err := testutil.GatherAndCompare(reg, strings.NewReader(want), "litevirt_orphan_runtime"); err != nil {
		t.Error(err)
	}
}
