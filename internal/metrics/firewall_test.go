package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Each pass replaces the whole set: a name that stopped being ambiguous loses
// its series, so an alert clears when the operator fixes the duplicate.
func TestFirewallMetrics_DuplicateSGNICsReplacesEachPass(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newFirewallMetrics(reg)
	series := func() map[string]float64 {
		t.Helper()
		mfs, err := reg.Gather()
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]float64{}
		for _, mf := range mfs {
			if mf.GetName() != "litevirt_firewall_sg_duplicate_name_nics" {
				continue
			}
			for _, s := range mf.GetMetric() {
				for _, l := range s.GetLabel() {
					if l.GetName() == "sg" {
						out[l.GetValue()] = s.GetGauge().GetValue()
					}
				}
			}
		}
		return out
	}

	m.SetDuplicateSGNICs(map[string]int{"web": 2, "db": 1})
	if got := series(); len(got) != 2 || got["web"] != 2 || got["db"] != 1 {
		t.Fatalf("after first pass: %v, want web=2 db=1", got)
	}
	m.SetDuplicateSGNICs(map[string]int{"db": 1})
	if got := series(); len(got) != 1 || got["db"] != 1 {
		t.Fatalf("after web was fixed: %v, want only db=1", got)
	}
	m.SetDuplicateSGNICs(map[string]int{})
	if got := series(); len(got) != 0 {
		t.Fatalf("after every duplicate was fixed: %v, want no series", got)
	}
}
