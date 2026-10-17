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

// The tag-group member series are replaced by each pass: a removed group
// loses its series.
//
// Mutation: no Reset — the removed group's series stays: red.
func TestFirewallMetrics_TagGroupMembersReplacesEachPass(t *testing.T) {
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
			if mf.GetName() != "litevirt_firewall_tag_group_members" {
				continue
			}
			for _, s := range mf.GetMetric() {
				for _, l := range s.GetLabel() {
					if l.GetName() == "group" {
						out[l.GetValue()] = s.GetGauge().GetValue()
					}
				}
			}
		}
		return out
	}
	m.SetTagGroupMembers(map[string]int{"web": 3, "db": 0})
	if got := series(); len(got) != 2 || got["web"] != 3 || got["db"] != 0 {
		t.Fatalf("after the first pass: %v, want web=3 db=0", got)
	}
	m.SetTagGroupMembers(map[string]int{"web": 2})
	if got := series(); len(got) != 1 || got["web"] != 2 {
		t.Fatalf("after db was removed: %v, want only web=2", got)
	}
}
