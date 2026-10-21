package metrics

import (
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pressure"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestPressureMetrics_Observe(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewPressureMetricsWith(reg)
	m.Observe(pressure.Report{Level: pressure.Degrade, Resources: []pressure.ResourceReport{
		{Name: "data_dir.space", Level: pressure.Degrade, Free: 6 << 30, TimeToFull: time.Hour},
		{Name: "pool.fast.space", Level: pressure.OK, Free: 50 << 30},
		{Name: "data_dir.inodes", Level: pressure.OK, Free: 900},
	}})
	if v := testutil.ToFloat64(m.level.WithLabelValues("host")); v != 2 {
		t.Errorf("host level %v, want 2", v)
	}
	if v := testutil.ToFloat64(m.free.WithLabelValues("data_dir")); v != float64(6<<30) {
		t.Errorf("data_dir free %v", v)
	}
	if v := testutil.ToFloat64(m.ttf.WithLabelValues("data_dir.space")); v != 3600 {
		t.Errorf("time to full %v, want 3600", v)
	}
	if n := testutil.CollectAndCount(m.free); n != 2 {
		t.Errorf("%d free series, want 2 (space resources only)", n)
	}
	// The pool goes away: its series go too.
	m.Observe(pressure.Report{Resources: []pressure.ResourceReport{{Name: "data_dir.space", Free: 1}}})
	if n := testutil.CollectAndCount(m.free); n != 1 {
		t.Errorf("after the pool went: %d free series, want 1", n)
	}
	if n := testutil.CollectAndCount(m.ttf); n != 0 {
		t.Errorf("not filling: %d time-to-full series, want 0", n)
	}
	var nilM *PressureMetrics
	nilM.Observe(pressure.Report{})
}
