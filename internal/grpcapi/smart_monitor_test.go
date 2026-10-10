package grpcapi

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/metrics"
	"github.com/litevirt/litevirt/internal/smart"
)

func TestSMARTTransitions(t *testing.T) {
	d := func(dev string, st smart.Status) smart.Disk { return smart.Disk{Device: dev, Model: "M", Status: st} }

	// First sighting: healthy and unknown are silent, failing/prefail page.
	ns, st := smartTransitions("h1", nil, []smart.Disk{d("/dev/a", smart.OK), d("/dev/b", smart.Unknown), d("/dev/c", smart.Failing), d("/dev/d", smart.Prefail)})
	if len(ns) != 2 {
		t.Fatalf("first pass = %d notifications, want 2: %+v", len(ns), ns)
	}
	if ns[0].Kind != "disk.smart.failing" || ns[0].Severity != "error" || ns[0].Subject != "h1:/dev/c" {
		t.Errorf("failing notification = %+v", ns[0])
	}
	if ns[1].Kind != "disk.smart.prefail" || ns[1].Severity != "warn" {
		t.Errorf("prefail notification = %+v", ns[1])
	}

	// Same state again: no re-page.
	ns, st = smartTransitions("h1", st, []smart.Disk{d("/dev/c", smart.Failing), d("/dev/d", smart.Prefail)})
	if len(ns) != 0 {
		t.Errorf("repeat pass paged again: %+v", ns)
	}

	// prefail -> failing pages; unknown does not clear a standing failure.
	ns, st = smartTransitions("h1", st, []smart.Disk{d("/dev/c", smart.Unknown), d("/dev/d", smart.Failing)})
	if len(ns) != 1 || ns[0].Kind != "disk.smart.failing" || ns[0].Subject != "h1:/dev/d" {
		t.Errorf("escalation = %+v", ns)
	}
	if st["/dev/c"] != smart.Failing {
		t.Error("an unknown read cleared a standing failure")
	}
	ns, _ = smartTransitions("h1", st, []smart.Disk{d("/dev/c", smart.Failing)})
	if len(ns) != 0 {
		t.Errorf("failure re-paged after an unknown blip: %+v", ns)
	}

	// Recovery says so once.
	ns, _ = smartTransitions("h1", st, []smart.Disk{d("/dev/c", smart.OK)})
	if len(ns) != 1 || ns[0].Kind != "disk.smart.recovered" || ns[0].Severity != "info" {
		t.Errorf("recovery = %+v", ns)
	}
}

func gaugeVals(t *testing.T, reg *prometheus.Registry, name string) []*dto.Metric {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return mf.GetMetric()
		}
	}
	return nil
}

func TestRunSMARTMonitor_GaugesAndDelivery(t *testing.T) {
	s := testServer(t)
	reg := prometheus.NewRegistry()
	s.SetSMARTMetrics(metrics.NewSMARTMetricsWith(reg))

	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
	}))
	defer srv.Close()
	ctx := adminCtx()
	if err := corrosion.InsertNotificationTarget(ctx, s.db, corrosion.NotificationTarget{ID: "t1", Name: "hook", Type: "webhook", Config: `{"url":"` + srv.URL + `"}`, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertNotificationRoute(ctx, s.db, corrosion.NotificationRoute{ID: "r1", EventPattern: "disk.*", TargetID: "t1", MinSeverity: "warn", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.smartRunner = func(_ context.Context, args ...string) ([]byte, error) {
		if args[0] == "--scan" {
			return []byte(`{"devices":[{"name":"/dev/sda","type":"sat"}]}`), nil
		}
		return []byte(`{"model_name":"WD","smart_support":{"available":true},"smart_status":{"passed":false}}`), &exec.ExitError{}
	}
	rctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunSMARTMonitor(rctx, time.Hour); close(done) }()

	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := len(bodies)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 1 || !strings.Contains(bodies[0], "disk.smart.failing") || !strings.Contains(bodies[0], "/dev/sda") {
		t.Fatalf("webhook bodies = %v", bodies)
	}
	m := gaugeVals(t, reg, "litevirt_disk_smart_status")
	if len(m) != 1 || m[0].GetGauge().GetValue() != 1 {
		t.Fatalf("status gauge = %v", m)
	}
	found := false
	for _, l := range m[0].GetLabel() {
		if l.GetName() == "status" && l.GetValue() == "failing" {
			found = true
		}
	}
	if !found {
		t.Errorf("status label not failing: %v", m[0].GetLabel())
	}
	if a := gaugeVals(t, reg, "litevirt_disk_smart_available"); len(a) != 1 || a[0].GetGauge().GetValue() != 1 {
		t.Errorf("available gauge = %v", a)
	}
}

func TestRunSMARTMonitor_NoSmartctlDegrades(t *testing.T) {
	s := testServer(t)
	reg := prometheus.NewRegistry()
	s.SetSMARTMetrics(metrics.NewSMARTMetricsWith(reg))
	s.smartRunner = func(context.Context, ...string) ([]byte, error) { return nil, exec.ErrNotFound }
	rctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.RunSMARTMonitor(rctx, time.Hour); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for len(gaugeVals(t, reg, "litevirt_disk_smart_available")) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	a := gaugeVals(t, reg, "litevirt_disk_smart_available")
	if len(a) != 1 || a[0].GetGauge().GetValue() != 0 {
		t.Errorf("available gauge = %v, want 0", a)
	}
	if got := gaugeVals(t, reg, "litevirt_disk_smart_status"); len(got) != 0 {
		t.Errorf("disk series with no smartctl: %v", got)
	}
}
