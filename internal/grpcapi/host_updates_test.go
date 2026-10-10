package grpcapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hostupdates"
	"github.com/litevirt/litevirt/internal/notify"
)

type hookRecorder struct {
	mu  sync.Mutex
	got []notify.Notification
}

func (h *hookRecorder) kinds() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var k []string
	for _, n := range h.got {
		k = append(k, n.Kind+"/"+string(n.Severity))
	}
	return k
}

func hostUpdatesServer(t *testing.T, st hostupdates.Status) (*Server, *hookRecorder) {
	t.Helper()
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	rec := &hookRecorder{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var n notify.Notification
		_ = json.NewDecoder(r.Body).Decode(&n)
		rec.mu.Lock()
		rec.got = append(rec.got, n)
		rec.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	cfg, _ := json.Marshal(map[string]string{"url": srv.URL})
	if err := corrosion.InsertNotificationTarget(ctx, s.db, corrosion.NotificationTarget{ID: "t1", Name: "hook", Type: "webhook", Config: string(cfg), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertNotificationRoute(ctx, s.db, corrosion.NotificationRoute{ID: "r1", EventPattern: "host.*", TargetID: "t1", MinSeverity: "info", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s.SetHostUpdates(HostUpdatesConfig{Enabled: true, Check: func(context.Context) hostupdates.Status { return st }})
	return s, rec
}

func waitKinds(t *testing.T, rec *hookRecorder, want int) []string {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if k := rec.kinds(); len(k) >= want {
			return k
		}
		time.Sleep(10 * time.Millisecond)
	}
	return rec.kinds()
}

func TestHostUpdates_PublishesLabelsAndFlagsSecurity(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{
		Supported: true, Manager: "apt", Pending: 3, Security: 1,
		Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}, {Name: "vim"}, {Name: "tzdata"}},
	})
	s.CheckHostUpdatesOnce(context.Background())

	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	p, sec, ok := hostupdates.FromLabels(h.Labels)
	if !ok || p != 3 || sec != 1 {
		t.Fatalf("labels not published: %v", h.Labels)
	}
	k := waitKinds(t, rec, 1)
	if len(k) != 1 || k[0] != "host.security_updates/warn" {
		t.Fatalf("want one warn security notification, got %v", k)
	}
}

func TestHostUpdates_NonSecurityIsInfo(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 2, Packages: []hostupdates.Pkg{{Name: "vim"}, {Name: "tzdata"}}})
	s.CheckHostUpdatesOnce(context.Background())
	k := waitKinds(t, rec, 1)
	if len(k) != 1 || k[0] != "host.updates/info" {
		t.Fatalf("got %v", k)
	}
}

func TestHostUpdates_UnchangedDoesNotRenotify(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 1, Security: 1, Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}}})
	s.CheckHostUpdatesOnce(context.Background())
	waitKinds(t, rec, 1)
	s.CheckHostUpdatesOnce(context.Background())
	time.Sleep(150 * time.Millisecond)
	if k := rec.kinds(); len(k) != 1 {
		t.Fatalf("an unchanged result must not notify again, got %v", k)
	}
}

func TestHostUpdates_RestartDoesNotRenotifyKnownState(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Pending: 1, Security: 1, Packages: []hostupdates.Pkg{{Name: "openssl", Security: true}}})
	if err := corrosion.SetHostLabel(context.Background(), s.db, s.hostName, hostupdates.LabelPending, "1"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.SetHostLabel(context.Background(), s.db, s.hostName, hostupdates.LabelSecurity, "1"); err != nil {
		t.Fatal(err)
	}
	s.CheckHostUpdatesOnce(context.Background()) // a fresh Server: no in-memory state
	time.Sleep(150 * time.Millisecond)
	if k := rec.kinds(); len(k) != 0 {
		t.Fatalf("the published labels already say this; a restart must not notify, got %v", k)
	}
}

func TestHostUpdates_FailedCheckIsUnknownNotZero(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt", Err: "apt list: boom"})
	s.CheckHostUpdatesOnce(context.Background())
	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	if h.Labels[hostupdates.LabelPending] != "unknown" {
		t.Fatalf("a failed check must publish unknown, got %v", h.Labels)
	}
	time.Sleep(100 * time.Millisecond)
	if k := rec.kinds(); len(k) != 0 {
		t.Fatalf("a failed check is not an update notification, got %v", k)
	}
}

func TestHostUpdates_FullyPatchedClearsAndIsQuiet(t *testing.T) {
	s, rec := hostUpdatesServer(t, hostupdates.Status{Supported: true, Manager: "apt"})
	s.CheckHostUpdatesOnce(context.Background())
	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	if p, sec, ok := hostupdates.FromLabels(h.Labels); !ok || p != 0 || sec != 0 {
		t.Fatalf("labels: %v", h.Labels)
	}
	time.Sleep(100 * time.Millisecond)
	if k := rec.kinds(); len(k) != 0 {
		t.Fatalf("nothing pending, nothing to say: %v", k)
	}
}

func TestHostUpdates_UnsupportedHostPublishesNothing(t *testing.T) {
	s, _ := hostUpdatesServer(t, hostupdates.Status{})
	s.CheckHostUpdatesOnce(context.Background())
	h, _ := corrosion.GetHost(context.Background(), s.db, s.hostName)
	if _, ok := h.Labels[hostupdates.LabelPending]; ok {
		t.Fatalf("a host with no package manager must publish no label: %v", h.Labels)
	}
}
