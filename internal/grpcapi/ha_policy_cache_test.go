package grpcapi

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc"
)

// haTestServer is a server whose replica may hold an ha row.
func haTestServer(t *testing.T) *Server {
	t.Helper()
	s := testServer(t)
	insertReadyHost(t, s, s.hostName)
	s.db.SetClusterPolicyGate(func() bool { return true })
	return s
}

func writeHA(t *testing.T, s *Server, state, after string) string {
	t.Helper()
	ts, err := corrosion.SetHAPolicy(context.Background(), s.db, capabilities.GrantForTest(t, capabilities.FeatureHADisarm),
		state, "test", "alice", after)
	if err != nil {
		t.Fatalf("write %s: %v", state, err)
	}
	return ts
}

func readyHA(t *testing.T, s *Server) *pb.ReadyResponse {
	t.Helper()
	r, err := s.Ready(context.Background(), &pb.ReadyRequest{})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// Ready answers the HA policy from the cache, and says ha_known=false until
// the cache has loaded once. A row written to the replica without a refresh
// does not show: the probe path reads no database for it.
//
// Mutations: answer ha_known=true before the first load — the first check goes
// red; read the replica in Ready — the unrefreshed disarm shows and the second
// check goes red.
func TestReady_AnswersTheHAPolicyFromTheCache(t *testing.T) {
	s := haTestServer(t)
	if r := readyHA(t, s); r.GetHaKnown() || r.GetHaDisarmed() {
		t.Fatalf("before the first load: known=%v disarmed=%v, want unknown", r.GetHaKnown(), r.GetHaDisarmed())
	}
	if err := s.RefreshHAPolicyCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := readyHA(t, s); !r.GetHaKnown() || r.GetHaDisarmed() || r.GetHaPolicyAt() != "" {
		t.Fatalf("no row, loaded: %+v, want known and armed", r)
	}
	ts := writeHA(t, s, corrosion.HADisarmed, "")
	if r := readyHA(t, s); r.GetHaDisarmed() {
		t.Fatal("Ready read the replica: a disarm the cache has not loaded shows")
	}
	if err := s.RefreshHAPolicyCache(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r := readyHA(t, s); !r.GetHaKnown() || !r.GetHaDisarmed() || r.GetHaPolicyAt() != ts {
		t.Fatalf("after the refresh: %+v, want disarmed at %s", r, ts)
	}
}

// The refresher follows a replicated change within a second.
func TestHAPolicyCache_RefreshesWithinASecond(t *testing.T) {
	s := haTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.RunHAPolicyCache(ctx)
	haWaitFor(t, 2*time.Second, "the first load", func() bool { return readyHA(t, s).GetHaKnown() })
	ts := writeHA(t, s, corrosion.HADisarmed, "")
	start := time.Now()
	haWaitFor(t, 2*time.Second, "the disarm to show", func() bool { return readyHA(t, s).GetHaPolicyAt() == ts })
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Fatalf("the cache took %s to follow the replica, want within a second", d)
	}
}

// The cache only moves forward, whatever order its two writers install in.
//
// Mutation: install without the order check — the older row replaces the
// newer one and this goes red.
func TestHAPolicyCache_OnlyMovesForward(t *testing.T) {
	base := time.Now().UTC()
	at := func(i int) string { return base.Add(time.Duration(i) * time.Millisecond).Format(time.RFC3339Nano) }
	var h haPolicyCache
	h.install(corrosion.HAPolicy{State: corrosion.HADisarmed, UpdatedAt: at(2)})
	h.install(corrosion.HAPolicy{State: corrosion.HAArmed, UpdatedAt: at(1)})
	if _, disarmed, policyAt := h.snapshot(); !disarmed || policyAt != at(2) {
		t.Fatalf("an older row replaced a newer one: disarmed=%v at=%s", disarmed, policyAt)
	}
	h.install(corrosion.HAPolicy{State: corrosion.HAArmed})
	if _, _, policyAt := h.snapshot(); policyAt != at(2) {
		t.Fatal("'no row' replaced a row")
	}

	// Both writers at once, in every interleaving the scheduler finds.
	var c haPolicyCache
	var wg sync.WaitGroup
	for i := 1; i <= 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.install(corrosion.HAPolicy{State: corrosion.HADisarmed, UpdatedAt: at(i)})
		}(i)
	}
	wg.Wait()
	if _, _, policyAt := c.snapshot(); policyAt != at(50) {
		t.Fatalf("concurrent installs settled on %s, want the newest %s", policyAt, at(50))
	}
}

// slowReady answers Ready after a delay.
type slowReady struct {
	pb.LiteVirtClient
	delay time.Duration
	resp  *pb.ReadyResponse
}

func (c *slowReady) Ready(context.Context, *pb.ReadyRequest, ...grpc.CallOption) (*pb.ReadyResponse, error) {
	time.Sleep(c.delay)
	return c.resp, nil
}

// A recorded answer is stamped with the time its probe was SENT, so its age
// never understates how old the information is.
//
// Mutation: stamp the receive time — this goes red.
func TestPeerReady_StampsTheHAAnswerWithTheSendTime(t *testing.T) {
	s := testServer(t)
	c := &slowReady{delay: 300 * time.Millisecond, resp: &pb.ReadyResponse{HostName: "host-b", Ready: true,
		HaKnown: true, HaDisarmed: true, HaPolicyAt: "2026-10-15T00:00:00Z"}}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return c, func() {}, nil }
	sent := time.Now()
	if _, _, err := s.PeerReady(context.Background(), "host-b", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	asked, known, disarmed, at, ok := s.PeerHAAnswer("host-b")
	if !ok || !known || !disarmed || at != "2026-10-15T00:00:00Z" {
		t.Fatalf("answer = known=%v disarmed=%v at=%q ok=%v", known, disarmed, at, ok)
	}
	if asked.Sub(sent) > 100*time.Millisecond {
		t.Fatalf("answer stamped %s after the send, want the send time (the reply took %s)", asked.Sub(sent), c.delay)
	}
	// Another host answering at the address says nothing known about this one.
	c.delay, c.resp = 0, &pb.ReadyResponse{HostName: "host-c", HaKnown: true}
	if _, _, err := s.PeerReady(context.Background(), "host-b", "127.0.0.1:1"); err != nil {
		t.Fatal(err)
	}
	if _, known, _, _, _ := s.PeerHAAnswer("host-b"); known {
		t.Fatal("another host's answer was taken as host-b's")
	}
}

// This node's own conditions and gauge follow its cache: a disarm opens
// ha_disarmed, an unreadable row opens ha_policy_unreadable (critical, naming
// the node), loads that keep failing open it too and make Ready answer
// ha_known=false, and an arm resolves both.
//
// Mutations: keep ha_known after loads keep failing — the unknown check goes
// red; skip the failing-load condition — its check goes red.
func TestHAPolicyCache_ConditionsAndGauge(t *testing.T) {
	ctx := context.Background()
	s := haTestServer(t)
	var gauge bool
	s.SetHADisarmedGauge(func(on bool) { gauge = on })
	cond := func(code string) corrosion.HealthCondition {
		row, _, err := corrosion.GetHealthCondition(ctx, s.db, corrosion.HADisarmEvaluator, code, "host", s.hostName)
		if err != nil {
			t.Fatal(err)
		}
		return row
	}
	open := func(code string) bool { return cond(code).Lifecycle == corrosion.ConditionConfirmed }
	pass := func() {
		_ = s.RefreshHAPolicyCache(ctx)
		s.syncHAConditions(ctx)
	}

	ts := writeHA(t, s, corrosion.HADisarmed, "")
	pass()
	if !open(corrosion.CondHADisarmed) || !gauge || open(corrosion.CondHAPolicyUnreadable) {
		t.Fatalf("disarmed: ha_disarmed=%v gauge=%v unreadable=%v", open(corrosion.CondHADisarmed), gauge, open(corrosion.CondHAPolicyUnreadable))
	}
	writeHA(t, s, corrosion.HAArmed, ts)
	pass()
	if open(corrosion.CondHADisarmed) || gauge {
		t.Fatalf("armed again: ha_disarmed=%v gauge=%v", open(corrosion.CondHADisarmed), gauge)
	}

	// A row this build cannot read.
	if err := s.db.Execute(ctx, `INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, NULL)
	 ON CONFLICT(key) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`, "ha", `{"state":"half"}`, "mallory", s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	pass()
	if c := cond(corrosion.CondHAPolicyUnreadable); c.Lifecycle != corrosion.ConditionConfirmed ||
		c.Severity != corrosion.SeverityCritical || c.SubjectID != s.hostName || !gauge {
		t.Fatalf("unreadable row: %+v gauge=%v", c, gauge)
	}
	if r := readyHA(t, s); !r.GetHaKnown() || !r.GetHaDisarmed() {
		t.Fatalf("an unreadable row must answer known and disarmed: %+v", r)
	}

	// Loads that keep failing.
	writeHA(t, s, corrosion.HAArmed, "")
	pass()
	if open(corrosion.CondHAPolicyUnreadable) {
		t.Fatal("a readable row left ha_policy_unreadable open")
	}
	if _, err := s.db.DB().ExecContext(ctx, `ALTER TABLE cluster_policies RENAME TO cluster_policies_gone`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < haCacheFailuresUnknown; i++ {
		pass()
	}
	if r := readyHA(t, s); r.GetHaKnown() {
		t.Fatal("a cache whose loads keep failing still answers ha_known=true")
	}
	c := cond(corrosion.CondHAPolicyUnreadable)
	if c.Lifecycle != corrosion.ConditionConfirmed || !gauge ||
		!strings.Contains(c.Evidence, "HA cache load failing on "+s.hostName) {
		t.Fatalf("failing loads: %+v gauge=%v", c, gauge)
	}
	if _, err := s.db.DB().ExecContext(ctx, `ALTER TABLE cluster_policies_gone RENAME TO cluster_policies`); err != nil {
		t.Fatal(err)
	}
	pass()
	if r := readyHA(t, s); !r.GetHaKnown() || open(corrosion.CondHAPolicyUnreadable) || gauge {
		t.Fatalf("recovered: known=%v unreadable=%v gauge=%v", r.GetHaKnown(), open(corrosion.CondHAPolicyUnreadable), gauge)
	}
}

func haWaitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %s waiting for %s", timeout, what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
