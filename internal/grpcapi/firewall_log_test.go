package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

func logServer(t *testing.T) (*Server, *firewall.LogStore, func(time.Time)) {
	t.Helper()
	s := testServer(t)
	now := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	store, err := firewall.OpenLogStore(firewall.LogStoreOptions{MaxRate: 1 << 30, Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	s.SetFirewallLogStore(store)
	return s, store, func(t time.Time) { now = t }
}

// C5 (L-6, I-2): reading the log needs firewall.log.view at "/". Viewer,
// Auditor and NetworkAdmin bindings are refused; Admin and a custom role
// holding the verb pass; with no bindings the legacy fallback is admin, so an
// operator is refused.
//
// Mutations: check sg.read — Viewer passes, red; check sg.* — NetworkAdmin
// passes, red; fall back to operator — the unbound operator passes, red.
func TestListFirewallLog_RBAC(t *testing.T) {
	for _, tc := range []struct {
		role string
		ok   bool
	}{{"Viewer", false}, {"Auditor", false}, {"NetworkAdmin", false}, {"Operator", false}, {"Admin", true}, {"LogReader", true}} {
		t.Run(tc.role, func(t *testing.T) {
			s, _, _ := logServer(t)
			if tc.role == "LogReader" {
				if err := corrosion.InsertRole(context.Background(), s.db, corrosion.RoleRecord{Name: "LogReader", Verbs: []string{auth.VerbFirewallLogView}}); err != nil {
					t.Fatal(err)
				}
			}
			ctx := boundAtCtx(t, s, "carol", "operator", tc.role, "/")
			_, err := s.ListFirewallLog(ctx, &pb.ListFirewallLogRequest{LocalOnly: true})
			if tc.ok && err != nil {
				t.Errorf("%s: %v, want allowed", tc.role, err)
			}
			if !tc.ok && status.Code(err) != codes.PermissionDenied {
				t.Errorf("%s: %v, want PermissionDenied", tc.role, err)
			}
		})
	}
	s, _, _ := logServer(t)
	if _, err := s.ListFirewallLog(operatorCtxNamed(), &pb.ListFirewallLogRequest{LocalOnly: true}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("unbound operator: %v, want PermissionDenied", err)
	}
	if _, err := s.ListFirewallLog(adminCtx(), &pb.ListFirewallLogRequest{LocalOnly: true}); err != nil {
		t.Errorf("unbound admin: %v", err)
	}
}

func operatorCtxNamed() context.Context { return userCtx("olga", "operator") }

// logPeer answers ListFirewallLog for one peer host.
type logPeer struct {
	pb.LiteVirtClient
	host    string
	entries []*pb.FirewallLogEntry
	err     error
	got     []*pb.ListFirewallLogRequest
}

func (p *logPeer) ListFirewallLog(_ context.Context, in *pb.ListFirewallLogRequest, _ ...grpc.CallOption) (*pb.ListFirewallLogResponse, error) {
	p.got = append(p.got, in)
	if p.err != nil {
		return nil, p.err
	}
	var out []*pb.FirewallLogEntry
	for _, e := range p.entries {
		if e.GetSeq() > in.GetAfterSeq()[p.host] {
			out = append(out, e)
		}
	}
	return &pb.ListFirewallLogResponse{Entries: out}, nil
}

// C5: without --host every active host is asked and the answers are merged by
// time; a host that cannot answer is named in errors and the rest still
// return; a peer is asked for its own records only, from its cursor; local
// entries carry this host and its sequence.
//
// Mutations: append peers' entries unsorted — red; drop a failing host's
// error — red; send the peer the whole cursor map rather than its own — the
// peer's filter still passes, so the check is on the request, red.
func TestListFirewallLog_FanOutMergesByTime(t *testing.T) {
	s, store, setNow := logServer(t)
	ctx := context.Background()
	for _, h := range []struct{ name, state string }{{"test-host", "active"}, {"b", "active"}, {"c", "active"}, {"d", "maintenance"}} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h.name, Address: "10.0.0.1", State: h.state}); err != nil {
			t.Fatal(err)
		}
	}
	t0 := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	setNow(t0.Add(1 * time.Second))
	store.Add(firewall.LogRecord{Workload: "web-1", Device: "lvt0", Side: "in", RuleID: "r1", Verdict: "drop"})
	setNow(t0.Add(3 * time.Second))
	store.Add(firewall.LogRecord{Workload: "web-1", Device: "lvt0", Side: "in", RuleID: "r1", Verdict: "drop"})
	b := &logPeer{host: "b", entries: []*pb.FirewallLogEntry{
		{Host: "b", Seq: 7, Time: t0.Add(2 * time.Second).Format(time.RFC3339Nano), Workload: "db-1"},
		{Host: "b", Seq: 8, Time: t0.Add(4 * time.Second).Format(time.RFC3339Nano), Workload: "db-1"},
	}}
	c := &logPeer{host: "c", err: status.Error(codes.Unavailable, "connection refused")}
	s.peerClientOverride = func(_ context.Context, host string) (pb.LiteVirtClient, func(), error) {
		switch host {
		case "b":
			return b, func() {}, nil
		case "c":
			return c, func() {}, nil
		}
		return nil, nil, errors.New("not a peer: " + host)
	}
	resp, err := s.ListFirewallLog(adminCtx(), &pb.ListFirewallLogRequest{AfterSeq: map[string]uint64{"b": 6, "c": 1}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range resp.GetEntries() {
		got = append(got, e.GetHost()+"/"+e.GetWorkload())
	}
	want := []string{"test-host/web-1", "b/db-1", "test-host/web-1", "b/db-1"}
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("entries = %v, want %v (by time)", got, want)
		}
	}
	if e := resp.GetEntries()[0]; e.GetSeq() != 1 || e.GetVerdict() != "drop" || e.GetDevice() != "lvt0" {
		t.Errorf("local entry = %+v", e)
	}
	if resp.GetErrors()["c"] == "" || len(resp.GetErrors()) != 1 {
		t.Errorf("errors = %v, want c's", resp.GetErrors())
	}
	if len(b.got) != 1 || !b.got[0].GetLocalOnly() || len(b.got[0].GetAfterSeq()) != 1 || b.got[0].GetAfterSeq()["b"] != 6 {
		t.Errorf("request to b = %+v, want local_only with b's own cursor", b.got)
	}
	// --host asks that host only.
	b.got = nil
	resp, err = s.ListFirewallLog(adminCtx(), &pb.ListFirewallLogRequest{Host: "b"})
	if err != nil || len(resp.GetEntries()) != 2 || len(b.got) != 1 {
		t.Errorf("--host b: %v, %d entries, %d call(s)", err, len(resp.GetEntries()), len(b.got))
	}
	// The cursor resumes: only entries after it.
	resp, err = s.ListFirewallLog(adminCtx(), &pb.ListFirewallLogRequest{Host: "test-host", AfterSeq: map[string]uint64{"test-host": 1}})
	if err != nil || len(resp.GetEntries()) != 1 || resp.GetEntries()[0].GetSeq() != 2 {
		t.Errorf("after seq 1: %v, %+v", err, resp.GetEntries())
	}
}
