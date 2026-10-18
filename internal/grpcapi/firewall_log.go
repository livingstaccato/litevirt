package grpcapi

// The firewall log reader (docs/firewall.md, "Logging"): lv firewall log.
// Records are tenant flow metadata, so reading them needs the verb
// firewall.log.view at "/" (auth.VerbFirewallLogView), which among the
// built-in roles only Admin holds; with no role bindings the legacy fallback
// is admin.

import (
	"context"
	"sort"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// defaultFirewallLogLimit is the records a ListFirewallLog returns with no
// limit.
const defaultFirewallLogLimit = 200

// SetFirewallLogStore gives the server this host's firewall log store.
func (s *Server) SetFirewallLogStore(st *firewall.LogStore) { s.fwLogStore.Store(st) }

// ListFirewallLog returns firewall log records: this host's, or (without
// local_only) every active host's, merged by time; --host asks one host.
func (s *Server) ListFirewallLog(ctx context.Context, req *pb.ListFirewallLogRequest) (*pb.ListFirewallLogResponse, error) {
	if err := s.RequirePerm(ctx, "/", auth.VerbFirewallLogView, "admin"); err != nil {
		return nil, err
	}
	var since time.Time
	if req.GetSince() != "" {
		t, err := time.Parse(time.RFC3339Nano, req.GetSince())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "since %q: want an RFC 3339 time", req.GetSince())
		}
		since = t
	}
	limit := int(req.GetLimit())
	if limit <= 0 {
		limit = defaultFirewallLogLimit
	}
	limit = min(limit, firewall.LogRingSize)
	out := &pb.ListFirewallLogResponse{Errors: map[string]string{}}
	local := func() {
		st := s.fwLogStore.Load()
		if st == nil {
			out.Errors[s.hostName] = "the firewall log is not available on this host"
			return
		}
		for _, r := range st.List(firewall.LogFilter{Workload: req.GetWorkload(), Since: since,
			AfterSeq: req.GetAfterSeq()[s.hostName], Limit: limit}) {
			out.Entries = append(out.Entries, toPbLogEntry(s.hostName, r))
		}
	}
	if req.GetLocalOnly() || req.GetHost() == s.hostName {
		local()
		return finishLog(out, limit), nil
	}
	var hosts []string
	if req.GetHost() != "" {
		h, err := corrosion.GetHost(ctx, s.db, req.GetHost())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "read host %s: %v", req.GetHost(), err)
		}
		if h == nil {
			return nil, status.Errorf(codes.InvalidArgument, "host %q is not in the cluster (lv host ls)", req.GetHost())
		}
		hosts = []string{h.Name}
	} else {
		local()
		all, err := corrosion.ListHosts(ctx, s.db)
		if err != nil {
			out.Errors["*"] = "list hosts: " + err.Error()
		}
		for _, h := range all {
			if h.Name != s.hostName && h.State == "active" {
				hosts = append(hosts, h.Name)
			}
		}
	}
	for _, h := range hosts {
		entries, err := s.peerFirewallLog(ctx, h, req, limit)
		if err != nil {
			out.Errors[h] = err.Error()
			continue
		}
		out.Entries = append(out.Entries, entries...)
	}
	return finishLog(out, limit), nil
}

// peerFirewallLog asks one peer for its own records, from its own cursor.
func (s *Server) peerFirewallLog(ctx context.Context, host string, req *pb.ListFirewallLogRequest, limit int) ([]*pb.FirewallLogEntry, error) {
	hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, closer, err := s.dialPeer(hctx, host)
	if err != nil {
		return nil, err
	}
	defer closer()
	resp, err := c.ListFirewallLog(hctx, &pb.ListFirewallLogRequest{Workload: req.GetWorkload(), Since: req.GetSince(),
		Limit: uint32(limit), AfterSeq: map[string]uint64{host: req.GetAfterSeq()[host]}, LocalOnly: true})
	if err != nil {
		return nil, err
	}
	if msg := resp.GetErrors()[host]; msg != "" {
		return nil, status.Error(codes.Unavailable, msg)
	}
	var out []*pb.FirewallLogEntry
	for _, e := range resp.GetEntries() {
		if e.GetHost() == host {
			out = append(out, e)
		}
	}
	return out, nil
}

// finishLog sorts the entries by time (then host and sequence) and keeps the
// newest limit.
func finishLog(out *pb.ListFirewallLogResponse, limit int) *pb.ListFirewallLogResponse {
	at := func(e *pb.FirewallLogEntry) time.Time {
		t, _ := time.Parse(time.RFC3339Nano, e.GetTime())
		return t
	}
	sort.SliceStable(out.Entries, func(i, j int) bool {
		a, b := out.Entries[i], out.Entries[j]
		if ta, tb := at(a), at(b); !ta.Equal(tb) {
			return ta.Before(tb)
		}
		if a.GetHost() != b.GetHost() {
			return a.GetHost() < b.GetHost()
		}
		return a.GetSeq() < b.GetSeq()
	})
	if n := len(out.Entries); n > limit {
		out.Entries = out.Entries[n-limit:]
	}
	if len(out.Errors) == 0 {
		out.Errors = nil
	}
	return out
}

func toPbLogEntry(host string, r firewall.LogRecord) *pb.FirewallLogEntry {
	return &pb.FirewallLogEntry{Host: host, Seq: r.Seq, Time: r.Time.UTC().Format(time.RFC3339Nano), Workload: r.Workload,
		Mac: r.MAC, Device: r.Device, Side: r.Side, RuleId: r.RuleID, Tier: r.Tier, Verdict: r.Verdict, Family: r.Family,
		Proto: r.Proto, Src: r.Src, Sport: uint32(r.Sport), Dst: r.Dst, Dport: uint32(r.Dport), Length: r.Length, TcpFlags: r.TCPFlags}
}
