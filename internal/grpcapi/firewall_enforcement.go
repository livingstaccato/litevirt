package grpcapi

// Per-NIC enforcement mode (docs/firewall.md, "Observe and enforce").
//
// A cluster that upgraded starts in OBSERVE: per-NIC rules are installed with
// would-drop counters and drop nothing, and every host with guest NICs raises a
// health condition and a notification saying so. `lv firewall enforce on`
// switches to enforcing; a freshly initialised cluster enforces from the start
// (corrosion.SeedFirewallEnforcement).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
	"github.com/litevirt/litevirt/internal/notify"
)

// FirewallEvaluator is the health-condition evaluator of the per-NIC firewall.
const FirewallEvaluator = "firewall"

// Condition codes, one row per host (subject_kind host).
const (
	CondFirewallObserve     = "firewall.nic.observe"     // rules observed, not enforced
	CondFirewallUnavailable = "firewall.nic.unavailable" // no bridge conntrack: guards only
	CondFirewallRefused     = "firewall.nic.refused"     // the kernel refused the per-NIC table
	CondFirewallTrunkVLANs  = "firewall.nic.trunk_vlans" // trunk VLANs their network does not allow
	CondFirewallInvalidRows = "firewall.rule.invalid"    // stored rows that fail the rule grammar
)

// SetFirewallEnforcement switches per-NIC enforcement for the whole cluster.
// Admin only, audited, replicated.
func (s *Server) SetFirewallEnforcement(ctx context.Context, req *pb.SetFirewallEnforcementRequest) (*pb.FirewallEnforcementStatus, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	mode := req.GetMode()
	if mode != corrosion.FirewallEnforce && mode != corrosion.FirewallObserve {
		return nil, status.Errorf(codes.InvalidArgument, "mode %q: want %s or %s", mode, corrosion.FirewallEnforce, corrosion.FirewallObserve)
	}
	before, berr := corrosion.GetFirewallEnforcement(ctx, s.db)
	beforeText := corrosion.AuditUnknown(fmt.Errorf("unread"))
	if berr == nil {
		beforeText = before.Mode
		if !before.Recorded {
			beforeText = corrosion.AuditStateUnset
		}
	}
	if err := corrosion.SetFirewallEnforcement(ctx, s.db, mode, callerUsername(ctx)); err != nil {
		s.audit(ctx, "firewall.enforcement", "cluster", corrosion.AuditChange(beforeText, mode), "error")
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		}
		return nil, status.Errorf(codes.Internal, "set firewall enforcement: %v", err)
	}
	s.audit(ctx, "firewall.enforcement", "cluster", corrosion.AuditChange(beforeText, mode), "ok")
	slog.Info("firewall enforcement set", "mode", mode, "by", callerUsername(ctx))
	s.reconcileLocal(ctx)
	return s.GetFirewallEnforcement(ctx, &pb.GetFirewallEnforcementRequest{})
}

// GetFirewallEnforcement reports the policy and, per host, what it has in
// force and what it would have dropped. Without local_only it asks every
// other active host too.
func (s *Server) GetFirewallEnforcement(ctx context.Context, req *pb.GetFirewallEnforcementRequest) (*pb.FirewallEnforcementStatus, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	enf, err := corrosion.GetFirewallEnforcement(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read firewall enforcement: %v", err)
	}
	out := &pb.FirewallEnforcementStatus{Mode: enf.Mode, SetBy: enf.SetBy, UpdatedAt: enf.UpdatedAt}
	out.Hosts = append(out.Hosts, s.localFirewallEnforcement(ctx))
	if req.GetLocalOnly() {
		return out, nil
	}
	hosts, err := corrosion.ListHosts(ctx, s.db)
	if err != nil {
		return out, nil
	}
	for _, h := range hosts {
		if h.Name == s.hostName || h.State != "active" {
			continue
		}
		hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		client, conn, perr := s.peerClient(hctx, h.Name)
		if perr != nil {
			cancel()
			out.Hosts = append(out.Hosts, &pb.FirewallHostEnforcement{HostName: h.Name, Error: perr.Error()})
			continue
		}
		st, gerr := client.GetFirewallEnforcement(hctx, &pb.GetFirewallEnforcementRequest{LocalOnly: true})
		conn.Close()
		cancel()
		if gerr != nil || len(st.GetHosts()) == 0 {
			msg := "no answer"
			if gerr != nil {
				msg = gerr.Error()
			}
			out.Hosts = append(out.Hosts, &pb.FirewallHostEnforcement{HostName: h.Name, Error: msg})
			continue
		}
		out.Hosts = append(out.Hosts, st.GetHosts()[0])
	}
	sort.Slice(out.Hosts, func(i, j int) bool { return out.Hosts[i].HostName < out.Hosts[j].HostName })
	return out, nil
}

// appliedStater is what the daemon's reconciler offers beyond the
// FirewallReconciler interface (test fakes need not).
type appliedStater interface {
	AppliedState() firewall.AppliedState
}

// wouldDropKeeper keeps this host's observe-mode totals (firewall.WouldDropTally).
type wouldDropKeeper interface {
	WouldDropTotals(ctx context.Context) (time.Time, []firewall.TallyEntry, error)
	ResetWouldDrops(ctx context.Context, now time.Time) error
}

func (s *Server) localFirewallEnforcement(ctx context.Context) *pb.FirewallHostEnforcement {
	h := &pb.FirewallHostEnforcement{HostName: s.hostName}
	if r, ok := s.fwRec().(appliedStater); ok {
		st := r.AppliedState()
		h.AppliedMode, h.Error = st.Mode, st.NICTableError
	}
	if k, ok := s.fwRec().(wouldDropKeeper); ok {
		since, entries, err := k.WouldDropTotals(ctx)
		if err != nil && h.Error == "" {
			h.Error = err.Error()
		}
		if !since.IsZero() {
			h.WouldDropSince = since.UTC().Format(time.RFC3339)
		}
		for _, e := range entries {
			h.WouldDrops = append(h.WouldDrops, &pb.FirewallWouldDrop{
				Device: e.Device, Workload: e.Workload, Mac: e.MAC, Side: e.Side, Rule: e.Rule,
				Packets: e.Packets, Bytes: e.Bytes,
			})
		}
	}
	return h
}

// ResetFirewallWouldDrops restarts every host's would-drop totals from now.
// Admin only, audited: the totals are the evidence an operator turns
// enforcement on by.
func (s *Server) ResetFirewallWouldDrops(ctx context.Context, req *pb.ResetFirewallWouldDropsRequest) (*pb.FirewallEnforcementStatus, error) {
	if err := RequireRole(ctx, "admin"); err != nil {
		return nil, err
	}
	now := time.Now()
	if k, ok := s.fwRec().(wouldDropKeeper); ok {
		if err := k.ResetWouldDrops(ctx, now); err != nil {
			s.audit(ctx, "firewall.would_drop.reset", s.hostName, "", "error")
			return nil, status.Errorf(codes.Internal, "reset the would-drop totals on %s: %v", s.hostName, err)
		}
	}
	s.audit(ctx, "firewall.would_drop.reset", s.hostName, "since="+now.UTC().Format(time.RFC3339), "ok")
	if !req.GetLocalOnly() {
		hosts, err := corrosion.ListHosts(ctx, s.db)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "list hosts: %v", err)
		}
		var failed []string
		for _, h := range hosts {
			if h.Name == s.hostName || h.State != "active" {
				continue
			}
			hctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			client, conn, perr := s.peerClient(hctx, h.Name)
			if perr == nil {
				_, perr = client.ResetFirewallWouldDrops(hctx, &pb.ResetFirewallWouldDropsRequest{LocalOnly: true})
				conn.Close()
			}
			cancel()
			if perr != nil {
				failed = append(failed, h.Name+": "+perr.Error())
			}
		}
		if len(failed) > 0 {
			return nil, status.Errorf(codes.Unavailable, "the totals were not reset on every host: %s", strings.Join(failed, "; "))
		}
	}
	return s.GetFirewallEnforcement(ctx, &pb.GetFirewallEnforcementRequest{LocalOnly: req.GetLocalOnly()})
}

// RecordFirewallState turns a reconcile pass's applied state into this host's
// health conditions, notifying on every change. The daemon wires it as the
// reconciler's state hook.
func (s *Server) RecordFirewallState(ctx context.Context, st firewall.AppliedState) {
	s.setFirewallCondition(ctx, CondFirewallObserve, st.Mode == firewall.NICModeObserve, corrosion.SeverityWarning,
		"per-NIC firewall rules are observed, not enforced: nothing they match is dropped; see `lv firewall enforce status`, then `lv firewall enforce on`")
	s.setFirewallCondition(ctx, CondFirewallUnavailable, st.Mode == firewall.NICModeGuardsOnly, corrosion.SeverityCritical,
		"nf_conntrack_bridge is unavailable on this host: per-NIC rules are not enforced here (NIC guards and the VLAN rule are)")
	s.setFirewallCondition(ctx, CondFirewallRefused, st.NICTableError != "", corrosion.SeverityCritical,
		"the kernel refused the per-NIC firewall table; the previous one stays, routed filtering and NAT still apply: "+st.NICTableError)
	s.setFirewallCondition(ctx, CondFirewallTrunkVLANs, len(st.BlockedTrunks) > 0, corrosion.SeverityWarning,
		s.blockedTrunksText(ctx, st.BlockedTrunks))
	s.setFirewallCondition(ctx, CondFirewallInvalidRows, len(st.InvalidRows) > 0, corrosion.SeverityCritical,
		invalidRowsText(st.InvalidRows))
	s.setFirewallCondition(ctx, CondFirewallPolicyUnreadable, len(st.UnreadablePolicies) > 0, corrosion.SeverityWarning,
		unreadablePoliciesText(st.UnreadablePolicies))
	s.recordTagGroupState(ctx, st.TagGroups)
}

// invalidRowsText names each stored row the firewall does not render as
// written, what it does instead, and the command that removes the row.
func invalidRowsText(rows []firewall.InvalidRow) string {
	if len(rows) == 0 {
		return ""
	}
	const show = 10
	var parts []string
	for i, r := range rows {
		if i == show {
			parts = append(parts, fmt.Sprintf("and %d more", len(rows)-show))
			break
		}
		what := r.Table + " " + r.ID
		if r.Table != "ip_sets" {
			what += fmt.Sprintf(" (stored action %q)", r.Action)
		}
		parts = append(parts, fmt.Sprintf("%s: %s; %s; remove it with `%s`", what, r.Reason, r.Handling, removeRowCmd(r)))
	}
	return "firewall rows not rendered as written (none renders more than it asked for): " + strings.Join(parts, "; ")
}

func removeRowCmd(r firewall.InvalidRow) string {
	switch r.Table {
	case "cluster_firewall_rules":
		return "lv firewall cluster-rule rm " + r.ID
	case "host_firewall_rules":
		return "lv firewall host-rule rm " + r.ID
	case "ip_sets":
		return "lv firewall ipset rm " + r.ID
	}
	return "lv sg rule-rm " + r.ID
}

// blockedTrunksText names each trunk whose VLANs its network does not allow,
// and the command that allows them (re-review R2-I1).
func (s *Server) blockedTrunksText(ctx context.Context, blocked []firewall.BlockedTrunk) string {
	if len(blocked) == 0 {
		return ""
	}
	byNet := map[string][]int{}
	var who []string
	for _, b := range blocked {
		byNet[b.Network] = append(byNet[b.Network], b.VIDs...)
		who = append(who, fmt.Sprintf("%s on %s (VLANs %s)", b.Workload, b.Network, vidList(b.VIDs)))
	}
	nets := make([]string, 0, len(byNet))
	for n := range byNet {
		nets = append(nets, n)
	}
	sort.Strings(nets)
	flat, _ := corrosion.FlatBridgeVLANs(ctx, s.db)
	var cmds []string
	for _, n := range nets {
		vids := byNet[n]
		def, err := lookupNetworkDef(ctx, s.db, n)
		switch {
		case err != nil:
			cmds = append(cmds, fmt.Sprintf("lv network set %s --allowed-vlans %s", n, vidList(sortedVIDs(vids))))
		case def != nil:
			vids = append(vids, def.AllowedVLANs...)
			cmds = append(cmds, fmt.Sprintf("lv network set %s --allowed-vlans %s (needs network.update on %s)",
				n, vidList(sortedVIDs(vids)), n))
		default:
			// A flat bridge (no network row): its own list, which the
			// command replaces, beside the VLANs recorded for it at upgrade
			// (re-review R4-I1).
			vids = append(vids, flat[n]...)
			cmds = append(cmds, fmt.Sprintf("lv network set %s --allowed-vlans %s (%s is a flat bridge, with no network row: "+
				"needs network.update at the cluster root)", n, vidList(sortedVIDs(vids)), n))
		}
	}
	sort.Strings(who)
	return "trunk VLANs their network does not allow are dropped: " + strings.Join(who, "; ") +
		". To allow them: " + strings.Join(cmds, "; ")
}

func vidList(v []int) string {
	out := make([]string, len(v))
	for i, x := range v {
		out[i] = strconv.Itoa(x)
	}
	return strings.Join(out, ",")
}

// setFirewallCondition raises or resolves one of this host's firewall
// conditions, writing and notifying only on a change.
func (s *Server) setFirewallCondition(ctx context.Context, code string, active bool, severity, detail string) {
	s.setHostCondition(ctx, FirewallEvaluator, code, active, severity, detail)
}

// setHostCondition raises or resolves one of this host's conditions of an
// evaluator, writing and notifying only on a change.
func (s *Server) setHostCondition(ctx context.Context, evaluator, code string, active bool, severity, detail string) {
	if s.db == nil {
		return
	}
	row, ok, err := corrosion.GetHealthCondition(ctx, s.db, evaluator, code, "host", s.hostName)
	if err != nil {
		return
	}
	isActive := ok && row.Lifecycle != corrosion.ConditionResolved
	if active == isActive && (!active || row.Evidence == detail) {
		return
	}
	ts := time.Now().UTC().Format(time.RFC3339)
	if !ok {
		if !active {
			return
		}
		row = corrosion.HealthCondition{Evaluator: evaluator, Code: code, SubjectKind: "host", SubjectID: s.hostName, FirstSeen: ts}
	}
	if active {
		if !isActive {
			row.FirstSeen, row.ConfirmedAt, row.ObserveCount = ts, ts, 0
		}
		row.Lifecycle, row.ResolvedAt, row.CleanCount, row.Evidence = corrosion.ConditionConfirmed, "", 0, detail
		row.ObserveCount++
	} else {
		row.Lifecycle, row.ResolvedAt, row.ObserveCount, row.CleanCount = corrosion.ConditionResolved, ts, 0, 1
	}
	row.Severity, row.Hosts, row.LastSeen, row.Reporter = severity, []string{s.hostName}, ts, s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("could not record a health condition", "evaluator", evaluator, "code", code, "error", err)
		return
	}
	sev := notify.SevWarn
	if severity == corrosion.SeverityCritical {
		sev = notify.SevError
	}
	verb := "raised"
	if !active {
		verb, sev = "resolved", notify.SevInfo
	}
	s.notify(ctx, notify.Notification{Kind: code, Severity: sev, Subject: s.hostName, Detail: verb + ": " + detail})
}

// SeedFirewallEnforcementLoop records the founder's genesis decision
// (decisionPath, written by the daemon when it founded the cluster: enforce)
// as the cluster's per-NIC enforcement mode, the first time it can
// (corrosion.SeedFirewallEnforcement), audits it and consumes the decision.
// With no decision on disk — a joiner, a rejoiner, a host of a cluster that
// upgraded — it records nothing: with no mode recorded the cluster observes,
// and only `lv firewall enforce` changes that (re-review I-3).
func (s *Server) SeedFirewallEnforcementLoop(ctx context.Context, every time.Duration, decisionPath string) {
	b, err := os.ReadFile(decisionPath)
	if err != nil {
		return
	}
	mode := strings.TrimSpace(string(b))
	if mode != corrosion.FirewallEnforce && mode != corrosion.FirewallObserve {
		slog.Warn("firewall: ignoring an unreadable initial enforcement decision", "path", decisionPath, "value", mode)
		return
	}
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		enf, err := corrosion.GetFirewallEnforcement(ctx, s.db)
		if err == nil && enf.Recorded {
			_ = os.Remove(decisionPath)
			return
		}
		if wrote, err := corrosion.SeedFirewallEnforcement(ctx, s.db, mode, s.hostName); err != nil {
			slog.Warn("firewall: could not record the initial enforcement mode", "error", err)
		} else if wrote != "" {
			slog.Info("firewall: recorded the cluster's initial per-NIC enforcement mode", "mode", wrote)
			s.auditAs(ctx, "litevirt", "firewall.enforcement", "cluster",
				corrosion.AuditChange(corrosion.AuditStateUnset, wrote)+" (initial, at genesis)", "ok")
			_ = os.Remove(decisionPath)
			s.reconcileLocal(ctx)
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
