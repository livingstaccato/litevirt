package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
)

// AccessVLANBridgeReconcileInterval is how often a host re-judges its bridges
// for bridge_vlan_filtering_off.
const AccessVLANBridgeReconcileInterval = 30 * time.Second

// accessVLANEvidenceVMs caps the VM names the evidence lists; the count is
// always the full one.
const accessVLANEvidenceVMs = 10

// ReconcileAccessVLANBridges raises bridge_vlan_filtering_off (evaluator
// access_vlan, subject host/<bridge>@<this host>, warning) for each bridge of
// this host that is a Linux bridge with VLAN filtering off (or unreadable)
// while some VM of the cluster has an access-port NIC (trunk: with one VLAN)
// on a network using it: a start of that VM here is refused
// (accessVLANStartPreflight), a failover one included. Observed on the first
// pass, confirmed on the next; resolved on the pass that finds the bridge
// filtering, gone, or used by no such VM. A bridge that does not exist here
// is not judged, as the start preflight does not judge it.
func (s *Server) ReconcileAccessVLANBridges(ctx context.Context) {
	if s.db == nil {
		return
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		slog.Warn("access-VLAN bridges: list VMs", "error", err)
		return
	}
	netRows, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		slog.Warn("access-VLAN bridges: list networks", "error", err)
		return
	}
	nets := health.AccessVLANNetworks(netRows)
	type use struct {
		vlan int
		vms  []string
	}
	uses := map[string]*use{}
	for _, vm := range vms {
		if vm.IsTemplate || vm.Spec == "" {
			continue
		}
		spec := &pb.VMSpec{}
		if json.Unmarshal([]byte(vm.Spec), spec) != nil {
			continue
		}
		for br, vlan := range health.AccessVLANBridges(spec, nets) {
			u := uses[br]
			if u == nil {
				u = &use{vlan: vlan}
				uses[br] = u
			}
			u.vms = append(u.vms, vm.Name)
		}
	}
	open := map[string]bool{}
	for br, u := range uses {
		problem := network.AccessVLANBridgeProblem(br, u.vlan, s.bridgeVLANFilteringOf)
		if problem == nil {
			continue
		}
		open[br] = true
		sort.Strings(u.vms)
		s.judgeAccessVLANBridge(ctx, br, u.vms, problem)
	}
	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, s.db, health.AccessVLANEvaluator, health.CondBridgeVLANFilteringOff)
	if err != nil {
		return
	}
	for i, c := range conds {
		if deleted[i] || c.Lifecycle == corrosion.ConditionResolved || c.SubjectKind != "host" {
			continue
		}
		br, host, ok := health.SplitAccessVLANSubject(c.SubjectID)
		if !ok || host != s.hostName || open[br] {
			continue
		}
		s.judgeAccessVLANBridge(ctx, br, nil, nil)
	}
}

// judgeAccessVLANBridge raises bridge_vlan_filtering_off for bridge on this
// host while problem, naming the VMs that cannot start here, and resolves it
// once problem is nil.
func (s *Server) judgeAccessVLANBridge(ctx context.Context, bridge string, vms []string, problem error) {
	subject := health.AccessVLANSubject(bridge, s.hostName)
	now := time.Now().UTC().Format(time.RFC3339)
	row, found, err := corrosion.GetHealthCondition(ctx, s.db, health.AccessVLANEvaluator, health.CondBridgeVLANFilteringOff, "host", subject)
	if err != nil {
		return
	}
	if problem == nil {
		if !found || row.Lifecycle == corrosion.ConditionResolved {
			return
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, s.hostName
		row.ObserveCount, row.CleanCount = 0, row.CleanCount+1
		if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
			slog.Warn("access-VLAN bridges: resolve condition", "bridge", bridge, "error", err)
		}
		return
	}
	if !found || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{Evaluator: health.AccessVLANEvaluator, Code: health.CondBridgeVLANFilteringOff,
			SubjectKind: "host", SubjectID: subject, Lifecycle: corrosion.ConditionObserved, FirstSeen: now}
	} else if row.Lifecycle == corrosion.ConditionObserved && row.ObserveCount >= 1 {
		row.Lifecycle, row.ConfirmedAt = corrosion.ConditionConfirmed, now
	}
	row.ObserveCount++
	row.CleanCount = 0
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{s.hostName}
	listed := vms
	if len(listed) > accessVLANEvidenceVMs {
		listed = listed[:accessVLANEvidenceVMs]
	}
	ev, _ := json.Marshal(map[string]any{
		"bridge": bridge, "host": s.hostName, "vm_count": len(vms), "vms": listed,
		"detail": fmt.Sprintf("host %s: %v. %d VM(s) with an access-VLAN NIC on bridge %s (%s) cannot start on %s, "+
			"by failover either. "+
			"Keep VLAN filtering on across a reboot in what creates the bridge "+
			"(docs/networking.md, \"Access-VLAN NICs need a VLAN-filtering bridge\")",
			s.hostName, problem, len(vms), bridge, strings.Join(listed, ", "), s.hostName),
	})
	row.Evidence = string(ev)
	row.LastSeen, row.ResolvedAt, row.Reporter = now, "", s.hostName
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		slog.Warn("access-VLAN bridges: raise condition", "bridge", bridge, "error", err)
	}
}
