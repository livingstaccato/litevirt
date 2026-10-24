package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/placement"
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
// (accessVLANStartPreflight), a failover one included. A bridge that does not
// exist here is named too: a start here would have litevirt create it, and
// litevirt creates a bridge without VLAN filtering, so that start would be
// refused the same way, and failover must pass this host over as well. A
// device that exists and is not a Linux bridge is not judged, as the start
// preflight does not judge it. Observed on the first pass, confirmed on the
// next; resolved on the pass that finds the bridge filtering, or used by no
// such VM.
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
		if problem == nil && !s.bridgeExistsHere(br) {
			problem = fmt.Errorf("bridge %q does not exist here, and the bridge litevirt would create for a start here does not "+
				"filter VLANs, so a NIC on VLAN %d would join its untagged segment; create it with VLAN filtering on "+
				"(ip link add %s type bridge vlan_filtering 1) and give its uplink the VLAN", br, u.vlan, br)
		}
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
			"by failover either, and are not migrated or drained onto it; failover places them on another host while one "+
			"qualifies, and one placed here anyway waits and starts once the bridge filters VLANs (a refused `lv start` "+
			"or health restart: start it again with `lv start <vm>`). "+
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

// accessVLANMoveView is what a drain knows of the hosts whose bridge cannot
// carry an access-port NIC (bridge_vlan_filtering_off): a VM with such a NIC
// is not drained onto one (placement.Request.ExcludeHosts). The target refuses
// the move itself (accessVLANMoveRefusal); this only keeps the drain from
// choosing it, so the VM goes to a host that can take it.
type accessVLANMoveView struct {
	nets  map[string]corrosion.NetworkRecord
	unfit map[string]map[string]bool
}

// readAccessVLANMoveView reads the view, or nil — no host excluded — when no
// host is named or a read fails (each target still refuses on its own).
func (s *Server) readAccessVLANMoveView(ctx context.Context) *accessVLANMoveView {
	unfit, err := health.AccessVLANUnfitHosts(ctx, s.db)
	if err != nil {
		slog.Warn("drain: cannot read which hosts' bridges cannot carry an access-VLAN NIC; each target judges its own", "error", err)
		return nil
	}
	if len(unfit) == 0 {
		return nil
	}
	nets, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		slog.Warn("drain: cannot read the networks; each target judges its own bridges for access-VLAN NICs", "error", err)
		return nil
	}
	return &accessVLANMoveView{nets: health.AccessVLANNetworks(nets), unfit: unfit}
}

// exclude adds to req.ExcludeHosts each host whose bridge cannot carry one of
// vm's access-port NICs.
func (v *accessVLANMoveView) exclude(req *placement.Request, vm corrosion.VMRecord) {
	if v == nil || vm.Spec == "" {
		return
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(vm.Spec), spec) != nil {
		return
	}
	for host, why := range health.AccessVLANHostsUnfitFor(spec, v.nets, v.unfit) {
		if req.ExcludeHosts == nil {
			req.ExcludeHosts = map[string]string{}
		}
		req.ExcludeHosts[host] = why
	}
}

// accessVLANMoveRefusal is a migration target's refusal (EnsureDisks, which
// every live and cold move asks before anything is copied or created) of a
// VM with an access-port NIC whose bridge here does not filter VLANs, or does
// not exist: the guest would join the bridge's untagged segment instead of
// its VLAN. The move's networks are provisioned here before EnsureDisks
// (prepareMigrationTarget), so a bridge litevirt had to create for it is
// judged as created — without VLAN filtering. A VM whose spec cannot be read
// is not judged here.
func (s *Server) accessVLANMoveRefusal(ctx context.Context, vm *corrosion.VMRecord) error {
	if vm == nil || vm.Spec == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(vm.Spec), spec) != nil {
		return nil
	}
	for _, n := range spec.GetNetwork() {
		v := accessVLAN(n.GetTrunk())
		if v == 0 {
			continue
		}
		bridge := resolveBridge(ctx, s.db, n.GetName())
		if bridge == "" || strings.HasPrefix(bridge, "direct:") {
			continue
		}
		problem := network.AccessVLANBridgeProblem(bridge, v, s.bridgeVLANFilteringOf)
		if problem == nil && !s.bridgeExistsHere(bridge) {
			problem = fmt.Errorf("bridge %q does not exist here", bridge)
		}
		if problem != nil {
			return status.Errorf(codes.FailedPrecondition,
				"not moving %q to %s: its NIC on network %s is an access port on VLAN %d, and here %v; "+
					"move it to a host whose bridge filters VLANs, or turn VLAN filtering on here first", vm.Name, s.hostName, n.GetName(), v, problem)
		}
	}
	return nil
}

// vmHasAccessVLANNIC reports whether vm has an access-port NIC (trunk: with
// one VLAN); true when its row cannot be read, so a move asks the target.
func (s *Server) vmHasAccessVLANNIC(ctx context.Context, vm string) bool {
	rec, err := corrosion.GetVM(ctx, s.db, vm)
	if err != nil {
		return true
	}
	if rec == nil || rec.Spec == "" {
		return false
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(rec.Spec), spec) != nil {
		return false
	}
	for _, n := range spec.GetNetwork() {
		if accessVLAN(n.GetTrunk()) != 0 {
			return true
		}
	}
	return false
}
