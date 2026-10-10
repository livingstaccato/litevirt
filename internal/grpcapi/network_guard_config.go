package grpcapi

// What a network keeps from its NICs, set after create (re-review R2-I1, m4):
// its router and reserved addresses (no guest NIC may claim them) and the
// trunk VLANs a NIC on the `trunk:` feature may carry on it. And the one-time
// recording, at upgrade, of the trunks a cluster already had into those lists.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// SetNetworkGuardConfig changes a network's gateway, reserved addresses and
// allowed trunk VLANs. It needs network.update on the network: what a guest
// may claim, and which VLANs a tenant's trunk reaches, are its network's
// owner's to decide. Audited as network.update.
func (s *Server) SetNetworkGuardConfig(ctx context.Context, req *pb.SetNetworkGuardConfigRequest) (*pb.NetworkInfo, error) {
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "name required")
	}
	nr, err := corrosion.GetNetwork(ctx, s.db, req.GetName())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get network: %v", err)
	}
	if nr == nil {
		return nil, status.Errorf(codes.NotFound, "network %q not found", req.GetName())
	}
	if err := s.RequirePerm(ctx, networkRBACPathFor(nr.Project, nr.Name), "network.update", "operator"); err != nil {
		s.audit(ctx, "network.update", nr.Name, "guard config", "denied")
		return nil, status.Errorf(codes.PermissionDenied, "setting %s's gateway, reserved addresses or trunk VLANs needs network.update on it", nr.Name)
	}
	var def compose.NetworkDef
	if nr.Config != "" {
		if err := json.Unmarshal([]byte(nr.Config), &def); err != nil {
			return nil, status.Errorf(codes.Internal, "read network %q config: %v", nr.Name, err)
		}
	}
	before := guardConfigText(def)
	if req.GetSetGateway() {
		def.Gateway = strings.TrimSpace(req.GetGateway())
	}
	if req.GetSetReservedAddresses() {
		def.ReservedAddresses = nil
		for _, a := range req.GetReservedAddresses() {
			if a = strings.TrimSpace(a); a != "" {
				def.ReservedAddresses = append(def.ReservedAddresses, a)
			}
		}
	}
	if req.GetSetAllowedVlans() {
		def.AllowedVLANs = nil
		for _, v := range req.GetAllowedVlans() {
			if v < 1 || v > 4094 {
				return nil, status.Errorf(codes.InvalidArgument, "VLAN %d is outside 1-4094", v)
			}
			def.AllowedVLANs = append(def.AllowedVLANs, int(v))
		}
		def.AllowedVLANs = sortedVIDs(def.AllowedVLANs)
	}
	for _, a := range append([]string{def.Gateway}, def.ReservedAddresses...) {
		if a == "" {
			continue
		}
		if ip, err := netip.ParseAddr(a); err != nil || ip.Zone() != "" {
			return nil, status.Errorf(codes.InvalidArgument, "gateway / reserved address %q is not an IP address", a)
		}
	}
	b, err := json.Marshal(def)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "encode network config: %v", err)
	}
	nr.Config = string(b)
	if err := corrosion.UpsertNetwork(ctx, s.db, *nr); err != nil {
		s.audit(ctx, "network.update", nr.Name, corrosion.AuditChange(before, "unchanged"), "error")
		return nil, status.Errorf(codes.Internal, "update network: %v", err)
	}
	s.audit(ctx, "network.update", nr.Name, corrosion.AuditChange(before, guardConfigText(def)), "ok")
	s.reconcileLocal(ctx)
	return networkRecordToInfo(nr), nil
}

// guardConfigText renders the fields SetNetworkGuardConfig sets, for audit.
func guardConfigText(d compose.NetworkDef) string {
	vids := make([]string, len(d.AllowedVLANs))
	for i, v := range d.AllowedVLANs {
		vids[i] = strconv.Itoa(v)
	}
	return fmt.Sprintf("{gateway=%s reserved=[%s] allowed-vlans=[%s]}", d.Gateway,
		strings.Join(d.ReservedAddresses, ","), strings.Join(vids, ","))
}

func sortedVIDs(in []int) []int {
	sort.Ints(in)
	var out []int
	for i, v := range in {
		if i == 0 || v != in[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// recordExistingTrunkVLANs records the VLANs of every trunk NIC that predates
// guards (it has no guard record) into its network's allowed list, so a trunk
// in use at upgrade keeps its VLANs (re-review R2-I1). The loader grants a
// trunk nothing else: lacking a record is not an allowance (R3-I1).
//
// It runs on every pass until the release has latched — an older build may
// create a trunk during the rollout, and that one keeps its VLANs too — and
// reports done after a pass made with the release latched: from then on no
// trunk without a record appears but a re-create's, which carries at most the
// VLANs its incarnation had. What it has recorded is kept under
// corrosion.TrunkVLANsRecordedKey, and a VLAN recorded once is never recorded
// again, so an operator who takes it off the list (`lv network set
// --allowed-vlans`) keeps it off. A flat bridge (no network row) has no list;
// its recorded VLANs are what the loader allows it.
//
// A replica that has not caught up records nothing (m4): it would upsert its
// stale copy of a network row over a newer one, and miss trunks it has not
// seen.
func (s *Server) recordExistingTrunkVLANs(ctx context.Context) (done bool, err error) {
	if !s.db.MayWriteClusterPolicy() {
		return false, nil
	}
	if ok, why := corrosion.ReplicaTrusted(ctx, s.db, s.hostName, s.db.ReplicaCaughtUp); !ok {
		slog.Debug("firewall: not recording trunk VLANs yet: the replica has not caught up", "why", why)
		return false, nil
	}
	final := s.firewallReleaseActive()
	recorded, have, err := corrosion.TrunkVLANsRecorded(ctx, s.db)
	if err != nil {
		return false, err
	}
	if recorded == nil {
		recorded = map[string][]int{}
	}
	guards, err := corrosion.ListNICGuardsWithDeleted(ctx, s.db)
	if err != nil {
		return false, err
	}
	vms, err := corrosion.ListVMs(ctx, s.db, "", "")
	if err != nil {
		return false, err
	}
	add := map[string][]int{} // network → VLANs
	for _, vm := range vms {
		spec := parseVMSpecBlob(vm.Spec)
		nics, _ := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
		macAt := map[int]string{}
		for _, n := range nics {
			macAt[n.Ordinal] = strings.ToLower(n.MAC)
		}
		for i, n := range spec.Network {
			if len(n.Trunk) < 2 {
				continue
			}
			mac := strings.ToLower(n.Mac)
			if mac == "" {
				mac = macAt[i]
			}
			if _, recorded := guards[corrosion.NICGuardKey(vm.Name, mac)]; recorded && mac != "" {
				continue // created on this release: its VLANs are the network's to allow
			}
			for _, v := range n.Trunk {
				add[n.Name] = append(add[n.Name], int(v))
			}
		}
	}
	nets := make([]string, 0, len(add))
	for n := range add {
		nets = append(nets, n)
	}
	sort.Strings(nets)
	changed := false
	for _, name := range nets {
		seen := map[int]bool{}
		for _, v := range recorded[name] {
			seen[v] = true
		}
		var fresh []int
		for _, v := range sortedVIDs(add[name]) {
			if !seen[v] {
				fresh = append(fresh, v)
			}
		}
		if len(fresh) == 0 {
			continue
		}
		nr, err := corrosion.GetNetwork(ctx, s.db, name)
		if err != nil {
			return false, err
		}
		if nr != nil {
			var def compose.NetworkDef
			_ = json.Unmarshal([]byte(nr.Config), &def)
			def.AllowedVLANs = sortedVIDs(append(def.AllowedVLANs, fresh...))
			b, _ := json.Marshal(def)
			nr.Config = string(b)
			if err := corrosion.UpsertNetwork(ctx, s.db, *nr); err != nil {
				return false, err
			}
			s.auditAs(ctx, "litevirt", "network.update", name,
				"allowed-vlans += "+vidList(fresh)+" (trunks that predate NIC guards)", "ok")
		}
		recorded[name] = sortedVIDs(append(recorded[name], fresh...))
		changed = true
	}
	if changed || !have {
		b, _ := json.Marshal(recorded)
		if err := corrosion.SetClusterPolicy(ctx, s.db, corrosion.TrunkVLANsRecordedKey, string(b), "litevirt (upgrade)"); err != nil {
			return false, err
		}
	}
	return final, nil
}

// RecordExistingTrunkVLANsLoop runs recordExistingTrunkVLANs until a pass
// made with the release latched.
func (s *Server) RecordExistingTrunkVLANsLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		done, err := s.recordExistingTrunkVLANs(ctx)
		if err != nil {
			slog.Warn("firewall: could not record the trunk VLANs in use at upgrade", "error", err)
		}
		if done {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
