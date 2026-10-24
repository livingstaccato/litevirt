package grpcapi

// What a network keeps from its NICs, set after create (re-review R2-I1, m4):
// its router and reserved addresses (no guest NIC may claim them) and the
// trunk VLANs a NIC on the `trunk:` feature may carry on it. And the one-time
// recording, at upgrade, of the trunks a cluster already had into those lists.

import (
	"context"
	"encoding/json"
	"errors"
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
		return s.setFlatBridgeVLANs(ctx, req)
	}
	if err := s.RequirePerm(ctx, networkRBACPathFor(nr.Project, nr.Name), "network.update", "operator"); err != nil {
		s.audit(ctx, "network.update", nr.Name, "guard config", "denied")
		return nil, status.Errorf(codes.PermissionDenied, "setting %s's gateway, reserved addresses or trunk VLANs needs network.update on it", nr.Name)
	}
	// Moving access-VLAN VMs onto bridges that do not filter VLANs puts
	// them on those bridges' untagged segments: a cluster-wide isolation
	// decision, the admin's alone, whoever owns the network.
	if req.GetSetAllowUnfilteredAccessVlanMoves() {
		if err := RequireRole(ctx, "admin"); err != nil {
			s.audit(ctx, auditUnfilteredAccessVLANMoves, nr.Name, onOff(req.GetAllowUnfilteredAccessVlanMoves()), "denied")
			return nil, status.Errorf(codes.PermissionDenied,
				"letting %s's access-VLAN VMs move onto bridges that do not filter VLANs requires the admin role", nr.Name)
		}
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
		vids, err := requestVIDs(req.GetAllowedVlans())
		if err != nil {
			return nil, err
		}
		def.AllowedVLANs = vids
	}
	wasUnfiltered := def.AllowUnfilteredAccessVLANMoves
	if req.GetSetAllowUnfilteredAccessVlanMoves() {
		def.AllowUnfilteredAccessVLANMoves = req.GetAllowUnfilteredAccessVlanMoves()
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
	if req.GetSetAllowUnfilteredAccessVlanMoves() {
		s.audit(ctx, auditUnfilteredAccessVLANMoves, nr.Name,
			corrosion.AuditChange(onOff(wasUnfiltered), onOff(def.AllowUnfilteredAccessVLANMoves)), "ok")
	}
	s.reconcileLocal(ctx)
	return networkRecordToInfo(nr), nil
}

// auditUnfilteredAccessVLANMoves is the audit action of a change to a
// network's allow_unfiltered_access_vlan_moves.
const auditUnfilteredAccessVLANMoves = "network.access_vlan_unfiltered_moves"

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func requestVIDs(in []int32) ([]int, error) {
	var out []int
	for _, v := range in {
		if v < 1 || v > 4094 {
			return nil, status.Errorf(codes.InvalidArgument, "VLAN %d is outside 1-4094", v)
		}
		out = append(out, int(v))
	}
	return sortedVIDs(out), nil
}

// setFlatBridgeVLANs sets the trunk VLANs a flat bridge — a network name
// with no network row, whose NICs attach to a bridge of that name — allows
// (re-review R4-I1). Only that list can be set on one: it has no subnet to
// keep addresses from. It has no project, so it needs network.update at the
// cluster root. Audited as network.update.
func (s *Server) setFlatBridgeVLANs(ctx context.Context, req *pb.SetNetworkGuardConfigRequest) (*pb.NetworkInfo, error) {
	name := req.GetName()
	if req.GetSetAllowUnfilteredAccessVlanMoves() {
		return nil, status.Errorf(codes.InvalidArgument,
			"network %q has no network row (a flat bridge), which cannot hold --allow-unfiltered-access-vlan-moves: "+
				"create the network (`lv network create`) to set it", name)
	}
	if req.GetSetGateway() || req.GetSetReservedAddresses() || !req.GetSetAllowedVlans() {
		return nil, status.Errorf(codes.InvalidArgument,
			"network %q has no network row (a flat bridge): only --allowed-vlans can be set on it", name)
	}
	if strings.ContainsAny(name, "/ \t\n") || len(name) > 64 {
		return nil, status.Errorf(codes.InvalidArgument, "%q is not a bridge name", name)
	}
	if err := s.RequirePerm(ctx, "/", "network.update", "operator"); err != nil {
		s.audit(ctx, "network.update", name, "flat bridge allowed-vlans", "denied")
		return nil, status.Errorf(codes.PermissionDenied,
			"%s has no network row (a flat bridge, which no project owns): setting its trunk VLANs needs network.update at the cluster root", name)
	}
	vids, err := requestVIDs(req.GetAllowedVlans())
	if err != nil {
		return nil, err
	}
	var before []int
	_, err = s.casVLANs(ctx, "", []string{corrosion.FlatBridgeVLANsKey}, callerUsername(ctx), func(st *vlanState) (bool, []string, error) {
		m := st.maps[corrosion.FlatBridgeVLANsKey]
		before = m[name]
		m[name] = vids
		return false, []string{corrosion.FlatBridgeVLANsKey}, nil
	})
	if err != nil {
		s.audit(ctx, "network.update", name, "flat bridge allowed-vlans: "+err.Error(), "error")
		if errors.Is(err, corrosion.ErrClusterPolicyGateClosed) {
			return nil, status.Errorf(codes.FailedPrecondition, "set the trunk VLANs of flat bridge %s: %v", name, err)
		}
		return nil, status.Errorf(codes.Internal, "set the trunk VLANs of flat bridge %s: %v", name, err)
	}
	s.audit(ctx, "network.update", name, corrosion.AuditChange("{flat-bridge allowed-vlans=["+vidList(before)+"]}",
		"{flat-bridge allowed-vlans=["+vidList(vids)+"]}"), "ok")
	s.reconcileLocal(ctx)
	return &pb.NetworkInfo{Name: name, Type: "bridge"}, nil
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

// vlanState is one read of a network row and some VLAN policy keys, for a
// read-modify-write (casVLANs).
type vlanState struct {
	// row is the network's live row, nil when it has none (a flat bridge);
	// def is its config.
	row *corrosion.NetworkRecord
	def compose.NetworkDef
	// maps holds each key's name → VIDs map (empty when the key is unset).
	maps map[string]map[string][]int
}

// trunkVLANWriteHook runs between a read-modify-write's read and its write
// (tests).
var trunkVLANWriteHook func()

// SetTrunkVLANWriteHookForTests sets trunkVLANWriteHook; the returned func
// restores it.
func SetTrunkVLANWriteHookForTests(fn func()) func() {
	old := trunkVLANWriteHook
	trunkVLANWriteHook = fn
	return func() { trunkVLANWriteHook = old }
}

// casAttempts bounds how often a read-modify-write is redone after a write
// to what it read landed between its read and its write.
const casAttempts = 5

// casVLANs reads network's row (none when network is "") and keys, lets
// mutate change them, and writes back what mutate says changed — the row
// when writeRow, and writeKeys — under compare-and-swap: only while the row
// and the keys are as read (re-review m6). A write that lands in between
// makes it read and mutate again. wrote reports a write.
func (s *Server) casVLANs(ctx context.Context, network string, keys []string, setBy string,
	mutate func(st *vlanState) (writeRow bool, writeKeys []string, err error)) (wrote bool, err error) {
	for attempt := 0; attempt < casAttempts; attempt++ {
		snap, err := corrosion.ReadVLANSnapshot(ctx, s.db, network, keys...)
		if err != nil {
			return false, err
		}
		st := &vlanState{row: snap.Row, maps: map[string]map[string][]int{}}
		if st.row != nil && st.row.Config != "" {
			if err := json.Unmarshal([]byte(st.row.Config), &st.def); err != nil {
				return false, fmt.Errorf("read network %q config: %w", network, err)
			}
		}
		for _, k := range keys {
			st.maps[k] = corrosion.DecodeVLANMap(snap.Keys[k].Value)
		}
		writeRow, writeKeys, err := mutate(st)
		if err != nil {
			return false, err
		}
		if !writeRow && len(writeKeys) == 0 {
			return false, nil
		}
		var row *corrosion.NetworkRecord
		if writeRow && st.row != nil {
			b, err := json.Marshal(st.def)
			if err != nil {
				return false, err
			}
			r := *st.row
			r.Config = string(b)
			row = &r
		}
		vals := map[string]string{}
		for _, k := range writeKeys {
			vals[k] = corrosion.EncodeVLANMap(st.maps[k])
		}
		if trunkVLANWriteHook != nil {
			trunkVLANWriteHook()
		}
		applied, err := corrosion.WriteNetworkVLANsCAS(ctx, s.db, snap, row, vals, setBy)
		if err != nil {
			return false, err
		}
		if applied {
			return true, nil
		}
	}
	return false, fmt.Errorf("network %q's trunk VLANs changed under each of %d attempts to update them", network, casAttempts)
}

// vidsMinus is a's VLANs that b lacks, sorted.
func vidsMinus(a, b []int) []int {
	in := map[int]bool{}
	for _, v := range b {
		in[v] = true
	}
	var out []int
	for _, v := range sortedVIDs(append([]int(nil), a...)) {
		if !in[v] {
			out = append(out, v)
		}
	}
	return out
}

// keepVLANs puts vids on def's allowed list as VLANs litevirt keeps there
// (compose.NetworkDef.KeptVLANs).
func keepVLANs(def *compose.NetworkDef, vids []int) {
	def.AllowedVLANs = sortedVIDs(append(def.AllowedVLANs, vids...))
	def.KeptVLANs = sortedVIDs(append(def.KeptVLANs, vids...))
}

// recordExistingTrunkVLANs records the VLANs of every trunk NIC that predates
// guards (it has no guard record) into its network's allowed list, so a trunk
// in use at upgrade keeps its VLANs (re-review R2-I1). The loader grants a
// trunk nothing else: lacking a record is not an allowance (R3-I1).
//
// It runs on every pass until the release has latched — an older build may
// create a trunk during the rollout, and that one keeps its VLANs too — and
// reports done after a pass made with the release latched that wrote
// nothing: from then on no trunk without a record appears but a re-create's,
// which carries at most the VLANs its incarnation had. What it has recorded is
// kept under corrosion.TrunkVLANsRecordedKey, per network name; a VLAN is
// recorded once. A flat bridge (no network row) has no list; the loader
// allows it what was recorded for it, and what an operator allows on it.
//
// Each network's row and the key are read and written together under
// compare-and-swap (re-review m6), and the VLANs a row took are marked as
// kept there (compose.NetworkDef.KeptVLANs). Every pass puts back on a row a
// recorded VLAN the row does not keep: one a write that never saw the
// recording took away under LWW, or one recorded while the name had no row
// (R4-I2). A kept VLAN missing from the allowed list is one an operator took
// off (`lv network set --allowed-vlans`), and it stays off.
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
	names := map[string]bool{}
	for n := range add {
		names[n] = true
	}
	for n := range recorded {
		names[n] = true
	}
	order := make([]string, 0, len(names))
	for n := range names {
		order = append(order, n)
	}
	sort.Strings(order)
	key := corrosion.TrunkVLANsRecordedKey
	wrote := false
	for _, name := range order {
		var putBack []int
		w, err := s.casVLANs(ctx, name, []string{key}, "litevirt (upgrade)", func(st *vlanState) (bool, []string, error) {
			rec := st.maps[key]
			var writeKeys []string
			if fresh := vidsMinus(add[name], rec[name]); len(fresh) > 0 {
				rec[name] = sortedVIDs(append(rec[name], fresh...))
				writeKeys = []string{key}
			}
			putBack = nil
			if st.row != nil {
				putBack = vidsMinus(rec[name], st.def.KeptVLANs)
				keepVLANs(&st.def, putBack)
			}
			return len(putBack) > 0, writeKeys, nil
		})
		if err != nil {
			return false, err
		}
		if w && len(putBack) > 0 {
			s.auditAs(ctx, "litevirt", "network.update", name,
				"allowed-vlans += "+vidList(putBack)+" (trunks that predate NIC guards)", "ok")
		}
		wrote = wrote || w
	}
	if !have && !wrote {
		// The first pass, with nothing to record: say it ran.
		if err := corrosion.SetClusterPolicy(ctx, s.db, key, corrosion.EncodeVLANMap(recorded), "litevirt (upgrade)"); err != nil {
			return false, err
		}
		wrote = true
	}
	return final && !wrote, nil
}

// carryFlatBridgeVLANs is what a network row created under name takes over
// from the flat bridge of that name (re-review R4-I2): the VLANs recorded for
// the bridge's trunks at upgrade and those an operator allows on it. They go
// on its allowed list as kept VLANs.
func (s *Server) carryFlatBridgeVLANs(ctx context.Context, name string) ([]int, error) {
	recorded, _, err := corrosion.TrunkVLANsRecorded(ctx, s.db)
	if err != nil {
		return nil, err
	}
	flat, err := corrosion.FlatBridgeVLANs(ctx, s.db)
	if err != nil {
		return nil, err
	}
	return sortedVIDs(append(append([]int(nil), recorded[name]...), flat[name]...)), nil
}

// keepTrunkVLANs merges into def, about to be written verbatim as network
// name's row (a create, a re-deploy, a peer's provisioning), the trunk VLANs
// litevirt keeps on it (re-review R4-I2, m6): for a row that exists, the
// VLANs it keeps and an operator has not taken off its list; for a row that
// does not, those of the flat bridge it takes over (carryFlatBridgeVLANs).
// It returns the VLANs a new row took over, for the caller to audit once the
// row is written.
func (s *Server) keepTrunkVLANs(ctx context.Context, name string, def *compose.NetworkDef) (carried []int, err error) {
	cur, err := corrosion.GetNetwork(ctx, s.db, name)
	if err != nil {
		return nil, err
	}
	if cur != nil {
		var old compose.NetworkDef
		if cur.Config != "" {
			_ = json.Unmarshal([]byte(cur.Config), &old)
		}
		var still []int
		for _, v := range old.KeptVLANs {
			for _, a := range old.AllowedVLANs {
				if a == v {
					still = append(still, v)
				}
			}
		}
		def.AllowedVLANs = sortedVIDs(append(def.AllowedVLANs, still...))
		def.KeptVLANs = sortedVIDs(append(def.KeptVLANs, old.KeptVLANs...))
		// Set only by `lv network set` (admin), never from a definition:
		// a re-deploy keeps it.
		def.AllowUnfilteredAccessVLANMoves = old.AllowUnfilteredAccessVLANMoves
		return nil, nil
	}
	carried, err = s.carryFlatBridgeVLANs(ctx, name)
	if err != nil {
		return nil, err
	}
	carried = vidsMinus(carried, def.AllowedVLANs)
	keepVLANs(def, carried)
	return carried, nil
}

// auditCarriedVLANs audits the VLANs a new network row took over from the
// flat bridge of its name.
func (s *Server) auditCarriedVLANs(ctx context.Context, name string, carried []int) {
	if len(carried) > 0 {
		s.auditAs(ctx, "litevirt", "network.update", name,
			"allowed-vlans += "+vidList(carried)+" (taken over from the flat bridge "+name+")", "ok")
	}
}

// carryRetargetVLANs adds to rt.To's allowed list, before a legacy stack NIC
// moves onto it from the flat bridge rt.From (nic_retarget.go), the NIC's
// trunk VLANs recorded under rt.From (re-review R4-I2): the trunk keeps what
// it carried. Only for a NIC with no guard record — one that predates guards,
// which is the case the move exists for. Audited.
func (s *Server) carryRetargetVLANs(ctx context.Context, vmName, uuid, mac string, trunk []int32, rt compose.NICRetarget) error {
	if len(trunk) < 2 {
		return nil
	}
	if rec, err := corrosion.GetNICGuard(ctx, s.db, vmName, mac); err != nil {
		return err
	} else if rec != nil && (rec.VMUUID == "" || uuid == "" || rec.VMUUID == uuid) {
		return nil
	}
	key := corrosion.TrunkVLANsRecordedKey
	var carried []int
	w, err := s.casVLANs(ctx, rt.To, []string{key}, "litevirt (upgrade)", func(st *vlanState) (bool, []string, error) {
		if st.row == nil {
			return false, nil, fmt.Errorf("network %q does not exist", rt.To)
		}
		rec := st.maps[key]
		var mine []int
		for _, v := range trunk {
			for _, r := range rec[rt.From] {
				if int(v) == r {
					mine = append(mine, r)
				}
			}
		}
		carried = vidsMinus(mine, st.def.AllowedVLANs)
		var writeKeys []string
		if fresh := vidsMinus(mine, rec[rt.To]); len(fresh) > 0 {
			rec[rt.To] = sortedVIDs(append(rec[rt.To], fresh...))
			writeKeys = []string{key}
		}
		writeRow := len(vidsMinus(mine, st.def.KeptVLANs)) > 0 || len(carried) > 0
		keepVLANs(&st.def, mine)
		return writeRow, writeKeys, nil
	})
	if err != nil {
		return fmt.Errorf("carry %s's trunk VLANs from %s to %s: %w", vmName, rt.From, rt.To, err)
	}
	if w && len(carried) > 0 {
		s.auditAs(ctx, "litevirt", "network.update", rt.To,
			"allowed-vlans += "+vidList(carried)+" (trunk of "+vmName+", moved from the flat bridge "+rt.From+")", "ok")
	}
	return nil
}

// RecordExistingTrunkVLANsLoop runs recordExistingTrunkVLANs until a pass
// made with the release latched.
func (s *Server) RecordExistingTrunkVLANsLoop(ctx context.Context, every time.Duration) {
	if every <= 0 {
		every = 30 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	s.recordExistingTrunkVLANsLoop(ctx, t.C)
}

// recordExistingTrunkVLANsLoop is RecordExistingTrunkVLANsLoop with its
// ticks handed in: a pass now, then one per tick, until a pass reports done
// or ctx ends.
func (s *Server) recordExistingTrunkVLANsLoop(ctx context.Context, tick <-chan time.Time) {
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
		case <-tick:
		}
	}
}
