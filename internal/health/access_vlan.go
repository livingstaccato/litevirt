package health

import (
	"context"
	"encoding/json"
	"strings"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// An access-port NIC (network[].trunk with exactly one VLAN) needs a Linux
// bridge that filters VLANs on the host that starts its VM; every start there
// is refused otherwise (grpcapi.accessVLANStartPreflight). Each host raises
// bridge_vlan_filtering_off (evaluator access_vlan, subject
// host/<bridge>@<host>) for each of its bridges that is a Linux bridge with
// VLAN filtering off while some VM of the cluster has an access-port NIC on a
// network using it (grpcapi.ReconcileAccessVLANBridges), so the hosts a
// failover could not start such a VM on are named before one needs to, and
// failover placement passes them over while another host qualifies
// (AccessVLANUnfitHosts).
const (
	AccessVLANEvaluator        = "access_vlan"
	CondBridgeVLANFilteringOff = "bridge_vlan_filtering_off"
)

// AccessVLANNetworks indexes nets by name, for AccessVLANBridges.
func AccessVLANNetworks(nets []corrosion.NetworkRecord) map[string]corrosion.NetworkRecord {
	out := make(map[string]corrosion.NetworkRecord, len(nets))
	for _, n := range nets {
		out[n.Name] = n
	}
	return out
}

// NetworkBridge is the host device a NIC on network name attaches to, from
// nets, as grpcapi's resolveBridge answers it: the flat bridge's name for a
// network with no record, or one whose config cannot be read.
func NetworkBridge(nets map[string]corrosion.NetworkRecord, name string) string {
	rec, ok := nets[name]
	if !ok {
		return network.FlatBridgeName(name)
	}
	var def compose.NetworkDef
	if err := json.Unmarshal([]byte(rec.Config), &def); err != nil {
		return network.FlatBridgeName(name)
	}
	def.Type = rec.Type
	return network.BridgeName(name, def)
}

// AccessVLANBridges is the Linux bridge of each of spec's access-port NICs
// (trunk: with one VLAN), deduplicated, with the NIC's VLAN. A NIC on a
// direct (macvtap) network has no bridge, and is left out.
func AccessVLANBridges(spec *pb.VMSpec, nets map[string]corrosion.NetworkRecord) map[string]int {
	var out map[string]int
	for _, n := range spec.GetNetwork() {
		if len(n.GetTrunk()) != 1 {
			continue
		}
		br := NetworkBridge(nets, n.GetName())
		if br == "" || strings.HasPrefix(br, "direct:") {
			continue
		}
		if out == nil {
			out = map[string]int{}
		}
		if _, seen := out[br]; !seen {
			out[br] = int(n.GetTrunk()[0])
		}
	}
	return out
}

// AccessVLANSubject is the condition subject of bridge on host.
func AccessVLANSubject(bridge, host string) string { return bridge + "@" + host }

// SplitAccessVLANSubject is AccessVLANSubject's inverse.
func SplitAccessVLANSubject(subject string) (bridge, host string, ok bool) {
	i := strings.LastIndex(subject, "@")
	if i <= 0 || i == len(subject)-1 {
		return "", "", false
	}
	return subject[:i], subject[i+1:], true
}

// AccessVLANUnfitHosts reads, from the replicated conditions, the bridges each
// host has reported unable to carry an access-port NIC: host → bridge → true.
// A condition still observed counts as well as a confirmed one.
func AccessVLANUnfitHosts(ctx context.Context, db *corrosion.Client) (map[string]map[string]bool, error) {
	conds, deleted, err := corrosion.ListHealthConditionsByCode(ctx, db, AccessVLANEvaluator, CondBridgeVLANFilteringOff)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for i, c := range conds {
		if deleted[i] || c.Lifecycle == corrosion.ConditionResolved || c.SubjectKind != "host" {
			continue
		}
		br, host, ok := SplitAccessVLANSubject(c.SubjectID)
		if !ok {
			continue
		}
		if out[host] == nil {
			out[host] = map[string]bool{}
		}
		out[host][br] = true
	}
	return out, nil
}

// AccessVLANHostsUnfitFor is, for a VM with spec, each host whose bridge cannot
// carry one of its access-port NICs (unfit, from AccessVLANUnfitHosts), with
// the reason: failover passes these over while another host qualifies, and a
// migration or drain does not move the VM onto one.
func AccessVLANHostsUnfitFor(spec *pb.VMSpec, nets map[string]corrosion.NetworkRecord, unfit map[string]map[string]bool) map[string]string {
	if len(unfit) == 0 {
		return nil
	}
	var out map[string]string
	for br := range AccessVLANBridges(spec, nets) {
		for host, bridges := range unfit {
			if !bridges[br] {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[host] = "bridge " + br + " cannot carry an access-VLAN NIC (" + CondBridgeVLANFilteringOff + ")"
		}
	}
	return out
}
