package failover

import (
	"context"
	"encoding/json"
	"log/slog"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/placement"
)

// accessVLANView is what a recovery pass knows of the hosts whose bridge
// cannot carry an access-port NIC (bridge_vlan_filtering_off, raised by each
// host about itself): a VM with such a NIC is placed on another host while one
// qualifies. The target's start preflight refuses the start on such a host
// whatever placement chose, so this read only improves where a VM lands.
type accessVLANView struct {
	nets  map[string]corrosion.NetworkRecord
	unfit map[string]map[string]bool
}

// readAccessVLANView reads the view, or nil — no host passed over — when no
// host is reported or a read fails.
func (c *Coordinator) readAccessVLANView(ctx context.Context) *accessVLANView {
	unfit, err := health.AccessVLANUnfitHosts(ctx, c.db)
	if err != nil {
		slog.Warn("failover: cannot read which hosts' bridges do not filter VLANs; placing without it", "error", err)
		return nil
	}
	if len(unfit) == 0 {
		return nil
	}
	nets, err := corrosion.ListNetworks(ctx, c.db)
	if err != nil {
		slog.Warn("failover: cannot read the networks; placing without the hosts whose bridges do not filter VLANs", "error", err)
		return nil
	}
	return &accessVLANView{nets: health.AccessVLANNetworks(nets), unfit: unfit}
}

// avoid sets req.AvoidHosts to the hosts whose bridge cannot carry one of vm's
// access-port NICs.
func (v *accessVLANView) avoid(req *placement.Request, vm corrosion.VMRecord) {
	if v == nil || vm.Spec == "" {
		return
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(vm.Spec), spec) != nil {
		return
	}
	req.AvoidHosts = accessVLANAvoidHosts(spec, v.nets, v.unfit)
}

// accessVLANAvoidHosts is, for a VM with spec, each host whose bridge cannot
// carry one of its access-port NICs (unfit, from
// health.AccessVLANUnfitHosts), with the reason: placement passes these over
// while another host qualifies.
func accessVLANAvoidHosts(spec *pb.VMSpec, nets map[string]corrosion.NetworkRecord, unfit map[string]map[string]bool) map[string]string {
	if len(unfit) == 0 {
		return nil
	}
	var out map[string]string
	for br := range health.AccessVLANBridges(spec, nets) {
		for host, bridges := range unfit {
			if !bridges[br] {
				continue
			}
			if out == nil {
				out = map[string]string{}
			}
			out[host] = "bridge " + br + " does not filter VLANs (" + health.CondBridgeVLANFilteringOff + ")"
		}
	}
	return out
}
