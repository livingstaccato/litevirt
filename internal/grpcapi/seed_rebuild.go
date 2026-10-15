package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// rebuildSeedNetworkConfig rewrites the network-config of vm's seed on this
// host after a hot attach or detach changed its NICs, so the seed lists the
// NICs the VM has (cloudinit.SeedNetworkConfig). The seed's meta-data — its
// instance-id — and user-data are kept byte for byte (cloudinit.RebuildISO),
// so the guest is not a new instance and first boot does not run again.
//
// The seed is only rewritten where one exists: a VM with none here (no cloud
// image) gets none. Best effort: the attach or detach has already happened,
// and a seed that cannot be rebuilt keeps what it held, which is logged.
func (s *Server) rebuildSeedNetworkConfig(ctx context.Context, vm *corrosion.VMRecord) {
	iso, err := lv.SafeCloudInitISOPath(s.dataDir, vm.Name)
	if err != nil {
		return
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		slog.Warn("seed rebuild: parse spec; the seed keeps its network-config", "vm", vm.Name, "error", err)
		return
	}
	nc, err := cloudinit.SeedNetworkConfig(ctx, s.db, vm.Name, &spec)
	if err != nil {
		slog.Warn("seed rebuild: derive network-config; the seed keeps its network-config", "vm", vm.Name, "error", err)
		return
	}
	changed, err := cloudinit.RebuildISO(iso, nc)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		slog.Warn("seed rebuild: the seed keeps its network-config", "vm", vm.Name, "seed", iso, "error", err)
	case changed:
		slog.Info("seed rebuilt for the VM's NICs", "vm", vm.Name, "seed", iso)
	}
}
