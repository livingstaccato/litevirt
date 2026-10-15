package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// rebuildSeedNetworkConfig rewrites the network-config and vendor-data of
// vm's seed on this host after a hot attach or detach changed its NICs, so
// the seed lists the NICs the VM has (cloudinit.SeedNetworkConfig) and asks
// cloud-init to apply it again on boot (cloudinit.SeedVendorData). The seed's
// meta-data — its instance-id — and user-data are kept byte for byte
// (cloudinit.RebuildISO), so the guest is not a new instance and first boot
// does not run again.
//
// A running domain holds the seed it was started with open, so its cdrom is
// reloaded (an eject and an insert of the same file) and the guest's next read
// sees the new seed. A reload that fails is logged and recorded as a
// seed.reload_failed event naming the remedy: `lv restart` starts the domain
// again, which opens the new seed.
//
// The seed is only rewritten where one exists: a VM with none here (no cloud
// image) gets none. Best effort: the attach or detach has already happened,
// and a seed that cannot be rebuilt keeps what it held, which is logged.
func (s *Server) rebuildSeedNetworkConfig(ctx context.Context, vm *corrosion.VMRecord, running bool) {
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
	changed, err := cloudinit.RebuildISO(iso, nc, cloudinit.SeedVendorData(&spec))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		slog.Warn("seed rebuild: the seed keeps its network-config", "vm", vm.Name, "seed", iso, "error", err)
		return
	case !changed:
		return
	}
	slog.Info("seed rebuilt for the VM's NICs", "vm", vm.Name, "seed", iso)
	if !running {
		return
	}
	if err := s.virt.ReloadCDROMMedia(vm.Name, iso); err != nil {
		detail := fmt.Sprintf("the seed was rebuilt for the VM's NICs, but the running guest still reads the one it was started with: %v; run `lv restart %s` to start it on the new seed", err, vm.Name)
		slog.Warn("seed rebuild: reload the seed cdrom", "vm", vm.Name, "seed", iso, "error", err)
		s.recordVMEvent(ctx, vm.Name, "seed.reload_failed", "error", detail)
	}
}
