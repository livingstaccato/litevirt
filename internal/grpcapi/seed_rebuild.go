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

// rebuildSeedNetworkConfig rewrites vm's seed on this host after a hot attach
// (added: the attached NIC's MAC) or detach changed its NICs, so the seed
// lists the NICs the VM has (cloudinit.SeedNetworkConfig) and asks cloud-init
// to apply it again on boot (cloudinit.SeedVendorData).
//
//   - Only the VM's own seed is rewritten (cloudinit.OwnSeed: a VM with
//     cloud-init, and a seed stamped for it, or unstamped and attached as the
//     cdrom of the VM's domain here), and only its network-config and
//     vendor-data: its meta-data — the instance-id — and user-data are kept
//     byte for byte, so the guest is never a new instance, and an unstamped
//     one is stamped. Each NIC keeps the guest name that seed gives it.
//   - Any other seed at the path is left untouched — never rebuilt from,
//     stamped, nor written again live under the running guest — and
//     reported; the VM's next start writes its own, or none for a VM
//     without cloud-init.
//   - Where the VM's NICs cannot be told from its spec
//     (cloudinit.ErrNICsAmbiguous), the seed is left exactly as it is and the
//     reason reported.
//   - An active domain (running or paused) holds the seed it was started with
//     open, so its cdrom is reloaded (an eject and an insert of the same file)
//     and the guest's next read sees the new seed. A reload that fails is a
//     seed.reload_failed event naming `lv restart`, which starts the domain
//     again on the new seed.
//
// A VM with no seed here gets none. Best effort: the attach or detach has
// already happened; what fails is reported as a VM event naming the remedy.
// The work outlives the request.
func (s *Server) rebuildSeedNetworkConfig(ctx context.Context, vm *corrosion.VMRecord, added string) {
	ctx = context.WithoutCancel(ctx)
	iso, err := lv.SafeCloudInitISOPath(s.dataDir, vm.Name)
	if err != nil {
		return
	}
	failed := func(cause error) {
		detail := fmt.Sprintf("the seed at %s on %s keeps its previous network-config, so a reboot of the guest does not reflect this change: %v; the next NIC attach or detach of this VM tries again", iso, s.hostName, cause)
		slog.Warn("seed rebuild failed", "vm", vm.Name, "seed", iso, "error", cause)
		s.recordVMEvent(ctx, vm.Name, "seed.rebuild_failed", "error", detail)
	}
	uuid := cloudinit.SpecUUID(vm.Spec)
	var spec pb.VMSpec
	specErr := json.Unmarshal([]byte(vm.Spec), &spec)
	cur, own, err := cloudinit.OwnSeed(iso, s.seedClaim(vm, &spec))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		failed(err)
		return
	case specErr != nil:
		failed(fmt.Errorf("parse the VM's spec: %w", specErr))
		return
	case !own:
		detail := fmt.Sprintf("the seed at %s on %s is not proven this VM's (not stamped for it, and not the cdrom of its domain here; a VM of the same name may have left it); it is left as it is, and not changed under the running guest; the VM's next start on %s writes its own, or none for a VM without cloud-init; or remove the file", iso, s.hostName, s.hostName)
		slog.Warn("seed rebuild: not this VM's seed; left alone", "vm", vm.Name, "seed", iso)
		s.recordVMEventSeverity(ctx, vm.Name, "seed.not_rebuilt", "ok", "warning", detail)
		return
	}
	stamp := func() {
		if cloudinit.SeedIsFor(iso, uuid) {
			return
		}
		if err := cloudinit.StampSeed(iso, uuid); err != nil {
			slog.Warn("seed rebuild: could not stamp the seed with its VM", "vm", vm.Name, "error", err)
		}
	}
	var adds []string
	if added != "" {
		adds = []string{added}
	}
	nc, err := cloudinit.SeedNetworkConfig(ctx, s.db, vm.Name, &spec, cloudinit.PriorFrom(cur.NetworkConfig, adds...))
	switch {
	case errors.Is(err, cloudinit.ErrNICsAmbiguous):
		stamp()
		detail := fmt.Sprintf("the seed at %s on %s keeps its network-config and vendor-data as they are: %v (the spec of a VM created before it recorded NIC MACs); configure the changed NIC in the guest", iso, s.hostName, err)
		slog.Warn("seed rebuild: NICs ambiguous; seed left as it is", "vm", vm.Name, "error", err)
		s.recordVMEventSeverity(ctx, vm.Name, "seed.not_rebuilt", "ok", "warning", detail)
		return
	case err != nil:
		failed(err)
		return
	}
	changed, err := cloudinit.RebuildISO(iso, nc, cloudinit.SeedVendorData(&spec, nc))
	if err != nil {
		failed(err)
		return
	}
	stamp()
	if !changed {
		return
	}
	slog.Info("seed rebuilt for the VM's NICs", "vm", vm.Name, "seed", iso)

	active, err := s.virt.DomainIsActive(vm.Name)
	if err != nil || !active {
		return
	}
	if err := s.virt.ReloadCDROMMedia(vm.Name, iso); err != nil {
		detail := fmt.Sprintf("the seed was rebuilt for the VM's NICs, but the running guest still reads the one it was started with: %v; run `lv restart %s` to start it on the new seed", err, vm.Name)
		slog.Warn("seed rebuild: reload the seed cdrom", "vm", vm.Name, "seed", iso, "error", err)
		s.recordVMEvent(ctx, vm.Name, "seed.reload_failed", "error", detail)
	}
}

// seedClaim is what this host knows of vm for cloudinit.OwnSeed: its spec
// (spec, parsed from vm.Spec) and its domain definition here, read-only. A
// definition that cannot be read attaches nothing.
func (s *Server) seedClaim(vm *corrosion.VMRecord, spec *pb.VMSpec) cloudinit.SeedClaim {
	return cloudinit.SeedClaim{VMName: vm.Name, UUID: cloudinit.SpecUUID(vm.Spec),
		CloudInit: cloudinit.SpecHasCloudInit(spec), DomainXML: func() string {
			x, err := s.virt.DumpXMLInactive(vm.Name)
			if err != nil {
				return ""
			}
			return x
		}}
}
