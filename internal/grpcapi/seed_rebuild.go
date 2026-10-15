package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"

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
//   - Only a seed stamped for this VM (cloudinit.SeedIsFor) is rewritten, and
//     only its network-config and vendor-data: its meta-data — the
//     instance-id — and user-data are kept byte for byte, so the guest is not a
//     new instance. Each NIC keeps the guest name that seed gives it.
//   - A seed at the path that is not stamped for this VM (a deleted VM of the
//     name left it, or an earlier release wrote it) is never rewritten from.
//     For a VM with cloud-init it is written again from the VM's own spec, as
//     a start writes it; for one without, it is left alone and reported.
//   - Where the VM's NICs cannot be told from its spec
//     (cloudinit.ErrNICsAmbiguous), the seed is left exactly as it is and the
//     reason reported: a seed without network-config would boot on cloud-init's
//     fallback.
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
	if _, err := os.Lstat(iso); err != nil {
		return
	}
	failed := func(cause error) {
		detail := fmt.Sprintf("the seed at %s on %s keeps its previous network-config, so a reboot of the guest does not reflect this change: %v; the next NIC attach or detach of this VM tries again", iso, s.hostName, cause)
		slog.Warn("seed rebuild failed", "vm", vm.Name, "seed", iso, "error", cause)
		s.recordVMEvent(ctx, vm.Name, "seed.rebuild_failed", "error", detail)
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(vm.Spec), &spec); err != nil {
		failed(fmt.Errorf("parse the VM's spec: %w", err))
		return
	}
	owned := cloudinit.SeedIsFor(iso, cloudinit.SpecUUID(vm.Spec))
	if !owned && spec.Image == "" && spec.CloudInit == nil {
		detail := fmt.Sprintf("the seed at %s on %s was not written for this VM (a VM of the same name, or an earlier release, left it); it is left as it is, and this VM, which has no cloud-init, does not use it; remove it on %s", iso, s.hostName, s.hostName)
		slog.Warn("seed rebuild: not this VM's seed; left alone", "vm", vm.Name, "seed", iso)
		s.recordVMEventSeverity(ctx, vm.Name, "seed.not_rebuilt", "ok", "warning", detail)
		return
	}

	// The guest names of the NICs, from the seed being replaced. A seed that is
	// not proven this VM's names nothing it does not know by MAC.
	var prior *cloudinit.Prior
	var adds []string
	if added != "" {
		adds = []string{added}
	}
	cur, readErr := cloudinit.ReadSeed(iso)
	switch {
	case readErr == nil:
		prior = cloudinit.PriorFrom(cur.NetworkConfig, adds...)
	case owned:
		failed(readErr)
		return
	}

	nc, err := cloudinit.SeedNetworkConfig(ctx, s.db, vm.Name, &spec, prior)
	switch {
	case errors.Is(err, cloudinit.ErrNICsAmbiguous) && owned:
		detail := fmt.Sprintf("the seed at %s on %s keeps its network-config and vendor-data as they are: %v (the spec of a VM created before it recorded NIC MACs); configure the changed NIC in the guest", iso, s.hostName, err)
		slog.Warn("seed rebuild: NICs ambiguous; seed left as it is", "vm", vm.Name, "error", err)
		s.recordVMEventSeverity(ctx, vm.Name, "seed.not_rebuilt", "ok", "warning", detail)
		return
	case errors.Is(err, cloudinit.ErrNICsAmbiguous):
		// Written again from the spec with no network-config, as a start
		// writes it, and said so.
		s.recordVMEventSeverity(ctx, vm.Name, "seed.not_rebuilt", "ok", "warning", fmt.Sprintf(
			"the seed at %s on %s is written again with no network-config: %v (the spec of a VM created before it recorded NIC MACs); configure the VM's NICs in the guest", iso, s.hostName, err))
		nc = ""
	case err != nil:
		failed(err)
		return
	}
	vd := cloudinit.SeedVendorData(&spec, nc)

	if owned {
		changed, err := cloudinit.RebuildISO(iso, nc, vd)
		if err != nil {
			failed(err)
			return
		}
		if !changed {
			return
		}
	} else {
		userData := ""
		if spec.CloudInit != nil {
			userData = spec.CloudInit.Userdata
		}
		if userData == "" {
			userData = "#cloud-config\n{}\n"
		}
		if err := cloudinit.GenerateISO(cloudinit.Config{
			InstanceID: vm.Name, LocalHostname: vm.Name, UserData: userData, NetworkConfig: nc, VendorData: vd,
		}, iso); err != nil {
			failed(err)
			return
		}
		if err := cloudinit.StampSeed(iso, cloudinit.SpecUUID(vm.Spec)); err != nil {
			slog.Warn("seed rebuild: could not stamp the seed with its VM; a later start writes it again", "vm", vm.Name, "error", err)
		}
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
