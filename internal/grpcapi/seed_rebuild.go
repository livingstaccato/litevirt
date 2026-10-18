package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"slices"

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
	s.rebuildOwnSeed(ctx, vm, added, false)
}

// retryStaleSeedForStart tries again, before a start of vm on this host, the
// rebuild of its seed here that last failed (its stale mark,
// cloudinit.MarkSeedStale): an attach or detach whose rebuild failed, a
// migration here whose rewrite failed, or a start whose refresh failed. It
// does as rebuildSeedNetworkConfig does, the domain being inactive, and the
// mark goes when it succeeds. The start goes ahead whatever happens: a
// rebuild that fails again leaves the seed and its mark as they are and
// records the seed.rebuild_failed warning again. A seed not marked, not the
// VM's, or one the start's caller has already tried for this start
// (cloudinit.WithSeedTriedForStart) is left alone.
func (s *Server) retryStaleSeedForStart(ctx context.Context, vm *corrosion.VMRecord) {
	if cloudinit.SeedTriedForStart(ctx) {
		return
	}
	iso, err := lv.SafeCloudInitISOPath(s.dataDir, vm.Name)
	if err != nil || !cloudinit.SeedMarkedStale(iso) {
		return
	}
	// A start that finds the domain already active (running in libvirt)
	// boots nothing: its guest holds the seed it was started with open, so
	// the seed keeps its mark for the next start, or an attach or detach,
	// which reloads the cdrom.
	if active, aerr := s.virt.DomainIsActive(vm.Name); aerr == nil && active {
		return
	}
	s.rebuildOwnSeed(ctx, vm, "", true)
}

// writeMissingSeedForStart writes vm's seed again before a start of it on
// this host when its domain here boots from the seed (a CD-ROM at the VM's
// seed path) and the file is gone: a live move's commit removes the source's
// seed, and a VM returned to that host afterwards (`lv doctor firmware-move
// --accept-source`, or a cold move from it, which sends no seed it does not
// have) would otherwise not start. It is written from the VM's spec and NIC
// rows as a migration target's is (ensureCloudInitRequest), with the VM's
// name as its instance-id, so the guest is not a new instance on it. Never a
// refusal: a seed that cannot be written is a seed.rebuild_failed warning,
// and the start goes on to libvirt, which names the missing file.
func (s *Server) writeMissingSeedForStart(ctx context.Context, vm *corrosion.VMRecord) {
	if s.virt == nil {
		return
	}
	iso, err := lv.SafeCloudInitISOPath(s.dataDir, vm.Name)
	if err != nil {
		return
	}
	if _, err := os.Lstat(iso); !errors.Is(err, fs.ErrNotExist) {
		return
	}
	if active, aerr := s.virt.DomainIsActive(vm.Name); aerr != nil || active {
		return
	}
	domXML, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return
	}
	files, err := domainCDROMFiles(domXML)
	if err != nil || !slices.Contains(files, iso) {
		return
	}
	req := s.ensureCloudInitRequest(ctx, vm)
	if req == nil {
		err = errors.New("its spec or its network-config cannot be read")
	} else {
		err = writeVMSeed(vm, req, iso)
	}
	if err != nil {
		detail := fmt.Sprintf("the VM's domain on %s boots from its seed at %s, which is missing, and it could not be written again: %v; the start goes on, and libvirt refuses it for the missing file; the next start on %s tries again", s.hostName, iso, err, s.hostName)
		slog.Warn("seed missing before a start, and not written", "vm", vm.Name, "seed", iso, "error", err)
		s.recordVMEventSeverity(context.WithoutCancel(ctx), vm.Name, "seed.rebuild_failed", "error", "warning", detail)
		return
	}
	slog.Info("seed missing before a start: written again from the VM's spec", "vm", vm.Name, "seed", iso)
}

// seedStartRebuildRaced, set only by tests, runs in a start's rebuild between
// the derivation of the network-config and the rewrite.
var seedStartRebuildRaced func()

// rebuildOwnSeed is rebuildSeedNetworkConfig, after an attach or detach, or,
// forStart, before a start of the domain (retryStaleSeedForStart): a seed not
// the VM's is then left alone unreported, as a start of it always has, and
// the domain is not running, so there is no cdrom to reload.
func (s *Server) rebuildOwnSeed(ctx context.Context, vm *corrosion.VMRecord, added string, forStart bool) {
	ctx = context.WithoutCancel(ctx)
	iso, err := lv.SafeCloudInitISOPath(s.dataDir, vm.Name)
	if err != nil {
		return
	}
	failed := func(cause error) {
		if merr := cloudinit.MarkSeedStale(iso); merr != nil {
			slog.Warn("seed rebuild: could not mark the seed stale", "vm", vm.Name, "seed", iso, "error", merr)
		}
		if forStart {
			detail := fmt.Sprintf("the VM's seed at %s on %s, which an earlier rebuild here failed for, could not be brought up to date with its NICs before this start: %v; the VM starts on it as it is, so a NIC attached or detached since the seed was written may lose its configuration in the guest at this boot; the next start or NIC attach or detach of the VM on %s tries again", iso, s.hostName, cause, s.hostName)
			slog.Warn("seed rebuild before a start failed", "vm", vm.Name, "seed", iso, "error", cause)
			s.recordVMEventSeverity(ctx, vm.Name, "seed.rebuild_failed", "error", "warning", detail)
			return
		}
		detail := fmt.Sprintf("the seed at %s on %s keeps its previous network-config, so a reboot of the guest does not reflect this change: %v; the next start or NIC attach or detach of the VM on %s tries again", iso, s.hostName, cause, s.hostName)
		slog.Warn("seed rebuild failed", "vm", vm.Name, "seed", iso, "error", cause)
		s.recordVMEvent(ctx, vm.Name, "seed.rebuild_failed", "error", detail)
	}
	uuid := cloudinit.SpecUUID(vm.Spec)
	var spec pb.VMSpec
	specErr := json.Unmarshal([]byte(vm.Spec), &spec)
	cur, own, why, err := cloudinit.OwnSeedWhy(iso, s.seedClaim(vm, &spec))
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return
	case err != nil:
		failed(err)
		return
	case specErr != nil:
		failed(fmt.Errorf("parse the VM's spec: %w", specErr))
		return
	case !own && forStart:
		return
	case !own:
		detail := fmt.Sprintf("the seed at %s on %s is not proven this VM's: %s (a VM of the same name may have left it); it is left as it is, and not changed under the running guest; the VM's next start on %s writes its own, or none for a VM without cloud-init; or, with the VM stopped, remove the file and its .owner file", iso, s.hostName, why, s.hostName)
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
	// A seed an earlier rebuild here failed for may not list a NIC the VM
	// has: its names are read as possibly stale.
	prior := cloudinit.PriorFrom(cur.NetworkConfig, adds...)
	prior.Stale = cloudinit.SeedMarkedStale(iso)
	nc, err := cloudinit.SeedNetworkConfig(ctx, s.db, vm.Name, &spec, prior)
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
	if forStart && seedStartRebuildRaced != nil {
		seedStartRebuildRaced()
	}
	changed, err := cloudinit.RebuildISO(iso, nc, cloudinit.SeedVendorData(&spec, nc))
	if err != nil {
		failed(err)
		return
	}
	stamp()
	if forStart {
		// A start holds no VM lock on every path (a health restart or a
		// restore autostart holds none, and the lock is not reentrant, so
		// the hook cannot take it under startVMLocked): an attach or detach
		// can commit while this rebuild runs, and this rewrite can land
		// after its own. Derived again, a NIC set that moved keeps the seed
		// marked, so the next start or attach or detach rewrites it.
		if again, aerr := cloudinit.SeedNetworkConfig(ctx, s.db, vm.Name, &spec, prior); aerr != nil || again != nc {
			if merr := cloudinit.MarkSeedStale(iso); merr != nil {
				slog.Warn("seed rebuild before a start: could not mark the seed stale", "vm", vm.Name, "seed", iso, "error", merr)
			}
		}
	}
	if !changed || forStart {
		if changed {
			slog.Info("seed rebuilt for the VM's NICs before its start", "vm", vm.Name, "seed", iso)
		}
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
		CloudInit: cloudinit.SpecHasCloudInit(spec), UserData: cloudinit.SpecUserData(spec), DomainXML: func() string {
			x, err := s.virt.DumpXMLInactive(vm.Name)
			if err != nil {
				return ""
			}
			return x
		}}
}
