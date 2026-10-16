package grpcapi

// Eligibility of a live firmware move (spec §3.2): which running Secure Boot /
// vTPM VM may move live, decided in three stages on the source. Stage A reads
// only this host and the target's row, before any call to the target; stage B
// judges the target's PrepareLiveFirmwareTarget answer; stage C judges the
// route once EnsureDisks has answered. Every refusal is FailedPrecondition and
// names the cold move, which stays available for every VM refused here: a
// refused live move changes nothing, so the VM's TPM and NVRAM state stay where
// they are.

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// liveFirmwareCode reads a host's firmware code: what is installed, and what a
// running domain's processes run (lv.FirmwareCodeProbe).
type liveFirmwareCode interface {
	Installed(ctx context.Context) (lv.InstalledFirmwareCode, error)
	RunningFirmwareCode(ctx context.Context, liveXML string) (lv.FirmwareRuntime, error)
}

// liveFirmwareHost is what a live firmware move reads of this host.
type liveFirmwareHost struct {
	// enabled is migration.live_firmware.
	enabled bool
	// guests is the live D-9 check (daemon.CheckLibvirtGuests): nil when
	// libvirt-guests neither saves nor restores guests. Unset refuses.
	guests func(ctx context.Context) error
	// code replaces the production probe (tests).
	code liveFirmwareCode
}

// SetLiveFirmware wires migration.live_firmware and the live libvirt-guests
// check (D-9) a live firmware move re-reads on each attempt. A host that never
// calls it refuses every live firmware move.
func (s *Server) SetLiveFirmware(enabled bool, guests func(ctx context.Context) error) {
	s.liveFW.enabled, s.liveFW.guests = enabled, guests
}

// setLiveFirmwareCodeForTest replaces this host's firmware code probe.
func (s *Server) setLiveFirmwareCodeForTest(c liveFirmwareCode) { s.liveFW.code = c }

// liveFirmwareCode is this host's firmware code probe: the injected one, or
// the production probe of this host's firmware store and OVMF files, asking
// libvirt for its version. A backend that cannot say its version leaves the
// probe without one, and every read refuses.
func (s *Server) liveFirmwareCode() liveFirmwareCode {
	if s.liveFW.code != nil {
		return s.liveFW.code
	}
	var version func() (uint64, error)
	if v, ok := s.virt.(interface{ LibvirtVersion() (uint64, error) }); ok {
		version = v.LibvirtVersion
	}
	return lv.NewFirmwareCodeProbe(s.fw(), s.firmware, version)
}

// pbFirmwareRuntime is rt as the RPCs carry it, with this host's live firmware
// fingerprint (liveFirmwareFingerprint) in place of the probe's OVMF one.
func (s *Server) pbFirmwareRuntime(rt lv.FirmwareRuntime) (*pb.FirmwareRuntime, error) {
	fp, err := s.liveFirmwareFingerprint()
	if err != nil {
		return nil, fmt.Errorf("firmware fingerprint: %w", err)
	}
	return &pb.FirmwareRuntime{
		Libvirt: rt.Libvirt, Qemu: rt.QEMU, Swtpm: rt.Swtpm, Libtpms: rt.Libtpms,
		OvmfFingerprint: fp, LiveFirmwareEnabled: s.liveFW.enabled,
	}, nil
}

// installedFirmwareRuntime is this host's INSTALLED firmware runtime in the
// form a live firmware move compares: what a target answers Prepare with
// (dst_runtime), since its incoming QEMU and swtpm are exec'd from it.
func (s *Server) installedFirmwareRuntime(ctx context.Context) (*pb.FirmwareRuntime, error) {
	in, err := s.liveFirmwareCode().Installed(ctx)
	if err != nil {
		return nil, err
	}
	return s.pbFirmwareRuntime(in.Runtime)
}

// liveFirmwareApplicability is which firmware state the VM carries, derived
// from this host's row (spec §4): tpm, and uefi = an NVRAM file (firmware uefi
// or empty) with Secure Boot or a TPM.
func liveFirmwareApplicability(spec firmwareSpec) *pb.FirmwareApplicability {
	return &pb.FirmwareApplicability{Tpm: spec.Tpm, Uefi: fwmig.UEFI(spec.hasNvram(), spec.SecureBoot, spec.Tpm)}
}

// liveFirmwareMove is what stage A judges.
type liveFirmwareMove struct {
	vm     *corrosion.VMRecord
	target *corrosion.HostRecord
	// withStorage is the request's --with-storage.
	withStorage bool
	// disks are the VM's disk rows.
	disks []corrosion.DiskRecord
}

// liveFirmwareEligible is what stage A found, for Prepare and stages B and C.
type liveFirmwareEligible struct {
	// uuid is the VM's domain uuid (its spec's, equal to the live domain's).
	uuid string
	// runtime is the code the source domain's processes run (§3.5).
	runtime *pb.FirmwareRuntime
	// applicability is the source's {tpm, uefi}.
	applicability *pb.FirmwareApplicability
	// storage: the move copies the host-local disks (every disk is one).
	storage bool
}

// liveFirmwareRefusal is a refusal of the live move of vm to target: the
// reason, then the cold move that remains.
func liveFirmwareRefusal(vm, target, format string, args ...any) error {
	return status.Errorf(codes.FailedPrecondition,
		"live migration of Secure Boot / vTPM VM %q refused: %s — migrate it cold instead: `lv stop %s`, then `lv migrate %s %s --cold`",
		vm, fmt.Sprintf(format, args...), vm, vm, target)
}

// liveDomainFirmware is what the running definition says of the VM's firmware.
type liveDomainFirmware struct {
	uuid   string
	loader bool
	nvram  string // the NVRAM file's path, "" without one
	tpm    bool
}

func parseLiveDomainFirmware(domXML string) (liveDomainFirmware, error) {
	var d struct {
		UUID string `xml:"uuid"`
		OS   struct {
			Loader *struct{} `xml:"loader"`
			NVRAM  *struct {
				Path string `xml:",chardata"`
			} `xml:"nvram"`
		} `xml:"os"`
		Devices struct {
			TPM []struct{} `xml:"tpm"`
		} `xml:"devices"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		return liveDomainFirmware{}, err
	}
	out := liveDomainFirmware{uuid: strings.ToLower(strings.TrimSpace(d.UUID)), loader: d.OS.Loader != nil, tpm: len(d.Devices.TPM) > 0}
	if d.OS.NVRAM != nil {
		out.nvram = strings.TrimSpace(d.OS.NVRAM.Path)
	}
	return out, nil
}

// liveFirmwareStageA is stage A (spec §3.2 items 1–7): source-local, before
// any call to the target, and writing nothing. Each item is read live; the
// first that fails is the refusal.
func (s *Server) liveFirmwareStageA(ctx context.Context, m liveFirmwareMove) (*liveFirmwareEligible, error) {
	vm, target := m.vm.Name, m.target.Name
	spec := parseFirmwareSpec(m.vm.Spec)
	refuse := func(format string, args ...any) error { return liveFirmwareRefusal(vm, target, format, args...) }

	// Item 1: the setting, the installed floors and D-9, all on this host.
	if !s.liveFW.enabled {
		return nil, refuse("migration.live_firmware is off on %s", s.hostName)
	}
	code := s.liveFirmwareCode()
	installed, err := code.Installed(ctx)
	if err != nil {
		return nil, refuse("the installed firmware code on %s cannot be read: %v", s.hostName, err)
	}
	if err := lv.FirmwareFloorsMet(installed.Runtime); err != nil {
		return nil, refuse("%s: %v", s.hostName, err)
	}
	if s.liveFW.guests == nil {
		return nil, refuse("%s cannot check libvirt-guests (D-9)", s.hostName)
	}
	if err := s.liveFW.guests(ctx); err != nil {
		return nil, refuse("%s: %v; a guest libvirt-guests saves or restores runs outside litevirt's firmware move guard", s.hostName, err)
	}

	// Item 2: the source domain runs (not paused), its running definition is
	// this VM's, it carries the firmware the row declares, and its processes
	// run the installed code.
	if s.virt == nil {
		return nil, refuse("libvirt is not connected on %s", s.hostName)
	}
	st, err := s.virt.DomainStateReason(vm)
	if err != nil {
		return nil, refuse("the state of its domain on %s cannot be read: %v", s.hostName, err)
	}
	if st.State != "running" {
		if st.Reason == "paused" {
			return nil, refuse("its domain on %s is paused (by partition pause or an operator); a paused guest is not moved live, "+
				"since the target would resume it", s.hostName)
		}
		return nil, refuse("its domain on %s is not running (state %s, reason %s)", s.hostName, st.State, st.Reason)
	}
	if spec.UUID == "" {
		return nil, refuse("its spec carries no uuid, so its firmware state cannot be bound to it")
	}
	liveXML, err := s.virt.DumpXML(vm)
	if err != nil {
		return nil, refuse("its running definition on %s cannot be read: %v", s.hostName, err)
	}
	dom, err := parseLiveDomainFirmware(liveXML)
	if err != nil {
		return nil, refuse("its running definition on %s cannot be parsed: %v", s.hostName, err)
	}
	if !strings.EqualFold(dom.uuid, spec.UUID) {
		return nil, refuse("the running domain %s has uuid %q, but the VM's spec names %q", vm, dom.uuid, spec.UUID)
	}
	app := liveFirmwareApplicability(spec)
	if dom.tpm != app.Tpm {
		return nil, refuse("the VM's spec says tpm=%t, but its running definition says tpm=%t", app.Tpm, dom.tpm)
	}
	if app.Uefi {
		if !dom.loader || dom.nvram == "" {
			return nil, refuse("the VM's spec says it keeps UEFI vars, but its running definition has no loader or NVRAM")
		}
		if want := s.fw().NvramPath(vm); filepath.Clean(dom.nvram) != filepath.Clean(want) {
			return nil, refuse("its running definition keeps its NVRAM at %s, not at %s where this host's firmware store holds it", dom.nvram, want)
		}
	} else if dom.nvram != "" {
		return nil, refuse("the VM's spec says it keeps no UEFI vars, but its running definition has an NVRAM at %s", dom.nvram)
	}
	running, err := code.RunningFirmwareCode(ctx, liveXML)
	if err != nil {
		return nil, refuse("%v", err)
	}
	if running != installed.Runtime {
		return nil, refuse("its running code %+v is not %s's installed code %+v", running, s.hostName, installed.Runtime)
	}

	// Item 3: the running TPM keeps its state across the move.
	if app.Tpm && !lv.TPMPersistentStateYes(liveXML) {
		return nil, refuse("its running TPM is not persistent_state='yes'; redefine it first: `lv stop %s`, `lv start %s`", vm, vm)
	}

	// Item 4: no snapshot of the VM carries a firmware sidecar.
	sidecars, err := s.snapshotFirmwareSidecars(vm)
	if err != nil {
		return nil, refuse("its snapshot firmware sidecars cannot be listed: %v", err)
	}
	if len(sidecars) > 0 {
		return nil, refuse("snapshot firmware sidecar(s) %s are kept for it; remove those snapshots first (`lv snapshot rm %s <name>`)",
			strings.Join(sidecars, ", "), vm)
	}

	// Item 5: no firmware move record names the VM on this host. One that
	// cannot be read counts as present.
	recs, err := fwmig.New(s.fw().DataDir).Lookup(vm, spec.UUID)
	if err != nil {
		return nil, refuse("a firmware move record on %s cannot be read: %v", s.hostName, err)
	}
	if len(recs) > 0 {
		r := recs[0]
		return nil, refuse("a firmware move record names it on %s (attempt %s, %s, peer %s); resolve that move first",
			s.hostName, r.Attempt, r.State, r.Peer)
	}

	// Item 6: the target's labels.
	if app.Tpm && m.target.Labels[corrosion.LabelTPMCapable] != "true" {
		return nil, refuse("target host %s is not vTPM-capable (%s)", target, corrosion.LabelTPMCapable)
	}
	if spec.SecureBoot && m.target.Labels[corrosion.LabelSecureBootCapable] != "true" {
		return nil, refuse("target host %s is not Secure-Boot-capable (%s)", target, corrosion.LabelSecureBootCapable)
	}
	if m.target.Labels[corrosion.LabelFwLiveMigrate] != "true" {
		return nil, refuse("target host %s does not advertise %s=true", target, corrosion.LabelFwLiveMigrate)
	}

	// Item 7: the route, as far as the disks and this host's TLS tell it now.
	storage, err := s.liveFirmwareRouteStageA(vm, target, m.withStorage, m.disks)
	if err != nil {
		return nil, err
	}

	rt, err := s.pbFirmwareRuntime(running)
	if err != nil {
		return nil, refuse("%v", err)
	}
	return &liveFirmwareEligible{uuid: strings.ToLower(spec.UUID), runtime: rt, applicability: app, storage: storage}, nil
}

// liveFirmwareRouteStageA is stage A item 7 (spec §3.3): a storage copy only
// when every disk is host-local and this host can encrypt it; a memory-only
// move only when no disk is host-local. It reports whether the move copies
// storage.
func (s *Server) liveFirmwareRouteStageA(vm, target string, withStorage bool, disks []corrosion.DiskRecord) (bool, error) {
	var local, shared []string
	for _, d := range disks {
		if isHostLocalDisk(d) {
			local = append(local, d.DiskName)
		} else {
			shared = append(shared, d.DiskName)
		}
	}
	if len(local) == 0 {
		return false, nil
	}
	if !withStorage {
		return false, liveFirmwareRefusal(vm, target, "it has host-local disk(s) %s; a live move copies them only with --with-storage",
			strings.Join(local, ", "))
	}
	if len(shared) > 0 {
		return false, liveFirmwareRefusal(vm, target, "a storage copy with shared disks beside host-local ones is not supported "+
			"(host-local %s, shared %s); move the host-local disks to shared storage, or migrate cold",
			strings.Join(local, ", "), strings.Join(shared, ", "))
	}
	if !s.migrationTLSReady() {
		return false, liveFirmwareRefusal(vm, target, "%s has no migration-TLS credentials (`lv host install-migration-tls`), and a storage copy "+
			"carries the TPM state; migration.allow_unencrypted_storage does not apply to it", s.hostName)
	}
	return true, nil
}

// snapshotFirmwareSidecars lists the firmware sidecar files kept for vm's
// snapshots (lv.SnapshotFirmwareBundlePath): any file in its snapfw directory.
func (s *Server) snapshotFirmwareSidecars(vm string) ([]string, error) {
	dir := filepath.Dir(lv.SnapshotFirmwareBundlePath(s.dataDir, vm, "x"))
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		out = append(out, filepath.Join(dir, e.Name()))
	}
	sort.Strings(out)
	return out, nil
}

// firmwareLiveUnimplementedText is the refusal when the target's build has no
// live firmware migration: today's cold-only text, and why.
func firmwareLiveUnimplementedText(vm, target string) string {
	return fmt.Sprintf("Secure Boot / vTPM VM %q must be migrated cold (--cold), and stopped: live firmware carry is not yet a validated path — "+
		"stop it (`lv stop %s`), then `lv migrate %s %s --cold`; target %s runs a build without live firmware migration",
		vm, vm, vm, target, target)
}

// liveFirmwareStageB is stage B (spec §3.2 items 8–10): the target's answer
// to PrepareLiveFirmwareTarget. A target without the RPC is refused with the
// cold-only text; any other Prepare error is returned as the target gave it.
func liveFirmwareStageB(vm, target string, a *liveFirmwareEligible, resp *pb.PrepareLiveFirmwareTargetResponse, callErr error) error {
	// Item 8.
	if callErr != nil {
		if status.Code(callErr) == codes.Unimplemented {
			return status.Error(codes.FailedPrecondition, firmwareLiveUnimplementedText(vm, target))
		}
		return callErr
	}
	if resp == nil || resp.GetDstRuntime() == nil || resp.GetDstApplicability() == nil {
		return liveFirmwareRefusal(vm, target, "target %s answered Prepare without its runtime or the VM's applicability", target)
	}
	// Item 9.
	if err := compareFirmwareRuntimes(a.runtime, resp.GetDstRuntime()); err != nil {
		return liveFirmwareRefusal(vm, target, "target %s: %v", target, err)
	}
	// Item 10.
	src, dst := a.applicability, resp.GetDstApplicability()
	if src.GetTpm() != dst.GetTpm() || src.GetUefi() != dst.GetUefi() {
		return liveFirmwareRefusal(vm, target, "the VM's firmware differs between the hosts' rows: source tpm=%t uefi=%t, target %s tpm=%t uefi=%t",
			src.GetTpm(), src.GetUefi(), target, dst.GetTpm(), dst.GetUefi())
	}
	return nil
}

// firmwareRuntimeKey is a FirmwareRuntime as testedFirmwarePairs keys it.
type firmwareRuntimeKey struct {
	libvirt, qemu, swtpm, libtpms, fingerprint string
}

func runtimeKey(r *pb.FirmwareRuntime) firmwareRuntimeKey {
	return firmwareRuntimeKey{r.GetLibvirt(), r.GetQemu(), r.GetSwtpm(), r.GetLibtpms(), r.GetOvmfFingerprint()}
}

// testedFirmwarePairs are the unequal (source, target) runtimes a live
// firmware move has been proven across. Compiled in; empty in v1 (spec §3.2
// item 9, K-4).
var testedFirmwarePairs = map[[2]firmwareRuntimeKey]bool{}

// compareFirmwareRuntimes is nil when the source's running runtime and the
// target's installed one are equal, or a tested pair. Otherwise it names the
// first differing field and both values: libvirt, qemu, swtpm, libtpms, then
// the firmware layout, then the OVMF content. Every field must be set: an
// empty one is never equal to anything.
func compareFirmwareRuntimes(src, dst *pb.FirmwareRuntime) error {
	if !dst.GetLiveFirmwareEnabled() {
		return errors.New("migration.live_firmware is off there")
	}
	sl, so, sok := splitLiveFirmwareFingerprint(src.GetOvmfFingerprint())
	dl, do, dok := splitLiveFirmwareFingerprint(dst.GetOvmfFingerprint())
	fields := []struct{ what, s, d string }{
		{"libvirt", src.GetLibvirt(), dst.GetLibvirt()},
		{"qemu", src.GetQemu(), dst.GetQemu()},
		{"swtpm", src.GetSwtpm(), dst.GetSwtpm()},
		{"libtpms", src.GetLibtpms(), dst.GetLibtpms()},
	}
	for _, f := range fields {
		if f.s == "" || f.d == "" {
			return fmt.Errorf("%s is not known (source %q, target %q)", f.what, f.s, f.d)
		}
	}
	if !sok || !dok {
		return fmt.Errorf("the firmware fingerprint is not readable (source %q, target %q)", src.GetOvmfFingerprint(), dst.GetOvmfFingerprint())
	}
	fields = append(fields,
		struct{ what, s, d string }{"firmware layout (dataDir and OVMF paths)", sl, dl},
		struct{ what, s, d string }{"ovmf_fingerprint (OVMF content)", so, do})
	for _, f := range fields {
		if f.s != f.d {
			if testedFirmwarePairs[[2]firmwareRuntimeKey{runtimeKey(src), runtimeKey(dst)}] {
				return nil
			}
			return fmt.Errorf("%s differs: source runs %s, target has %s; a live firmware move needs equal firmware code on both hosts", f.what, f.s, f.d)
		}
	}
	return nil
}

// liveFirmwareStageC is stage C (spec §3.2 item 11): the route resolved after
// EnsureDisks (chooseLiveFirmwareRoute's answer) and both hosts' TLS, against
// liveFirmwareRoutes (§3.3). It returns the route the source marker records.
func liveFirmwareStageC(vm string, target corrosion.HostRecord, storage bool, r migrationRoute, bothTLS bool) (fwmig.Route, error) {
	if storage {
		if !bothTLS {
			return "", liveFirmwareRefusal(vm, target.Name, "the storage copy would not be encrypted (a host has no migration-TLS credentials, "+
				"`lv host install-migration-tls`), and it carries the TPM state")
		}
		if r.addr != target.Address || r.direct || r.onNetwork {
			return "", liveFirmwareRefusal(vm, target.Name, "a storage copy goes only to the target's cluster address %s, not %s", target.Address, r.addr)
		}
		return fwmig.RouteStorageCopy, nil
	}
	if !r.direct {
		if r.addr != target.Address || r.onNetwork {
			return "", liveFirmwareRefusal(vm, target.Name, "a tunnelled move goes only to the target's cluster address %s, not %s", target.Address, r.addr)
		}
		return fwmig.RouteTunnelled, nil
	}
	if !liveFirmwareMignetRoute {
		return "", liveFirmwareRefusal(vm, target.Name, "a memory-only move over migration.network is not yet allowed for firmware VMs (lab e2e E-9)")
	}
	if !r.onNetwork || !bothTLS {
		return "", liveFirmwareRefusal(vm, target.Name, "a direct memory-only move needs the migration network and TLS on both hosts")
	}
	return fwmig.RouteMigrationNetwork, nil
}
