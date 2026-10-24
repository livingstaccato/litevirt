package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/placement"
)

// USB passthrough (Proxmox "usbN" / "USB mappings").
//
// A VM names each USB device one of three ways:
//
//   - vendor:product — a raw device, matched by id on the host that runs it;
//   - bus-port — a raw device, by where it is plugged in on that host;
//   - mapping — a cluster-wide resource mapping whose rows say, per host,
//     which device (vendor:product or bus-port) stands in for it.
//
// A raw device exists on one host only, so it binds the VM there: placement,
// failover, drain and rebalance consider that host alone, and a create must pin
// it. A mapped device restricts the VM to the hosts the mapping lists, and a
// cold migration re-resolves it on the target. Live migration is refused while
// any USB device is attached (as on Proxmox VE, which migrates a VM with USB
// passthrough offline only, and only when every device is mapped).
//
// Hotplug is not offered: device attach/detach is journaled
// (enforcement.operation_protocol) and has no un-journaled path, and USB has
// no journaled kind yet. The device list changes through `lv update --usb …`,
// a redefine-class change (stopped, or --restart-if-needed).

// validateUSBDeviceShapes checks each device names exactly one well-formed
// selector. It needs no host and no database.
func validateUSBDeviceShapes(devs []*pb.USBDeviceSpec) error {
	for i, d := range devs {
		if d == nil {
			return status.Errorf(codes.InvalidArgument, "usb device %d is empty", i)
		}
		byID := d.Vendor != "" || d.Product != ""
		forms := 0
		if byID {
			forms++
		}
		if d.BusPort != "" {
			forms++
		}
		if d.Mapping != "" {
			forms++
		}
		if forms != 1 {
			return status.Errorf(codes.InvalidArgument,
				"usb device %d: name it by exactly one of vendor:product, bus-port or mapping", i)
		}
		switch {
		case byID:
			_, vok := lv.NormalizeUSBID(d.Vendor)
			_, pok := lv.NormalizeUSBID(d.Product)
			if !vok || !pok {
				return status.Errorf(codes.InvalidArgument,
					"usb device %d: vendor %q and product %q must be 4 hex digits each", i, d.Vendor, d.Product)
			}
		case d.BusPort != "":
			if !lv.ValidUSBBusPort(d.BusPort) {
				return status.Errorf(codes.InvalidArgument,
					"usb device %d: bus-port %q is malformed (want <bus>-<port>[.<port>...], e.g. 1-2 or 3-1.4)", i, d.BusPort)
			}
		}
	}
	return nil
}

// normalizeUSBDevices returns devs with ids lower-cased and stripped of 0x, so
// a stored spec compares and renders one way.
func normalizeUSBDevices(devs []*pb.USBDeviceSpec) []*pb.USBDeviceSpec {
	out := make([]*pb.USBDeviceSpec, 0, len(devs))
	for _, d := range devs {
		n := &pb.USBDeviceSpec{BusPort: d.BusPort, Mapping: d.Mapping}
		if d.Vendor != "" || d.Product != "" {
			n.Vendor, _ = lv.NormalizeUSBID(d.Vendor)
			n.Product, _ = lv.NormalizeUSBID(d.Product)
		}
		out = append(out, n)
	}
	return out
}

// validateUSBMappings checks every mapping a VM's USB devices name exists and
// hands out USB devices — a PCI mapping would resolve to a PCI address no USB
// hostdev can carry.
func (s *Server) validateUSBMappings(ctx context.Context, devs []*pb.USBDeviceSpec) error {
	seen := map[string]bool{}
	for _, d := range devs {
		if d.GetMapping() == "" || seen[d.Mapping] {
			continue
		}
		seen[d.Mapping] = true
		m, err := corrosion.GetResourceMapping(ctx, s.db, d.Mapping)
		if err != nil {
			return status.Errorf(codes.Internal, "read resource mapping %q: %v", d.Mapping, err)
		}
		if m == nil {
			return status.Errorf(codes.NotFound, "no resource mapping %q (lv mapping ls shows them)", d.Mapping)
		}
		if kind := m.MappingKind(); kind != corrosion.MappingKindUSB {
			if kind == corrosion.MappingKindNone {
				return status.Errorf(codes.FailedPrecondition, "resource mapping %q has no devices yet (lv mapping add-device %s usb:<vendor>:<product> --host <host>)", d.Mapping, d.Mapping)
			}
			return status.Errorf(codes.InvalidArgument, "resource mapping %q holds %s devices, not USB devices", d.Mapping, kind)
		}
	}
	return nil
}

// validateUSBForVM is the whole USB check a create or update runs: the shape,
// the mappings, and — for a raw device — the one host it binds the VM to.
// host is that host: the create's pin, or the host the VM lives on.
func (s *Server) validateUSBForVM(ctx context.Context, devs []*pb.USBDeviceSpec, host string) error {
	if err := validateUSBDeviceShapes(devs); err != nil {
		return err
	}
	if err := s.validateUSBMappings(ctx, devs); err != nil {
		return err
	}
	for _, d := range devs {
		if d.Mapping == "" && host == "" {
			return status.Error(codes.InvalidArgument,
				"a raw USB device (vendor:product or bus-port) is plugged into one host: pin the VM to it (--host), or name the device through a USB resource mapping")
		}
	}
	return nil
}

// resolveUSBHostdevs resolves a VM's USB devices to the hostdevs THIS host
// defines: a mapped device through the mapping's row for this host, a
// bus-port through this host's sysfs. Fails closed — a VM is never defined
// missing a device it asks for.
func (s *Server) resolveUSBHostdevs(ctx context.Context, spec *pb.VMSpec) ([]lv.USBHostdevConfig, error) {
	var out []lv.USBHostdevConfig
	for i, d := range spec.GetUsbDevices() {
		if d == nil {
			continue
		}
		ref := lv.USBDeviceRef{Vendor: d.Vendor, Product: d.Product, BusPort: d.BusPort}
		if d.Mapping != "" {
			addr, err := corrosion.ResolveMappingAddress(ctx, s.db, d.Mapping, s.hostName)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "resolve USB mapping %q on %s: %v", d.Mapping, s.hostName, err)
			}
			if addr == "" {
				return nil, status.Errorf(codes.FailedPrecondition,
					"USB mapping %q has no device on host %s", d.Mapping, s.hostName)
			}
			r, err := lv.ParseUSBMappingAddress(addr)
			if err != nil {
				return nil, status.Errorf(codes.FailedPrecondition, "USB mapping %q on %s: %v", d.Mapping, s.hostName, err)
			}
			ref = r
		}
		cfg, err := lv.ResolveUSBDevice(ref)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "usb device %d of %q on %s: %v", i, spec.Name, s.hostName, err)
		}
		out = append(out, cfg)
	}
	return out, nil
}

// usbNoHome stands in for the host of a raw USB device when none is known: no
// host is named that, so placement qualifies none.
const usbNoHome = "(no host)"

// applyUSBPlacement adds a VM's USB constraints to a placement request. home
// is the host a raw device binds it to (the create's pin, or the host it lives
// on); "" for a raw device means no host qualifies.
func applyUSBPlacement(req *placement.Request, spec *pb.VMSpec, home string) {
	mappings, raw := corrosion.USBMappingNames(spec)
	req.USBMappings = mappings
	if raw {
		req.USBHost = home
		if home == "" {
			// No host can be named: refuse every one rather than none.
			req.USBHost = usbNoHome
		}
	}
}

// refuseUSBMigration applies the USB rules to a migration of vm to target:
// live is refused while any USB device is attached, a raw device cannot leave
// its host, and a mapped one may go only where its mapping has a device.
func (s *Server) refuseUSBMigration(ctx context.Context, vm *corrosion.VMRecord, spec *pb.VMSpec, target string, cold bool) error {
	devs := spec.GetUsbDevices()
	if len(devs) == 0 {
		return nil
	}
	if !cold {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has USB passthrough devices; a USB device cannot be carried live — migrate it with --cold (mapped devices only), or remove them (`lv update %s --clear-usb`)",
			vm.Name, vm.Name)
	}
	mappings, raw := corrosion.USBMappingNames(spec)
	if raw {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q has a raw USB device, which is plugged into %s and no other host; name it through a USB resource mapping to migrate the VM",
			vm.Name, vm.HostName)
	}
	var missing []string
	for _, m := range mappings {
		hosts, err := corrosion.HostsForMapping(ctx, s.db, m)
		if err != nil {
			return status.Errorf(codes.Internal, "hosts for USB mapping %q: %v", m, err)
		}
		found := false
		for _, h := range hosts {
			if h == target {
				found = true
				break
			}
		}
		if !found {
			missing = append(missing, m)
		}
	}
	if len(missing) > 0 {
		return status.Errorf(codes.FailedPrecondition,
			"target host %q has no device under USB mapping(s) %s, which VM %q uses", target, strings.Join(missing, ", "), vm.Name)
	}
	return nil
}

// validateMemoryHotplugSpec checks a spec's hot-add band against the rules
// GenerateDomainXML renders by: a region above the boot memory, a whole number
// of 2 MiB blocks, and no balloon band beside it.
func validateMemoryHotplugSpec(spec *pb.VMSpec) error {
	max, base := spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib
	if max == 0 {
		return nil
	}
	switch {
	case max < 0:
		return status.Errorf(codes.InvalidArgument, "memory hot-add maximum %d MiB is negative", max)
	case max <= base:
		return status.Errorf(codes.InvalidArgument,
			"memory hot-add maximum %d MiB must be above the boot memory %d MiB", max, base)
	case (max-base)%2 != 0:
		return status.Errorf(codes.InvalidArgument,
			"memory hot-add maximum %d MiB minus the boot memory %d MiB must be a multiple of 2 MiB", max, base)
	case spec.MemoryMib < base || spec.MemoryMib > max:
		return status.Errorf(codes.InvalidArgument,
			"memory %d MiB is outside the hot-add band [%d, %d] MiB", spec.MemoryMib, base, max)
	case (spec.MemoryMib-base)%2 != 0:
		return status.Errorf(codes.InvalidArgument,
			"memory %d MiB must be the boot memory %d MiB plus a multiple of 2 MiB", spec.MemoryMib, base)
	case spec.MaxMemoryMib > spec.MemoryMib || spec.MinMemoryMib > 0:
		return status.Error(codes.InvalidArgument,
			"memory hot-add and a balloon band (--min-mem / --max-mem) cannot be combined")
	case spec.GetResources().GetHugepages():
		return status.Error(codes.InvalidArgument,
			"memory hot-add and hugepages cannot be combined (the 2 MiB hot-add block does not fit larger hugepages)")
	}
	return nil
}

// admitCreateUSBAndHotplug is CreateVM's check of the gated hardware fields:
// the capability gate, then each feature's own rules. It also sets the
// server-owned hot-add boot memory (the VM's memory at create).
func (s *Server) admitCreateUSBAndHotplug(ctx context.Context, spec *pb.VMSpec) error {
	spec.MemoryHotplugBaseMib = 0 // server-owned
	if len(spec.UsbDevices) == 0 && spec.MemoryHotplugMaxMib == 0 {
		return nil
	}
	// The entry node's fail-fast; the owner that writes the row takes the
	// feature's grant itself (createVM).
	if err := s.passthroughFeatureGate(ctx); err != nil {
		return err
	}
	if len(spec.UsbDevices) > 0 {
		if err := s.authorizeUSBDevices(ctx, spec.UsbDevices); err != nil {
			return err
		}
		pin := ""
		if spec.Placement != nil {
			pin = spec.Placement.Host
		}
		if err := s.validateUSBForVM(ctx, spec.UsbDevices, pin); err != nil {
			return err
		}
		spec.UsbDevices = normalizeUSBDevices(spec.UsbDevices)
	}
	if spec.MemoryHotplugMaxMib != 0 {
		spec.MemoryHotplugBaseMib = spec.MemoryMib
		if err := validateMemoryHotplugSpec(spec); err != nil {
			return err
		}
	}
	return nil
}

// usbSummary renders a VM's USB devices for an event or log line.
func usbSummary(devs []*pb.USBDeviceSpec) string {
	parts := make([]string, 0, len(devs))
	for _, d := range devs {
		switch {
		case d.Mapping != "":
			parts = append(parts, "mapping:"+d.Mapping)
		case d.BusPort != "":
			parts = append(parts, "port:"+d.BusPort)
		default:
			parts = append(parts, fmt.Sprintf("%s:%s", d.Vendor, d.Product))
		}
	}
	return strings.Join(parts, ",")
}

// parseSpecOrNil decodes a stored VM spec, or returns nil when there is none
// or it does not parse (the getters on a nil spec read as empty).
func parseSpecOrNil(raw string) *pb.VMSpec {
	if raw == "" {
		return nil
	}
	spec := &pb.VMSpec{}
	if json.Unmarshal([]byte(raw), spec) != nil {
		return nil
	}
	return spec
}

// applyUSBHotplugUpdate applies an UpdateVM's USB list and hot-add ceiling to
// spec (whose memory the request has already set) and checks the resulting
// hot-add band. Turning hot-add on records the boot memory as the VM's memory
// now; a stopped VM whose memory drops below its boot cell takes the new size
// as its boot cell (a redefine sets it afresh).
func applyUSBHotplugUpdate(req *pb.UpdateVMRequest, spec *pb.VMSpec) error {
	if req.SetUsbDevices {
		spec.UsbDevices = normalizeUSBDevices(req.UsbDevices)
	}
	if req.MemoryHotplugMaxMib != nil {
		max := *req.MemoryHotplugMaxMib
		switch {
		case max == 0:
			spec.MemoryHotplugBaseMib = 0
		case spec.MemoryHotplugMaxMib == 0:
			spec.MemoryHotplugBaseMib = spec.MemoryMib
		}
		spec.MemoryHotplugMaxMib = max
	}
	if spec.MemoryHotplugMaxMib > 0 && spec.MemoryMib < spec.MemoryHotplugBaseMib {
		spec.MemoryHotplugBaseMib = spec.MemoryMib
	}
	return validateMemoryHotplugSpec(spec)
}

// preflightUSBHotplugUpdate checks an UpdateVM's USB and hot-add changes
// against a copy of the stored spec, before the update stops anything: the
// capability gate for a setting that adds either, the USB devices (a raw one
// binds to host, where the VM lives), and the resulting hot-add band.
// Clearing either needs no gate — removing a field an old peer would drop
// loses nothing.
func (s *Server) preflightUSBHotplugUpdate(ctx context.Context, req *pb.UpdateVMRequest, stored *pb.VMSpec, host string) error {
	if !req.SetUsbDevices && req.MemoryHotplugMaxMib == nil {
		if stored.MemoryHotplugMaxMib > 0 && req.MemoryMib > 0 {
			// A memory change on a hot-add VM must stay inside its band.
			probe := proto.Clone(stored).(*pb.VMSpec)
			probe.MemoryMib = req.MemoryMib
			return applyUSBHotplugUpdate(req, probe)
		}
		return nil
	}
	if updateSetsPassthrough(req) {
		if err := s.passthroughFeatureGate(ctx); err != nil {
			return err
		}
	}
	if req.SetUsbDevices && len(req.UsbDevices) > 0 {
		if err := s.validateUSBForVM(ctx, req.UsbDevices, host); err != nil {
			return err
		}
	}
	probe := proto.Clone(stored).(*pb.VMSpec)
	if req.MemoryMib > 0 {
		probe.MemoryMib = req.MemoryMib
	}
	return applyUSBHotplugUpdate(req, probe)
}

// refreshUSBHostdevsForStart re-resolves a VM's USB devices on this host and
// rewrites them into its persistent definition before it starts. A device this
// host cannot resolve refuses the start: the guest never boots without a
// device it asks for, nor with whatever now holds a stale bus/device number.
func (s *Server) refreshUSBHostdevsForStart(ctx context.Context, vm *corrosion.VMRecord) error {
	spec := parseSpecOrNil(vm.Spec)
	if len(spec.GetUsbDevices()) == 0 || s.virt == nil {
		return nil
	}
	usb, err := s.resolveUSBHostdevs(ctx, spec)
	if err != nil {
		return err
	}
	cur, err := s.virt.DumpXMLInactive(vm.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read the definition of %q to refresh its USB devices: %v", vm.Name, err)
	}
	next, err := lv.ReplaceUSBHostdevs(cur, usb)
	if err != nil {
		return status.Errorf(codes.Internal, "refresh USB devices of %q: %v", vm.Name, err)
	}
	if next == cur {
		return nil
	}
	if err := s.virt.DefineDomain(next); err != nil {
		return status.Errorf(codes.Internal, "redefine %q with its USB devices: %v", vm.Name, err)
	}
	return nil
}

// rawUSBDenied is the refusal for a raw USB device without the admin role.
const rawUSBDenied = "a raw USB device (vendor:product or bus-port) hands one of the host's own devices to the guest, which needs the admin role; name it through a USB resource mapping you may use instead"

// authorizeUSBDevices is the caller's permission to pass these devices
// through, judged where the caller is real — the entry node, before any
// forward (a forwarded call runs as the peer, which must never be what
// grants it). A raw device is the host's own and needs the admin role, as on
// Proxmox VE (Sys.Modify on /). A mapped one needs resourcemap.use on
// /mappings/<name> (Proxmox Mapping.Use); with no role bindings, the admin
// role.
func (s *Server) authorizeUSBDevices(ctx context.Context, devs []*pb.USBDeviceSpec) error {
	seen := map[string]bool{}
	for _, d := range devs {
		if d == nil {
			continue
		}
		if d.Mapping == "" {
			if err := RequireRole(ctx, "admin"); err != nil {
				return status.Error(codes.PermissionDenied, rawUSBDenied)
			}
			continue
		}
		if seen[d.Mapping] {
			continue
		}
		seen[d.Mapping] = true
		if err := s.RequirePerm(ctx, mappingRBACPath(d.Mapping), "resourcemap.use", "admin"); err != nil {
			return status.Errorf(codes.PermissionDenied, "using resource mapping %q needs resourcemap.use on %s: %v",
				d.Mapping, mappingRBACPath(d.Mapping), status.Convert(err).Message())
		}
	}
	return nil
}

// mappingRBACPath is the permission path of one resource mapping.
func mappingRBACPath(name string) string { return "/mappings/" + name }

// admitRestoredUSBAndHotplug decides what a live restore's spec may carry of
// USB passthrough and memory hot-add. Only the cluster's own row (fromExisting)
// is server-side state that passed create's gates; it keeps them, judged again
// here as a create would judge them (the gate, the caller's permission, the
// devices on THIS host). A client-supplied or manifest spec grants neither:
// both are stripped — the VM restores with fixed memory and no USB device —
// and the strip is audited.
//
// When they are kept, the grant is the feature's, taken on this node (the one
// that writes the row): the row must be written with it (insertVMWithGrants).
func (s *Server) admitRestoredUSBAndHotplug(ctx context.Context, spec *pb.VMSpec, name string, fromExisting bool) (capabilities.FeatureGrant, error) {
	var none capabilities.FeatureGrant
	if len(spec.UsbDevices) == 0 && spec.MemoryHotplugMaxMib == 0 && spec.MemoryHotplugBaseMib == 0 {
		return none, nil
	}
	if !fromExisting {
		what := usbSummary(spec.UsbDevices)
		if spec.MemoryHotplugMaxMib != 0 {
			what = strings.TrimPrefix(what+fmt.Sprintf(",memory-hotplug-max=%d", spec.MemoryHotplugMaxMib), ",")
		}
		spec.UsbDevices = nil
		spec.MemoryHotplugMaxMib, spec.MemoryHotplugBaseMib = 0, 0
		s.audit(ctx, "vm.restore", name, "not carried from the restored spec (set them again with lv update): "+what, "ok")
		return none, nil
	}
	// The caller's permission and the devices first, so a refused restore
	// records no use; then the feature's grant, the last check before the row.
	if len(spec.UsbDevices) > 0 {
		if err := s.authorizeUSBDevices(ctx, spec.UsbDevices); err != nil {
			return none, err
		}
		if err := s.validateUSBForVM(ctx, spec.UsbDevices, s.hostName); err != nil {
			return none, err
		}
	}
	if err := validateMemoryHotplugSpec(spec); err != nil {
		return none, err
	}
	return s.passthroughGrant(ctx)
}
