package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A VM's PCI passthrough on a host it did not run on before (a failover).
//
// A concrete-address selector names a slot on the host it was recorded on.
// On any other host it is realized by a device of the KIND the old host's
// inventory records at that address (corrosion.PCIAddressIdentity), never by
// whatever sits at the same address here. Portable selectors (a type, a
// mapping, SR-IOV) resolve here as they always do.

// addressOnThisHost is the device on this host that realizes vmName's
// concrete address bdf, recorded on origin (intent deviceID): the device that
// already realizes it here, else one of its kind the VM owns here (a restart
// here keeps the device it has), else a free one; never one in exclude.
func (s *Server) addressOnThisHost(ctx context.Context, vmName, deviceID, origin, bdf string, exclude map[string]bool) (string, error) {
	ident, _, err := corrosion.PCIAddressIdentity(ctx, s.db, vmName, deviceID, origin, bdf)
	if err != nil {
		if errors.Is(err, corrosion.ErrPCIIdentityUnknown) {
			return "", status.Errorf(codes.FailedPrecondition, "PCI device %s of %s: %v", bdf, vmName, err)
		}
		return "", status.Errorf(codes.Internal, "read the identity of PCI device %s of %s: %v", bdf, vmName, err)
	}
	if ident.Host == s.hostName && !exclude[ident.Address] {
		return ident.Address, nil
	}
	devs, err := corrosion.ListPCIDevices(ctx, s.db, s.hostName, "")
	if err != nil {
		return "", status.Errorf(codes.Internal, "query devices: %v", err)
	}
	for _, owner := range []string{vmName, ""} {
		for _, d := range devs {
			if d.VMName == owner && !exclude[d.Address] && ident.Matches(d) {
				return d.Address, nil
			}
		}
	}
	// Say why each device of the kind here is not this one's.
	var taken []string
	for _, d := range devs {
		if !ident.Matches(d) {
			continue
		}
		switch {
		case exclude[d.Address]:
			taken = append(taken, fmt.Sprintf("%s is taken by another of %s's devices", d.Address, vmName))
		case d.VMName != "" && d.VMName != vmName:
			taken = append(taken, fmt.Sprintf("%s is owned by VM %s", d.Address, d.VMName))
		}
	}
	if len(taken) > 0 {
		return "", status.Errorf(codes.FailedPrecondition,
			"%s needs a free PCI device %s on host %s (it had one at %s on %s), and none is free: %s",
			vmName, ident.String(), s.hostName, bdf, origin, strings.Join(taken, "; "))
	}
	return "", status.Errorf(codes.FailedPrecondition,
		"%s needs a free PCI device %s on host %s (it had one at %s on %s) and there is none: the device at the same address here, if any, is not that device",
		vmName, ident.String(), s.hostName, bdf, origin)
}

// declaredDevicesHere is vm's PCI passthrough as device specs that resolve on
// this host: its intents (else its spec's devices), each concrete address
// recorded on another host replaced by the address of a device of its kind
// here. The replaced ones come first, so a type selector of the same kind
// does not take the device chosen for them. moved maps the intent of each
// replaced address that has one to the address it takes here.
func (s *Server) declaredDevicesHere(ctx context.Context, vm *corrosion.VMRecord, spec *pb.VMSpec, intents []corrosion.PCIIntentRecord) (specs []*pb.DeviceSpec, moved map[string]string, err error) {
	type selector struct {
		dev      *pb.DeviceSpec
		deviceID string
		origin   string
		known    bool // origin is the host the address was recorded on
	}
	var sels []selector
	if len(intents) > 0 {
		for _, in := range intents {
			if in.SelectorKind == "address" {
				addr := ""
				if in.ExclusiveKey != nil {
					addr = *in.ExclusiveKey
				}
				sels = append(sels, selector{dev: &pb.DeviceSpec{Address: addr}, deviceID: in.DeviceID, origin: in.HostName, known: in.HostName != ""})
				continue
			}
			d := &pb.DeviceSpec{}
			if err := protojson.Unmarshal([]byte(in.SelectorPayload), d); err != nil {
				return nil, nil, status.Errorf(codes.Internal, "decode selector payload for device %s: %v", in.DeviceID, err)
			}
			sels = append(sels, selector{dev: d})
		}
	} else {
		for _, d := range spec.GetDevices() {
			sels = append(sels, selector{dev: proto.Clone(d).(*pb.DeviceSpec)})
		}
	}

	exclude := map[string]bool{}
	moved = map[string]string{}
	var here, rest []*pb.DeviceSpec
	for _, sel := range sels {
		if kind, _ := corrosion.ClassifyPCISelector(sel.dev); kind != "address" {
			rest = append(rest, sel.dev)
			continue
		}
		origin := sel.origin
		if !sel.known {
			// Recorded without its host: the host that records the VM as
			// owning it. None does: a device this host's own (released when
			// the VM stopped here), as it always was.
			_, owner, err := corrosion.PCIAddressIdentity(ctx, s.db, vm.Name, "", "", sel.dev.Address)
			if err != nil && !errors.Is(err, corrosion.ErrPCIIdentityUnknown) {
				return nil, nil, status.Errorf(codes.Internal, "read the owner of PCI device %s of %s: %v", sel.dev.Address, vm.Name, err)
			}
			origin = owner
		}
		if origin == "" || origin == s.hostName {
			rest = append(rest, sel.dev)
			continue
		}
		addr, err := s.addressOnThisHost(ctx, vm.Name, sel.deviceID, origin, sel.dev.Address, exclude)
		if err != nil {
			return nil, nil, err
		}
		exclude[addr] = true
		here = append(here, &pb.DeviceSpec{Address: addr})
		if sel.deviceID != "" {
			moved[sel.deviceID] = addr
		}
	}
	return append(here, rest...), moved, nil
}

// PassthroughForRebuild is the reconciler's PCI passthrough hook
// (health/passthrough_rebuild.go): the devices a domain it rebuilds from vm's
// spec on this host passes through.
//
// Before hardware_v2 latches it claims and binds them here, as CreateVM does:
// the devices the VM already owns here, else a device for each of its
// selectors, a concrete address recorded on another host by a device of its
// kind. A VM this host has none for is refused (the reconciler does not start
// it), unless its spec opts in to running without them
// (corrosion.LabelFailoverWithoutDevices). After the latch the start
// preflight realizes the devices; the hook only decides whether an opted-in
// VM this host cannot give them to starts without them.
func (s *Server) PassthroughForRebuild(ctx context.Context, vm *corrosion.VMRecord) (health.PassthroughRebuild, error) {
	none := health.PassthroughRebuild{}
	if vm == nil || s.db == nil {
		return none, nil
	}
	spec := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			return none, status.Errorf(codes.InvalidArgument, "decode spec for %q: %v", vm.Name, err)
		}
	}
	optOut := corrosion.FailoverWithoutDevices(spec)
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, vm.Name)
	if err != nil {
		return none, status.Errorf(codes.Internal, "read PCI intents for %q: %v", vm.Name, err)
	}
	dropped := func(err error) health.PassthroughRebuild {
		why := fmt.Sprintf("%s=true, and this host has none for it: %s", corrosion.LabelFailoverWithoutDevices, status.Convert(err).Message())
		slog.Warn("pci: starting a VM without its passthrough devices, as its spec opts in to", "vm", vm.Name, "error", err)
		return health.PassthroughRebuild{Dropped: why}
	}

	if s.hardwareV2Latched(ctx) {
		if !optOut || len(intents) == 0 {
			return none, nil // the start preflight's (PrepareHardwareForStart)
		}
		var pure []corrosion.PCIIntentRecord
		for _, in := range intents {
			if in.SelectorKind != "sriov" {
				pure = append(pure, in)
			}
		}
		if _, rerr := s.resolveDeviceIntents(ctx, vm.Name, pure); rerr != nil && notRetryableHere(rerr) {
			return dropped(rerr), nil
		}
		return none, nil
	}

	if len(intents) == 0 && len(spec.GetDevices()) == 0 {
		return none, nil
	}
	// A domain rebuilt on the host that holds its devices: those.
	owned, tombstoned, err := corrosion.VMDeviceOwnership(ctx, s.db, s.hostName, vm.Name)
	if err != nil {
		return none, status.Errorf(codes.Internal, "read PCI ownership for %q: %v", vm.Name, err)
	}
	if len(tombstoned) > 0 && !optOut {
		return none, status.Errorf(codes.FailedPrecondition,
			"assigned PCI device(s) %v of %s have vanished from host %s", tombstoned, vm.Name, s.hostName)
	}
	if len(owned) > 0 {
		return health.PassthroughRebuild{Addresses: owned}, nil
	}
	specs, moved, err := s.declaredDevicesHere(ctx, vm, spec, intents)
	if err == nil {
		addrs, finish, aerr := s.allocateDevices(ctx, vm.Name, specs, deviceLeaseStageBound)
		if aerr == nil {
			// Where each moved address intent is realized now: the device
			// that says, from here on, what kind of device it needs
			// (corrosion.PCIAddressIdentity). The row it was recorded on
			// stays behind on the host the VM left.
			s.recordMovedRealizations(ctx, vm.Name, moved)
			return health.PassthroughRebuild{Addresses: addrs, Done: func(started bool) {
				if !started {
					s.releaseAllocatedDevices(ctx, "start", vm.Name, addrs)
				}
				finish()
			}}, nil
		}
		err = aerr
	}
	if optOut && notRetryableHere(err) {
		return dropped(err), nil
	}
	return none, err
}

// recordMovedRealizations writes the realization of each intent in moved at
// the address it takes on this host, as the start preflight does after the
// latch. A write that fails is logged: the VM still starts with the device,
// and its identity falls back to the host it was recorded on.
func (s *Server) recordMovedRealizations(ctx context.Context, vmName string, moved map[string]string) {
	for deviceID, addr := range moved {
		members, err := s.resolveDeviceSpec(ctx, vmName, &pb.DeviceSpec{Address: addr}, deviceID, map[string]bool{})
		if err == nil {
			err = s.writePCIRealizations(ctx, vmName, deviceID, members)
		}
		if err != nil {
			slog.Warn("pci: could not record where a moved device is realized", "vm", vmName, "device", deviceID, "address", addr, "error", err)
		}
	}
}

// passthroughForStart is, before hardware_v2 latches, the PCI passthrough an
// operator start (startVMLocked) gives a VM whose persistent definition has
// none of the PCI devices its spec declares: a VM a failover moved here
// stopped, whose definition was built from its spec without them
// (health/rekeyed_stopped.go). The devices are claimed here as for a rebuild
// (PassthroughForRebuild) and added to the definition; a VM this host has
// none for is refused, unless its spec opts in to starting without them
// (dropped then says why). After the latch the start preflight does this.
//
// done is called once with whether the domain started: false gives back what
// was claimed and puts the definition back as it was.
func (s *Server) passthroughForStart(ctx context.Context, vm *corrosion.VMRecord) (done func(started bool), dropped string, err error) {
	noop := func(bool) {}
	if vm == nil || s.virt == nil || s.db == nil || s.hardwareV2Latched(ctx) {
		return noop, "", nil
	}
	spec := &pb.VMSpec{}
	if vm.Spec != "" && json.Unmarshal([]byte(vm.Spec), spec) != nil {
		return noop, "", nil
	}
	intents, err := corrosion.ListVMPCIIntents(ctx, s.db, vm.Name)
	if err != nil {
		return noop, "", status.Errorf(codes.Internal, "read PCI intents for %q: %v", vm.Name, err)
	}
	if len(intents) == 0 && len(spec.GetDevices()) == 0 {
		return noop, "", nil
	}
	prior, derr := s.virt.DumpXMLInactive(vm.Name)
	if derr != nil || len(lv.HostdevSourcePCIAddresses(prior)) > 0 {
		return noop, "", nil
	}
	pt, err := s.PassthroughForRebuild(ctx, vm)
	if err != nil {
		return noop, "", err
	}
	if pt.Dropped != "" {
		return noop, pt.Dropped, nil
	}
	give := func(started bool) {
		if pt.Done != nil {
			pt.Done(started)
		}
	}
	if len(pt.Addresses) == 0 {
		return give, "", nil
	}
	withDevs, err := lv.AddPCIHostdevs(prior, pt.Addresses)
	if err == nil {
		err = s.virt.DefineDomain(withDevs)
	}
	if err != nil {
		give(false)
		return noop, "", status.Errorf(codes.Internal, "add the PCI passthrough of %q to its definition: %v", vm.Name, err)
	}
	var once sync.Once
	return func(started bool) {
		once.Do(func() {
			if !started {
				if derr := s.virt.DefineDomain(prior); derr != nil {
					slog.Warn("pci: could not put back the definition of a VM not started", "vm", vm.Name, "error", derr)
				}
			}
			give(started)
		})
	}, "", nil
}

// notePassthroughDropped records that vm, started here by an operator, runs
// without its PCI passthrough devices: its state detail, an event and an
// audit row.
func (s *Server) notePassthroughDropped(ctx context.Context, vm, why string) {
	detail := health.PassthroughDroppedDetail(why)
	slog.Warn("pci: "+detail, "vm", vm)
	if err := s.persistVMState(ctx, vm, "running", detail, corrosion.OpVMState); err != nil {
		slog.Error("record the running-without-devices detail", "vm", vm, "error", err)
	}
	health.RecordPassthroughDropped(ctx, s.db, s.hostName, callerUsername(ctx), vm, detail)
	s.audit(ctx, "vm.passthrough_dropped", vm, detail, "ok")
}

// notRetryableHere reports whether err says this host cannot give a VM its
// devices, as opposed to a read that failed.
func notRetryableHere(err error) bool {
	switch status.Code(err) {
	case codes.FailedPrecondition, codes.ResourceExhausted, codes.AlreadyExists, codes.NotFound:
		return true
	}
	return false
}
