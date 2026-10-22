package placement

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// FailoverDeviceRequests is what vm's PCI passthrough devices require of a
// host it is recovered onto, and a description of each for an operator. The
// selectors are the VM's intents (the authority once they exist), else its
// spec's devices, each as DeviceRequestFor converts it, except a concrete
// address: that is a slot on the host it was recorded on, so it requires a
// free device of the kind the inventory records there
// (corrosion.PCIAddressIdentity), never a device at the same address.
//
// An error means the requirement cannot be stated (an unreadable record, an
// address whose device is not in any inventory): the caller does not recover
// the VM, rather than recover it to a host chosen without its devices.
func FailoverDeviceRequests(ctx context.Context, db *corrosion.Client, vm corrosion.VMRecord) ([]DeviceRequest, []string, error) {
	intents, err := corrosion.ListVMPCIIntents(ctx, db, vm.Name)
	if err != nil {
		return nil, nil, fmt.Errorf("read the PCI intents of %s: %w", vm.Name, err)
	}
	type selector struct {
		dev      *pb.DeviceSpec
		deviceID string
		origin   string
	}
	var sels []selector
	if len(intents) > 0 {
		for _, in := range intents {
			if in.SelectorKind == "address" {
				addr := ""
				if in.ExclusiveKey != nil {
					addr = *in.ExclusiveKey
				}
				origin := in.HostName
				if origin == "" {
					origin = vm.HostName
				}
				sels = append(sels, selector{dev: &pb.DeviceSpec{Address: addr}, deviceID: in.DeviceID, origin: origin})
				continue
			}
			d := &pb.DeviceSpec{}
			if err := protojson.Unmarshal([]byte(in.SelectorPayload), d); err != nil {
				return nil, nil, fmt.Errorf("decode the PCI intent %s of %s: %w", in.DeviceID, vm.Name, err)
			}
			sels = append(sels, selector{dev: d})
		}
	} else if vm.Spec != "" {
		spec := &pb.VMSpec{}
		if err := json.Unmarshal([]byte(vm.Spec), spec); err != nil {
			return nil, nil, fmt.Errorf("decode the spec of %s: %w", vm.Name, err)
		}
		for _, d := range spec.Devices {
			sels = append(sels, selector{dev: d, origin: vm.HostName})
		}
	}

	var reqs []DeviceRequest
	var descs []string
	for _, s := range sels {
		if kind, _ := corrosion.ClassifyPCISelector(s.dev); kind == "address" {
			ident, _, err := corrosion.PCIAddressIdentity(ctx, db, vm.Name, s.deviceID, s.origin, s.dev.Address)
			if err != nil {
				return nil, nil, err
			}
			reqs = append(reqs, DeviceRequest{Vendor: ident.VendorID, DeviceID: ident.DeviceID, Count: 1})
			descs = append(descs, ident.String()+" (was "+s.dev.Address+" on "+s.origin+")")
			continue
		}
		dr := DeviceRequestFor(s.dev)
		if dr.Count <= 0 {
			dr.Count = 1
		}
		reqs = append(reqs, dr)
		descs = append(descs, describeDeviceRequest(dr))
	}
	return reqs, descs, nil
}

func describeDeviceRequest(r DeviceRequest) string {
	var f []string
	for _, kv := range [][2]string{{"mapping", r.Mapping}, {"type", r.Type}, {"vendor", r.Vendor}, {"model", r.Model}, {"parent", r.Parent}} {
		if kv[1] != "" {
			f = append(f, kv[0]+"="+kv[1])
		}
	}
	if r.Sriov {
		f = append(f, "sriov")
	}
	s := strings.Join(f, " ")
	if r.Count > 1 {
		s += fmt.Sprintf(" x%d", r.Count)
	}
	return s
}

// LoadDevicePools reads what SelectBatchWithMappings needs to judge the
// device requests of reqs on hosts: each host's whole PCI inventory and the
// addresses of every resource mapping a request names. Both are nil when no
// request has devices.
func LoadDevicePools(ctx context.Context, db *corrosion.Client, hosts []corrosion.HostRecord, reqs []Request) (map[string][]corrosion.PCIDeviceRecord, map[string]map[string][]string, error) {
	need := false
	for _, r := range reqs {
		if len(r.Devices) > 0 {
			need = true
			break
		}
	}
	if !need {
		return nil, nil, nil
	}
	devices := make(map[string][]corrosion.PCIDeviceRecord, len(hosts))
	for _, h := range hosts {
		devs, err := corrosion.ListPCIDevices(ctx, db, h.Name, "")
		if err != nil {
			return nil, nil, fmt.Errorf("list PCI devices on %s: %w", h.Name, err)
		}
		devices[h.Name] = devs
	}
	mappings := map[string]map[string][]string{}
	for _, r := range reqs {
		for _, d := range r.Devices {
			if d.Mapping == "" {
				continue
			}
			if _, done := mappings[d.Mapping]; done {
				continue
			}
			m, err := corrosion.GetResourceMapping(ctx, db, d.Mapping)
			if err != nil {
				return nil, nil, fmt.Errorf("get resource mapping %q: %w", d.Mapping, err)
			}
			byHost := map[string][]string{}
			if m != nil {
				for _, md := range m.Devices {
					byHost[md.HostName] = append(byHost[md.HostName], md.Address)
				}
			}
			mappings[d.Mapping] = byHost
		}
	}
	return devices, mappings, nil
}
