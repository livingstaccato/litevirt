package health

import (
	"context"
	"fmt"
	"net"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// Probe targets are resolved relative to the VM.
//
// The checker runs on the VM's owning HOST. A target that names a place on the
// VM — a bare port, an empty host, localhost or any loopback address — is
// rewritten to the VM's address before the transport sees it; a target naming
// another host is probed as given; exec runs in the guest and is never
// rewritten. compose.ParseHealthTarget holds the rules, shared with compose
// validation so a file is refused for exactly the targets the checker could not
// run.
//
// When the probe CANNOT run — the VM has no known address yet, or its stored
// target cannot be interpreted — the outcome is "unknown", never a failure:
// the verdict says why (so a vm_healthy wait keeps waiting and its timeout
// names the reason), and the healthcheck's action does not fire. A probe that
// was never run says nothing about the VM, and restarting a VM because the
// checker does not know where it is would restart it forever.

// SetNICIPDiscovery replaces the owner-host lookup vmAddress falls back to
// when a NIC has no recorded address (ARP cache, then dnsmasq leases). Test
// seam, nil in production — the same seam grpcapi's discovery has, for the
// same reason: no test host has a guest answering ARP.
func (v *VMChecker) SetNICIPDiscovery(fn func(mac string) string) {
	v.mu.Lock()
	v.nicIPDiscovery = fn
	v.mu.Unlock()
}

// resolveProbeSpec returns hspec with its target resolved against vm, or nil
// and the reason the probe cannot be run.
func (v *VMChecker) resolveProbeSpec(ctx context.Context, vm corrosion.VMRecord, hspec *pb.HealthCheckSpec) (*pb.HealthCheckSpec, string) {
	if hspec.Type == "exec" {
		return hspec, "" // runs in the guest, by name: nothing to resolve
	}
	ht, err := compose.ParseHealthTarget(hspec.Type, hspec.Target)
	if err != nil {
		return nil, fmt.Sprintf("healthcheck cannot be probed: %v", err)
	}
	addr := ""
	if ht.VMRelative {
		a, why := v.vmAddress(ctx, vm)
		if a == "" {
			return nil, why
		}
		addr = a
	}
	out := proto.Clone(hspec).(*pb.HealthCheckSpec)
	out.Target = ht.Resolve(addr)
	return out, ""
}

// vmAddress is the address a VM-relative probe goes to, or "" and why there
// is none.
//
// Sources, in order:
//  1. the NIC's recorded address (vm_interfaces.ip, lowest ordinal first) —
//     a static assignment or one the IP scanner / NetBox gate recorded. It is
//     what `lv ls`, DNS and the load balancer use, so the probe checks the
//     address everything else sends traffic to.
//  2. a live lookup of each NIC's MAC on THIS host — the ARP cache, then the
//     dnsmasq leases — which is possible because the probe runs on the VM's
//     owner. This covers the window before the IP scanner (30s) records a DHCP
//     address, and a bound network whose claim has not been granted yet. The
//     address is used, never written: recording belongs to the gated paths.
func (v *VMChecker) vmAddress(ctx context.Context, vm corrosion.VMRecord) (string, string) {
	if v.db == nil {
		return "", "no address known for VM yet: no cluster state to read its NICs from"
	}
	ifaces, err := corrosion.GetVMInterfaces(ctx, v.db, vm.Name)
	if err != nil {
		return "", fmt.Sprintf("no address known for VM yet: reading its NICs failed: %v", err)
	}
	if len(ifaces) == 0 {
		return "", "no address known for VM yet: it has no network interface to probe"
	}
	for _, ifc := range ifaces {
		if ip := bareIP(ifc.IP); ip != "" {
			return ip, ""
		}
	}
	v.mu.Lock()
	discover := v.nicIPDiscovery
	v.mu.Unlock()
	if discover == nil {
		discover = discoverNICAddressLocal
	}
	for _, ifc := range ifaces {
		if ifc.MAC == "" {
			continue
		}
		if ip := bareIP(discover(ifc.MAC)); ip != "" {
			return ip, ""
		}
	}
	return "", fmt.Sprintf("no address known for VM yet: none recorded for its NICs and no ARP entry or DHCP lease on %s", v.hostName)
}

// discoverNICAddressLocal is grpcapi's discoverNICAddress: where this host
// sees a MAC answering.
func discoverNICAddressLocal(mac string) string {
	if ip := lv.GetIPFromARP(mac); ip != "" {
		return ip
	}
	return lv.GetIPFromDHCPLeases("/var/lib/libvirt/dnsmasq", mac)
}

// bareIP returns s as a bare IP literal ("10.0.0.5/24" → "10.0.0.5"), or ""
// when it is not an address.
func bareIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip, _, err := net.ParseCIDR(s); err == nil {
		return ip.String()
	}
	if ip := net.ParseIP(s); ip != nil {
		return ip.String()
	}
	return ""
}
