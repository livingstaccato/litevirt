package health

import (
	"context"
	"fmt"
	"log/slog"
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

// SetNICIPDiscovery replaces the owner-host lookup vmAddress checks a NIC's
// recorded address against, and falls back to when none is recorded (dnsmasq
// leases, then the ARP cache). Test
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
// Sources:
//  1. the NIC's recorded address (vm_interfaces.ip, lowest ordinal first) —
//     a static assignment or one the IP scanner / NetBox gate recorded. It is
//     what `lv ls`, DNS and the load balancer use.
//  2. a live lookup of that NIC's MAC on THIS host — the dnsmasq leases, then
//     the ARP cache — which is possible because the probe runs on the VM's
//     owner. When it finds an address and that address is not the recorded
//     one, the live one wins: the IP scanner records a DHCP address once and
//     never updates it, so after the guest reboots onto a new lease the
//     recorded address is stale, and probing it fails a healthy VM (and its
//     action restarts it). When the lookup finds nothing, the recorded address
//     stands — a static or NetBox-assigned address need not appear in either.
//  3. with no address recorded for any NIC, the same live lookup for each
//     NIC's MAC in turn. This covers the window before the IP scanner (30s)
//     records a DHCP address, and a bound network whose claim has not been
//     granted yet.
//
// A live address is used, never written: recording belongs to the gated
// discovery paths (grpcapi/netbox_discovery.go).
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
	v.mu.Lock()
	discover := v.nicIPDiscovery
	v.mu.Unlock()
	if discover == nil {
		discover = lv.DiscoverIPForMAC // the lookup grpcapi's discovery uses too
	}
	live := func(mac string) string {
		if mac == "" {
			return ""
		}
		return bareIP(discover(mac))
	}
	for _, ifc := range ifaces {
		recorded := bareIP(ifc.IP)
		if recorded == "" {
			continue
		}
		if seen := live(ifc.MAC); seen != "" && seen != recorded {
			slog.Debug("vmcheck: probing the live address, not the recorded one",
				"vm", vm.Name, "mac", ifc.MAC, "recorded", recorded, "live", seen)
			return seen, ""
		}
		return recorded, ""
	}
	for _, ifc := range ifaces {
		if ip := live(ifc.MAC); ip != "" {
			return ip, ""
		}
	}
	return "", fmt.Sprintf("no address known for VM yet: none recorded for its NICs and no ARP entry or DHCP lease on %s", v.hostName)
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
