package grpcapi

import (
	"context"
	"log/slog"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// cloneContainerNICs rebuilds the MANAGED interface rows + create-spec networks
// for a CLONE from its source's create spec. The clone is a NEW workload: it gets
// a deterministic per-NIC MAC + veth (from the clone's name — matching what the
// runtime clone writes on-disk) and a DYNAMIC IP (blank: a clone must not reuse
// the source's address), so no IPAM lease is taken here. Legacy raw NICs are
// copied verbatim (no managed state).
//
// The derived MAC is the one the runtime clone wrote; when another NIC holds
// it (a container of the clone's name that migrated away from this host) a
// fresh one is drawn, and redrawn reports which NICs, by ordinal, need the
// clone's config rewritten to it.
func (s *Server) cloneContainerNICs(ctx context.Context, ctName string, srcSpec corrosion.ContainerCreateSpec) (ifaces []corrosion.ContainerInterfaceRecord, specNets []corrosion.ContainerNetwork, redrawn map[int]string, err error) {
	alloc := s.newMACAllocator()
	owner := corrosion.ContainerGuardOwner(s.hostName, ctName)
	for i, n := range srcSpec.Networks {
		if n.NetworkName == "" {
			specNets = append(specNets, n) // legacy/unmanaged → copy as-is
			continue
		}
		mac, ferr := s.freeContainerMAC(ctx, alloc, ctName, i, owner)
		if ferr != nil {
			return nil, nil, nil, ferr
		}
		if mac != corrosion.ContainerMAC(s.hostName, ctName, i) {
			if redrawn == nil {
				redrawn = map[int]string{}
			}
			redrawn[i] = mac
		}
		veth := corrosion.ContainerVethName(ctName, i)
		ifaces = append(ifaces, corrosion.ContainerInterfaceRecord{
			HostName: s.hostName, CtName: ctName, NetworkName: n.NetworkName, Ordinal: i,
			MAC: mac, IP: "", VethDevice: veth, SecurityGroups: n.SecurityGroups,
		})
		specNets = append(specNets, corrosion.ContainerNetwork{
			Name: n.Name, Bridge: n.Bridge, MAC: mac, NetworkName: n.NetworkName, SecurityGroups: n.SecurityGroups,
		})
	}
	return ifaces, specNets, redrawn, nil
}

// freeContainerMAC is NIC ordinal's derived MAC (corrosion.ContainerMAC),
// or a fresh random one in the same scheme when another NIC holds it or
// this request already has it.
func (s *Server) freeContainerMAC(ctx context.Context, alloc *macAllocator, ctName string, ordinal int, owner string) (string, error) {
	mac := corrosion.ContainerMAC(s.hostName, ctName, ordinal)
	ok, err := alloc.free(ctx, mac, owner)
	if err != nil {
		return "", err
	}
	if ok {
		alloc.reserve(mac)
		return mac, nil
	}
	return alloc.nextContainer(ctx)
}

// containerSpecNetworkNames lists the network each create-spec NIC attaches to:
// the managed network's name, or for a legacy raw NIC its bridge. It is what
// admitCopiedNetworks judges for a path that copies a container's NICs.
func containerSpecNetworkNames(spec corrosion.ContainerCreateSpec) []string {
	out := make([]string, 0, len(spec.Networks))
	for _, n := range spec.Networks {
		if n.NetworkName != "" {
			out = append(out, n.NetworkName)
		} else {
			out = append(out, n.Bridge)
		}
	}
	return out
}

// managedNICCount is how many of a create-spec's NICs become container_interfaces
// rows — the ONLY NICs a project's NIC quota counts. A legacy raw-bridge
// attachment carries no managed state and no row, so charging it would refuse
// creates for something that contributes nothing. Mirrors the rule in
// corrosion.BuildContainerInterfacesFromSpec and cloneContainerNICs.
func managedNICCount(spec corrosion.ContainerCreateSpec) int {
	n := 0
	for _, net := range spec.Networks {
		if net.NetworkName != "" {
			n++
		}
	}
	return n
}

// containerVethName is the deterministic host veth name for a container NIC.
// Defined in corrosion (shared with the health/relocate path); kept as a local
// alias for readability here.
func containerVethName(ctName string, ordinal int) string {
	return corrosion.ContainerVethName(ctName, ordinal)
}

// resolveBridgeToNetwork returns the single managed network whose rendered
// bridge equals bridge; ok=false if zero or many match (⇒ legacy-unmanaged).
// A network list that cannot be read is an error, never "raw" (m-3): a raw
// bridge is admitted on raw-bridge authority alone, which another project's
// rendered bridge must not be.
func (s *Server) resolveBridgeToNetwork(ctx context.Context, bridge string) (string, bool, error) {
	nets, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return "", false, err
	}
	match, n := "", 0
	for _, nr := range nets {
		if resolveBridge(ctx, s.db, nr.Name) == bridge {
			match, n = nr.Name, n+1
		}
	}
	return match, n == 1, nil
}

// classifiedNetworkNames is containerSpecNetworkNames with each raw bridge
// that renders a managed network named as that network: what admission
// judges for a path that copies a container's NICs (m-7). A raw bridge that
// has since become another project's network is that project's NIC.
func (s *Server) classifiedNetworkNames(ctx context.Context, spec corrosion.ContainerCreateSpec) ([]string, error) {
	out := make([]string, 0, len(spec.Networks))
	for _, n := range spec.Networks {
		if n.NetworkName != "" {
			out = append(out, n.NetworkName)
			continue
		}
		name, ok, err := s.resolveBridgeToNetwork(ctx, n.Bridge)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, name)
		} else {
			out = append(out, n.Bridge)
		}
	}
	return out, nil
}

// containerNICPlan is the resolved per-create network wiring.
type containerNICPlan struct {
	lxcNics  []ContainerNICOpt
	ifaces   []corrosion.ContainerInterfaceRecord
	specNets []corrosion.ContainerNetwork
}

// resolveContainerNICs turns the requested NICs into runtime attachments, the
// managed-interface rows, and the create-spec network intent, ALLOCATING each
// managed NIC's IPAM lease as it goes (tombstone/race-safe). A NIC is MANAGED
// when it names — or its bridge resolves to — exactly one known network;
// otherwise it's a legacy raw-bridge attachment with no managed state (no
// interface row, IPAM, or veth). On error the caller must release this
// container's leases (network.ReleaseContainerLeases) to undo partial allocation.
func (s *Server) resolveContainerNICs(ctx context.Context, project, ctName string, nics []*pb.ContainerNetwork) (*containerNICPlan, error) {
	p := &containerNICPlan{}
	haveGateway := false // one default route: the first managed NIC with a subnet
	// A MAC the request names must be its NIC's own: one another live NIC
	// records would put two NICs on one MAC, and the guard keyed by it would
	// admit the other's traffic.
	owner := corrosion.ContainerGuardOwner(s.hostName, ctName)
	seenMAC := map[string]bool{}
	var explicit []string
	for _, n := range nics {
		if m := strings.ToLower(n.GetMac()); m != "" {
			if seenMAC[m] {
				return nil, status.Errorf(codes.InvalidArgument, "MAC %s is given to two NICs of this request", m)
			}
			seenMAC[m] = true
			explicit = append(explicit, m)
		}
	}
	// The cluster's MACs, read once for the whole request.
	macs, merr := s.loadMACSet(ctx)
	if merr != nil {
		return nil, merr
	}
	if mac, holder := macs.firstHeld(explicit, owner); holder != "" {
		return nil, status.Errorf(codes.AlreadyExists, "MAC %s is already used by %s", mac, holder)
	}
	macAlloc := s.newMACAllocatorFrom(macs)
	for _, m := range explicit {
		macAlloc.reserve(m)
	}
	for i, n := range nics {
		netName := n.NetworkName
		var def *compose.NetworkDef
		switch {
		case netName != "":
			var derr error
			if def, derr = lookupNetworkDef(ctx, s.db, netName); derr != nil {
				// Fail closed on a read failure rather than report the network
				// missing: "not found" is a definite answer this read did not
				// give, and the def is what decides raw-bridge admission and the
				// bound-network refusal below.
				return nil, status.Errorf(codes.Internal, "read network %q: %v", netName, derr)
			} else if def == nil {
				return nil, status.Errorf(codes.InvalidArgument, "network %q not found", netName)
			}
		case n.Bridge != "":
			name, ok, rerr := s.resolveBridgeToNetwork(ctx, n.Bridge)
			if rerr != nil {
				// Fail closed: a bridge that may render a managed network must
				// not take the raw-bridge path because the list was unreadable.
				return nil, status.Errorf(codes.Unavailable, "read networks (does bridge %q render a managed network?): %v", n.Bridge, rerr)
			}
			if ok {
				netName = name
				var derr error
				// Same reason: a bridge that RESOLVES to a managed network must
				// not degrade to the legacy raw-bridge path (no isolation check,
				// no bound-network refusal) because its record could not be read.
				if def, derr = lookupNetworkDef(ctx, s.db, name); derr != nil {
					return nil, status.Errorf(codes.Internal, "read network %q: %v", name, derr)
				}
			}
		}

		if def == nil {
			// Legacy-unmanaged raw bridge: outside isolation. A named-project
			// container may NOT use one (hard isolation requires a managed network);
			// the default project / root keeps the escape hatch.
			ref := n.Bridge
			if ref == "" {
				ref = n.NetworkName
			}
			if err := s.admitRawBridge(ctx, ref); err != nil {
				return nil, err
			}
			// Pass through verbatim. No managed state.
			p.lxcNics = append(p.lxcNics, ContainerNICOpt{Name: n.Name, Bridge: n.Bridge, IP: n.Ip, MAC: n.Mac})
			p.specNets = append(p.specNets, corrosion.ContainerNetwork{Name: n.Name, Bridge: n.Bridge, IP: n.Ip, MAC: n.Mac})
			continue
		}

		// Managed NIC → project isolation applies: the container may attach only to a
		// global network or one its own project owns. Also closes the raw-bridge
		// escape hatch — a bridge that RESOLVES to another project's managed network
		// is denied here (an unresolved raw bridge stays legacy/global above).
		if err := s.admitNetworkAttach(ctx, project, netName); err != nil {
			return nil, err
		}

		// Allocator selection happens HERE, before any provisioning or address
		// work, because for a container it is also an ADMISSION decision: a
		// NetBox-bound network is VM-only and must be refused outright rather
		// than allocated around. Resolving it early makes the refusal cover the
		// static-IP and subnet-less NICs too, which never reach the claim below.
		alloc, _, aerr := s.allocatorFor(ctx, "ct", netName)
		if aerr != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "%v", aerr)
		}

		// Managed NIC. Containers support only L2 bridge-family networks; direct
		// (macvtap) and SR-IOV are VM-only (they'd render VM-shaped link values
		// like "direct:<iface>" into lxc.net.N.link).
		switch def.Type {
		case "direct", "sriov":
			return nil, status.Errorf(codes.InvalidArgument,
				"network %q type %q is not supported for containers", netName, def.Type)
		}
		// Provision the network on this host (creates/ensures the bridge/vxlan/
		// isolated device) and use the real bridge — like the VM path.
		bridge, perr := s.provisionForVM(ctx, netName)
		if perr != nil {
			// vxlan / isolated devices MUST be provisioned by litevirt (lxc can't
			// auto-create them), so a provision failure means the link won't exist —
			// hard-fail rather than track a managed NIC on a phantom device. A plain
			// bridge falls back to the resolved name (lxc auto-creates it, or it's
			// pre-existing), matching VM create.
			if def.Type == "vxlan" || def.Type == "isolated" {
				return nil, status.Errorf(codes.FailedPrecondition, "provision %s network %q: %v", def.Type, netName, perr)
			}
			slog.Warn("container network provision failed; using resolved bridge name",
				"network", netName, "error", perr)
			bridge = resolveBridge(ctx, s.db, netName)
		} else if bridge == "" {
			bridge = resolveBridge(ctx, s.db, netName)
		}
		mac := n.Mac
		if mac == "" {
			// Wide (40-bit), host-aware, deterministic CT MAC — same generator the
			// clone/relocate paths use, so a rebuild reproduces it and two same-named
			// CTs on different hosts (shared L2) don't collide. (GenerateMAC's 24-bit
			// 52:54:00 space is VM-shared; CTs get the wider scheme.)
			// The derived MAC repeats for the same host, name and NIC: a
			// container of this name that migrated away holds it. One another
			// NIC holds is drawn afresh instead.
			var ferr error
			if mac, ferr = s.freeContainerMAC(ctx, macAlloc, ctName, i, owner); ferr != nil {
				return nil, ferr
			}
		}
		veth := containerVethName(ctName, i)
		// Allocate the IP NOW (writing the lease) — tombstone- and race-safe. A
		// static request reserves that exact address (fail if held by another);
		// otherwise litevirt allocates from the subnet; a subnet-less network is
		// DHCP (blank IP, no lease). The caller releases all of this container's
		// leases (network.ReleaseContainerLeases) if create later fails.
		ip := ""
		switch {
		case n.Ip != "":
			ok, rerr := network.ReserveContainerIP(ctx, s.db, netName, n.Ip, mac, s.hostName, ctName)
			if rerr != nil {
				return nil, status.Errorf(codes.Internal, "reserve IP %q on %q: %v", n.Ip, netName, rerr)
			}
			if !ok {
				return nil, status.Errorf(codes.AlreadyExists, "static IP %q on network %q is already in use", n.Ip, netName)
			}
			ip = n.Ip
		case def.Subnet != "":
			req := network.ClaimRequest{
				Network:   netName,
				Subnet:    def.Subnet,
				MAC:       mac,
				OwnerKind: "ct",
				OwnerHost: s.hostName,
				Name:      ctName,
			}
			var cand network.ClaimResult
			var aerr error
			if cloudinit.HostIsolatedAddressable(def) {
				// A VM create on this host may hold an address on this
				// network whose rows are not written yet: pass over it,
				// and claim under the lock its picks are made under
				// (review m-5).
				s.dhcpResMu.Lock()
				req.Exclude = s.isoPendingAddrsLocked(netName)
				cand, aerr = alloc.Claim(ctx, req)
				s.dhcpResMu.Unlock()
			} else {
				cand, aerr = alloc.Claim(ctx, req)
			}
			if aerr != nil {
				return nil, status.Errorf(codes.ResourceExhausted, "allocate IP on network %q: %v", netName, aerr)
			}
			ip = cand.IP
		}
		// The runtime NIC carries the subnet's prefix and gateway: LXC reads a
		// bare address classfully. The rows and the spec keep the address as
		// IPAM holds it.
		runIP, gw := network.ContainerAddress(ip, def.Subnet)
		if haveGateway {
			gw = ""
		}
		haveGateway = haveGateway || gw != ""
		p.lxcNics = append(p.lxcNics, ContainerNICOpt{Name: n.Name, Bridge: bridge, IP: runIP, MAC: mac, Veth: veth, Gateway: gw})
		p.ifaces = append(p.ifaces, corrosion.ContainerInterfaceRecord{
			HostName: s.hostName, CtName: ctName, NetworkName: netName, Ordinal: i,
			MAC: mac, IP: ip, VethDevice: veth, SecurityGroups: n.SecurityGroups,
		})
		// create_spec stores the EFFECTIVE IP (static or auto-allocated), so a
		// rebuild (restore/migrate/relocate) re-reserves the same address instead of
		// losing an auto-allocated one. The rebuild's reserve is conditional (never
		// steals), so reusing it is safe.
		p.specNets = append(p.specNets, corrosion.ContainerNetwork{
			Name: n.Name, Bridge: bridge, IP: ip, MAC: mac,
			NetworkName: netName, SecurityGroups: n.SecurityGroups,
		})
	}
	return p, nil
}

// releaseContainerNICs releases a container's managed IPAM leases and tombstones
// its interface rows (the delete cascade). Best-effort: returns the first error
// for logging but always attempts every step.
func (s *Server) releaseContainerNICs(ctx context.Context, ctName string) error {
	// Release every IPAM lease this container holds on the host (across networks),
	// then tombstone its interface rows. ReleaseContainerLeases works even when the
	// interface rows are absent (e.g. rolling back a create that failed before the
	// rows were written).
	firstErr := network.ReleaseContainerLeases(ctx, s.db, s.hostName, ctName)
	if e := corrosion.DeleteContainerInterfaces(ctx, s.db, s.hostName, ctName); e != nil && firstErr == nil {
		firstErr = e
	}
	return firstErr
}

// containerNICMACSetter rewrites the MAC of NIC ordinal in a stopped
// container's runtime config.
type containerNICMACSetter interface {
	SetContainerNICMAC(ctx context.Context, name string, ordinal int, mac string) error
}

// setContainerNICMACs writes macs (by NIC ordinal) into container name's
// config. A runtime that cannot is a refusal: the config would keep a MAC
// another NIC holds.
func (s *Server) setContainerNICMACs(ctx context.Context, name string, macs map[int]string) error {
	if len(macs) == 0 {
		return nil
	}
	st, ok := s.containerRuntime.(containerNICMACSetter)
	if !ok {
		return status.Errorf(codes.Unavailable,
			"container %q: a NIC's MAC is already used by another NIC, and this host's container runtime cannot write a new one into its config", name)
	}
	for ord, mac := range macs {
		if err := st.SetContainerNICMAC(ctx, name, ord, mac); err != nil {
			return status.Errorf(codes.Internal, "container %q: write NIC %d's MAC %s: %v", name, ord, mac, err)
		}
	}
	return nil
}
