package grpcapi

import (
	"context"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// deleteWorkload removes a planned workload, routing containers to
// DeleteContainer (on their resolved/current host) and VMs to DeleteVM. Used by
// the deploy executor for OpDelete and the delete half of an OpUpdate recreate.
func (s *Server) deleteWorkload(ctx context.Context, a planner.VMAction) error {
	if a.IsContainer && a.Kind == planner.OpUpdate {
		// Judged before anything is deleted: a refused recreate leaves the
		// member running as it is.
		if err := s.rememberRecreatedSecurity(ctx, a); err != nil {
			return err
		}
	}
	if a.IsContainer {
		_, err := s.DeleteContainer(ctx, &pb.DeleteContainerRequest{HostName: a.TargetHost, Name: a.VMName, Force: true})
		return err
	}
	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: a.VMName})
	return err
}

// buildContainerRequest converts a compose container workload (kind: lxc | oci)
// into a CreateContainerRequest for the planner-resolved host. The deploy path
// calls CreateContainer + StartContainer with the result, so a compose stack can
// mix VMs and containers.
//
// image →:
//   - a rootfs path ("/abs", "./rel", "../rel", "rootfs:<p>"): used verbatim as
//     the Template — a pre-extracted rootfs (e.g. from `lv ct pull`). Works for
//     both lxc and oci workloads.
//   - "distro[:release]" (kind: lxc): the LXC `download` template.
//   - an OCI registry ref (kind: oci, not a path): NOT auto-pulled by compose
//     yet — returns a clear error directing the operator to pre-pull. (follow-up)
//
// Container NICs attach to the resolved scoped-network bridge (resolveBridge,
// the same mapping VMs use). Full network provisioning + IPAM + security-groups
// for container veths is a separate follow-up; a container sharing a stack
// network with a VM finds the bridge already provisioned by the VM path.
func (s *Server) buildContainerRequest(ctx context.Context, instanceName string, d *compose.VMDef, f *compose.File, targetHost string) (*pb.CreateContainerRequest, error) {
	// Tag the container with its compose stack (reserved label) so the deploy
	// planner's current-state diff and `compose down` can find it — the
	// containers table has no stack_name column. Compose's value wins over any
	// user-set label of the same key.
	labels := map[string]string{}
	for k, v := range d.Labels {
		labels[k] = v
	}
	labels[corrosion.LabelStack] = f.Name

	req := &pb.CreateContainerRequest{
		HostName:  targetHost,
		Name:      instanceName,
		Cpu:       int32(d.CPU),
		MemoryMib: int32(d.Memory),
		Labels:    labels,
		Image:     d.Image,
		Arch:      "amd64",
		// Security opt-outs; CreateContainer holds them to the Admin role.
		Privileged:  d.Privileged,
		Confinement: d.Confinement,
	}

	switch {
	case isRootfsTemplate(d.Image):
		req.Template = d.Image
	case d.Kind == compose.WorkloadKindLXC:
		distro, release, _ := strings.Cut(d.Image, ":")
		if distro == "" {
			return nil, fmt.Errorf("container %q: kind=lxc needs image: \"distro[:release]\" (e.g. \"alpine:3.21\") or a rootfs path", instanceName)
		}
		req.Template, req.Distro, req.Release = "download", distro, release
	default: // kind=oci with a registry ref
		return nil, fmt.Errorf(
			"container %q: compose can't auto-pull OCI image %q yet — pre-pull it (`lv ct pull %s --dest <rootfs-dir>`) and set image: to that rootfs path",
			instanceName, d.Image, d.Image)
	}

	if d.Restart != nil {
		req.Restart = &pb.RestartPolicy{
			Condition:   d.Restart.Condition,
			Delay:       d.Restart.Delay,
			MaxAttempts: int32(d.Restart.MaxAttempts),
			Window:      d.Restart.Window,
		}
	}

	for _, n := range d.Network {
		// Resolve against the network's RECORD name. Compose registers each
		// stack-owned network as "<stack>_<name>", and an isolated network's host
		// bridge is derived from that name (br-iso-<hash>). Resolving the wrong
		// name misses the lookup and returns an invalid bridge, so the
		// container's veth can't attach and lxc-start aborts. External and
		// undeclared names are cluster networks and keep their own name; the VM
		// path resolves them through the same function.
		scoped := f.ResolveNetworkName(n.Name)
		ipCIDR, bareIP := n.IP, n.IP
		if n.IP != "" {
			if addr, _, hasPrefix := strings.Cut(n.IP, "/"); hasPrefix {
				bareIP = addr // caller already supplied a CIDR
			} else if def, _ := lookupNetworkDef(ctx, s.db, scoped); def != nil {
				// lxc.net.*.ipv4.address needs addr/prefix; compose NICs carry a
				// bare IP, so borrow the prefix from the network's subnet.
				if _, bits, ok := strings.Cut(def.Subnet, "/"); ok && bits != "" {
					ipCIDR = n.IP + "/" + bits
				}
			}
		}
		req.Networks = append(req.Networks, &pb.ContainerNetwork{
			Name:   n.Name,
			Bridge: resolveBridge(ctx, s.db, scoped),
			Ip:     ipCIDR,
			Mac:    n.MAC,
		})
		// Record the bare address so the container can be discovered as an LB
		// backend cluster-wide (see corrosion.LabelIP). DHCP NICs (no IP) are
		// resolved locally on the LB host at apply time instead.
		if bareIP != "" && labels[corrosion.LabelIP] == "" {
			labels[corrosion.LabelIP] = bareIP
		}
	}
	return req, nil
}

// isRootfsTemplate reports whether a compose container `image:` is a rootfs
// path/reference (vs a download distro or an OCI registry ref).
func isRootfsTemplate(image string) bool {
	return strings.HasPrefix(image, "/") || strings.HasPrefix(image, "./") ||
		strings.HasPrefix(image, "../") || strings.HasPrefix(image, "rootfs:")
}

// A compose recreate (an image, cpu or memory change) replaces a container
// with a new one. It keeps the outgoing container's privilege mode and
// confinement unless the stack file states its own: an existing container
// keeps its settings until an operator converts it, and a main-era member
// (privileged, legacy) would otherwise come back unprivileged and confined —
// breaking a nesting workload on an unrelated image bump, with a fix only an
// Admin could make. A brand-new member gets the defaults.

// inheritedSecurityKey marks a create whose privileged/legacy settings were
// carried over from the container it replaces, not asked for. Set only here,
// in-process; it never crosses the wire.
type inheritedSecurityKey struct{}

func withInheritedSecurity(ctx context.Context) context.Context {
	return context.WithValue(ctx, inheritedSecurityKey{}, true)
}

func securityInherited(ctx context.Context) bool {
	v, _ := ctx.Value(inheritedSecurityKey{}).(bool)
	return v
}

// rememberRecreatedSecurity records the outgoing container's security before
// a recreate deletes it.
func (s *Server) rememberRecreatedSecurity(ctx context.Context, a planner.VMAction) error {
	var rec *corrosion.ContainerRecord
	if a.TargetHost != "" {
		rec, _ = corrosion.GetContainer(ctx, s.db, a.TargetHost, a.VMName)
	}
	if rec == nil {
		if _, r, err := s.resolveContainerHost(ctx, "", a.VMName); err == nil {
			rec = r
		}
	}
	if rec == nil {
		return nil
	}
	if err := s.mayKeepMemberSecurity(ctx, a.VMName, rec.Project, corrosion.DecodeCreateSpec(rec.CreateSpec)); err != nil {
		return err
	}
	s.recreateSecMu.Lock()
	defer s.recreateSecMu.Unlock()
	if s.recreateSec == nil {
		s.recreateSec = map[string]recreatedMember{}
	}
	s.recreateSec[a.VMName] = recreatedMember{spec: corrosion.DecodeCreateSpec(rec.CreateSpec), project: rec.Project}
	return nil
}

// mayKeepMemberSecurity refuses a caller recreating a privileged or
// legacy-confined member who could not create one (not Admin) and holds no
// ct.exec on the member (root inside it already). Dropping the member to
// unprivileged instead would break the workload behind their back.
func (s *Server) mayKeepMemberSecurity(ctx context.Context, name, project string, spec corrosion.ContainerCreateSpec) error {
	privileged := spec.IDMapBase == 0
	if !privileged && spec.Confinement == lxc.ConfinementDefault {
		return nil
	}
	if RequireRole(ctx, "admin") == nil {
		return nil
	}
	if err := s.RequirePerm(ctx, ctRBACPathFor(project, name), "ct.exec", "operator"); err != nil {
		what := "legacy-confined"
		if privileged {
			what = "privileged"
		}
		return status.Errorf(codes.PermissionDenied,
			"container %q is %s; recreating it keeps that, which needs the Admin role or ct.exec on it (root inside it already): "+
				"ask an Admin to deploy this change, or move it over first with lv ct convert --unprivileged --confinement default %s",
			name, what, name)
	}
	return nil
}

// recreatedMember is what a recreate remembers of the container it replaces.
type recreatedMember struct {
	spec    corrosion.ContainerCreateSpec
	project string
}

// inheritRecreatedSecurity applies a recreate's remembered security to req
// when the stack file states none, and returns the context to create with.
//
// Carrying a privileged or legacy-confined member over is allowed only to a
// caller who could create one (Admin) or who holds ct.exec on the member being
// replaced — root inside it already. Anyone else is refused, by name: dropping
// the member to unprivileged instead would break the workload behind their
// back.
func (s *Server) inheritRecreatedSecurity(ctx context.Context, a planner.VMAction, d *compose.VMDef, req *pb.CreateContainerRequest) (context.Context, error) {
	if a.Kind != planner.OpUpdate {
		return ctx, nil
	}
	s.recreateSecMu.Lock()
	m, ok := s.recreateSec[a.VMName]
	delete(s.recreateSec, a.VMName)
	s.recreateSecMu.Unlock()
	if !ok || d.Privileged || d.Confinement != "" {
		return ctx, nil
	}
	req.Privileged = m.spec.IDMapBase == 0
	req.Confinement = m.spec.Confinement
	if req.Confinement == "" {
		req.Confinement = lxc.ConfinementLegacy
	}
	if !req.Privileged && req.Confinement == lxc.ConfinementDefault {
		return ctx, nil
	}
	// Checked before the delete too (rememberRecreatedSecurity); again here,
	// where the carried-over opt-out is granted.
	if err := s.mayKeepMemberSecurity(ctx, a.VMName, m.project, m.spec); err != nil {
		return ctx, err
	}
	return withInheritedSecurity(ctx), nil
}
