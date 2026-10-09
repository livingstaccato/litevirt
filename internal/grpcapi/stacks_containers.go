package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
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
//
// A container recreate is judged before this runs (judgeContainerRecreate,
// from recreateInline), so a refused recreate never reaches the delete.
func (s *Server) deleteWorkload(ctx context.Context, a planner.VMAction) error {
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

// judgeContainerRecreate judges a compose recreate of a container member
// BEFORE its delete half runs, so a refused recreate leaves the member as it
// is, and remembers the outgoing member's security for the create
// (inheritRecreatedSecurity).
//
// The mode the recreate asks for is the stack file's privileged/confinement,
// or, when it states neither, the member's own (an existing container keeps
// its settings until an operator converts it). Then:
//   - an opt-out the member does not already have (privileged over an id-
//     mapped member, legacy over default confinement) is a new one: Admin
//     only, as for lv ct create;
//   - a privileged or legacy-confined mode the member already has is kept
//     for whoever may deploy the stack when the recreate runs the same image
//     (sameContainerImage), as on main; when the image changes, the deployer
//     is choosing a new rootfs to run as host root, which needs the Admin
//     role or ct.exec on the member (root inside it already).
func (s *Server) judgeContainerRecreate(ctx context.Context, a planner.VMAction, f *compose.File) error {
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
	old := corrosion.DecodeCreateSpec(rec.CreateSpec)
	m := recreatedMember{spec: old, project: rec.Project}
	var d *compose.VMDef
	if f != nil {
		d, _ = compose.FindVMDef(f, a.VMName)
	}
	if d != nil {
		oldPrivileged, oldConfinement := recordedSecurity(old)
		privileged, confinement := d.Privileged, d.Confinement
		if !privileged && confinement == "" {
			privileged, confinement = oldPrivileged, oldConfinement
		}
		legacy := confinement == lxc.ConfinementLegacy
		switch {
		case !privileged && !legacy:
			// The defaults; a confinement that is not one is refused now,
			// not by the create after the delete.
			if err := containerSecurityRequest(ctx, false, d.Confinement); err != nil {
				return err
			}
		case (privileged && !oldPrivileged) || (legacy && oldConfinement != lxc.ConfinementLegacy):
			if err := containerSecurityRequest(ctx, d.Privileged, d.Confinement); err != nil {
				s.audit(ctx, "ct.recreate-security", a.VMName,
					fmt.Sprintf("project=%s new opt-out privileged=%v confinement=%s", rec.Project, d.Privileged, d.Confinement), "denied")
				return status.Errorf(status.Code(err), "recreating container %q: %s; the member was left as it is", a.VMName, status.Convert(err).Message())
			}
		default:
			if !sameContainerImage(*rec, old, d) {
				if err := s.mayChangePrivilegedImage(ctx, a.VMName, rec, d, privileged); err != nil {
					return err
				}
			}
			m.keep = true
			m.note = RequireRole(ctx, "admin") != nil
		}
	}
	s.recreateSecMu.Lock()
	defer s.recreateSecMu.Unlock()
	if s.recreateSec == nil {
		s.recreateSec = map[string]recreatedMember{}
	}
	s.recreateSec[a.VMName] = m
	return nil
}

// recordedSecurity is a container record's privilege mode and confinement;
// a record an earlier build wrote (no confinement) is privileged and legacy.
func recordedSecurity(spec corrosion.ContainerCreateSpec) (privileged bool, confinement string) {
	confinement = spec.Confinement
	if confinement == "" {
		confinement = lxc.ConfinementLegacy
	}
	return spec.IDMapBase == 0, confinement
}

// sameContainerImage reports whether a recreate from d runs the image the
// member runs: what decides the rootfs a privileged container starts as host
// root. Compared are the image reference (the record's image against the
// stack file's image:) and, when the member's create spec records them, the
// rootfs source it was built from: template, distro, release and arch. The
// security mode is judged by the caller, and the rest of a container's config
// (cpu, memory, NICs, labels, restart) does not change what runs as root.
func sameContainerImage(rec corrosion.ContainerRecord, old corrosion.ContainerCreateSpec, d *compose.VMDef) bool {
	if rec.Image != d.Image {
		return false
	}
	if old.Template == "" {
		return true // a record with no create spec names its image only
	}
	want := corrosion.ContainerCreateSpec{Arch: "amd64"}
	switch {
	case isRootfsTemplate(d.Image):
		want.Template = d.Image
	case d.Kind == compose.WorkloadKindLXC:
		want.Template = "download"
		want.Distro, want.Release, _ = strings.Cut(d.Image, ":")
	default:
		return false
	}
	return old.Template == want.Template && old.Distro == want.Distro && old.Release == want.Release &&
		(old.Arch == "" || old.Arch == want.Arch)
}

// mayChangePrivilegedImage refuses a recreate that runs a new image in a
// privileged or legacy-confined member for a caller who is neither Admin nor
// holds ct.exec on the member (root inside it already).
func (s *Server) mayChangePrivilegedImage(ctx context.Context, name string, rec *corrosion.ContainerRecord, d *compose.VMDef, privileged bool) error {
	if RequireRole(ctx, "admin") == nil {
		return nil
	}
	if err := s.RequirePerm(ctx, ctRBACPathFor(rec.Project, name), "ct.exec", "operator"); err == nil {
		return nil
	}
	what := "legacy-confined"
	if privileged {
		what = "privileged"
	}
	s.audit(ctx, "ct.recreate-security", name,
		fmt.Sprintf("project=%s %s image %q -> %q", rec.Project, what, rec.Image, d.Image), "denied")
	return status.Errorf(codes.PermissionDenied,
		"container %q is %s, and this deploy changes its image from %q to %q, which would run as root on the host; "+
			"that needs the Admin role or ct.exec on it (root inside it already). The member was left as it is: "+
			"deploy it with its current image, ask an Admin to deploy this change, or move it over first with "+
			"lv ct convert --unprivileged --confinement default %s",
		name, what, rec.Image, d.Image, name)
}

// noteKeptMemberSecurity records, as an audit event and a WARN, that a
// recreate carried a privileged or legacy-confined member's mode over for a
// non-Admin deployer, once the new container exists. It is kept rather than
// refused: refusing would newly block a compose update main allowed, and
// dropping the member to unprivileged would break its workload behind the
// deployer's back. The record names the remedy.
func (s *Server) noteKeptMemberSecurity(ctx context.Context, name, project string, privileged bool, confinement string) {
	what := "legacy-confined"
	if privileged {
		what = "privileged"
	}
	slog.Warn("compose recreate kept a container's privilege mode for a non-admin deployer; convert it with lv ct convert --unprivileged --confinement default",
		"container", name, "project", project, "mode", what, "confinement", confinement, "user", callerUsername(ctx))
	s.audit(ctx, "ct.recreate-security", name,
		fmt.Sprintf("project=%s recreate kept %s (privileged=%v confinement=%s) from the replaced member", project, what, privileged, confinement), "ok")
}

// recreatedMember is what a recreate remembers of the container it replaces:
// its create spec and project, whether its security mode is carried over
// (keep: judged by judgeContainerRecreate), and whether that is recorded
// (note: a non-Admin deployer).
type recreatedMember struct {
	spec    corrosion.ContainerCreateSpec
	project string
	keep    bool
	note    bool
}

// inheritRecreatedSecurity applies a recreate's remembered security to req
// when the stack file states none, and returns the context to create with
// and, for a non-Admin deployer whose member's mode is carried over, what
// records that once the create has succeeded (nil otherwise). What may be
// carried over was judged before the delete (judgeContainerRecreate).
func (s *Server) inheritRecreatedSecurity(ctx context.Context, a planner.VMAction, d *compose.VMDef, req *pb.CreateContainerRequest) (context.Context, func(), error) {
	if a.Kind != planner.OpUpdate {
		return ctx, nil, nil
	}
	s.recreateSecMu.Lock()
	m, ok := s.recreateSec[a.VMName]
	delete(s.recreateSec, a.VMName)
	s.recreateSecMu.Unlock()
	if !ok || !m.keep {
		return ctx, nil, nil
	}
	if !d.Privileged && d.Confinement == "" {
		req.Privileged, req.Confinement = recordedSecurity(m.spec)
	}
	var note func()
	if m.note {
		privileged, confinement := req.Privileged, req.Confinement
		note = func() { s.noteKeptMemberSecurity(ctx, a.VMName, m.project, privileged, confinement) }
	}
	return withInheritedSecurity(ctx), note, nil
}
