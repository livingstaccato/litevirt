package grpcapi

import (
	"context"

	"google.golang.org/grpc/metadata"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// rootContainerMode says what makes a container's exec, or a change of its
// image, a host-level grant: "privileged" (no user namespace: root inside is
// root on the host) or "legacy-confined" (AppArmor nesting allowed, the
// template's seccomp and capabilities). "" for an unprivileged container
// with default confinement. A record with no create spec (an earlier
// release's) is privileged and legacy, as toPbContainer reports it.
func rootContainerMode(rec corrosion.ContainerRecord) string {
	privileged, confinement, _ := containerSecurityOf(rec)
	switch {
	case privileged:
		return "privileged"
	case confinement == lxc.ConfinementLegacy:
		return "legacy-confined"
	}
	return ""
}

// requireContainerRoot is the check for exec in, or an image change of, a
// privileged or legacy-confined container: the Admin role, or
// auth.VerbContainerRoot on the container's path (the ContainerRoot role,
// bound there by an Admin). Operator's ct.* does not carry it. Without
// bindings the floor is admin.
func (s *Server) requireContainerRoot(ctx context.Context, rec corrosion.ContainerRecord) error {
	return s.RequirePerm(ctx, ctRBACPathFor(rec.Project, rec.Name), auth.VerbContainerRoot, "admin")
}

// execRootMDKey tells the owner, on a forwarded exec, whether the entry
// host found the caller may exec as root in the container ("1") or not
// ("0"). The owner refuses "0" for a container its own row shows privileged
// or legacy-confined. An entry host that predates it sends nothing, and the
// owner then trusts the entry's judgment, as before.
const execRootMDKey = "x-litevirt-exec-root-bin"

// execRootOutgoing is the context an exec is forwarded with: the entry's
// judgment of the caller (callerMayRoot) for rec.
func (s *Server) execRootOutgoing(ctx context.Context, rec corrosion.ContainerRecord) context.Context {
	v := "0"
	if s.callerMayRoot(ctx, rec) {
		v = "1"
	}
	return metadata.AppendToOutgoingContext(ctx, execRootMDKey, v)
}

// execRootRefused reports, on the owner of a forwarded exec, that the
// entry host found the caller may not exec as root.
func (s *Server) execRootRefused(ctx context.Context) bool {
	if !s.isRemotePeer(ctx) {
		return false
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	v := md.Get(execRootMDKey)
	return len(v) > 0 && v[0] == "0"
}

// callerMayRoot reports whether the caller may run a new image as root in
// rec's container: the Admin role, or requireContainerRoot.
func (s *Server) callerMayRoot(ctx context.Context, rec corrosion.ContainerRecord) bool {
	return RequireRole(ctx, "admin") == nil || s.requireContainerRoot(ctx, rec) == nil
}
