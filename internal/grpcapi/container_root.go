package grpcapi

import (
	"context"

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
