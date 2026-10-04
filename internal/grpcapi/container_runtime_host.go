package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// refuseNoContainerRuntime refuses a container create or migrate onto host
// when its record does not say it runs containers: corrosion.HostRunsContainers,
// the rule placement applies, so only litevirt.lxc=true qualifies and a host
// with no label has no runtime. `lv ct create` with no host runs on the node
// that took the request and `lv ct migrate` names its target, so neither went
// through placement: both went ahead and failed late with "lxc-create not
// found", a migrate after it had already stopped the source.
//
// A host with no row here decides nothing (the caller's own checks name it);
// a read that fails refuses, since nothing has been done yet.
func (s *Server) refuseNoContainerRuntime(ctx context.Context, host string) error {
	h, err := corrosion.GetHost(ctx, s.db, host)
	if err != nil {
		return status.Errorf(codes.Unavailable, "read host %q to check it runs containers: %v", host, err)
	}
	if h == nil || corrosion.HostRunsContainers(*h) {
		return nil
	}
	got := "not set"
	if v, ok := h.Labels[corrosion.LabelLXCCapable]; ok {
		got = "\"" + v + "\""
	}
	return status.Errorf(codes.FailedPrecondition,
		"host %q runs no containers: its %s label is %s, not \"true\" (its daemon found no lxc runtime); "+
			"choose a host labelled %s=true (`lv host label ls <host>` shows a host's labels)",
		host, corrosion.LabelLXCCapable, got, corrosion.LabelLXCCapable)
}
