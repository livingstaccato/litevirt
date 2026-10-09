package grpcapi

import (
	"context"
	"encoding/json"

	"google.golang.org/grpc/metadata"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/lxc"
)

// A compose recreate's create is authorized on the entry host from the
// recreate's decision (judgeContainerRecreate → recreateDecision.apply): the
// member's privileged/legacy mode it keeps, and the rootfs path it already
// uses. Both are in-process context values. When the member lives on another
// host and that host re-authenticates the forwarded create as the deployer
// (auth.forwarded_identity), it would judge the create without them and
// refuse what the entry allowed — after the delete.
//
// So the forwarded create carries the decision's outcome as peer metadata,
// bound to the exact create it was judged for: the container name, the
// member's host, the image and template. The member's host honours it only
// from an authenticated cluster peer (isRemotePeer, as for the owner-strict
// marker), only for a create that matches the binding, and only for a mode
// no broader than the one recorded in it. The single source of truth stays
// the entry's judgment; the member's host only applies it, to that create.
const recreateInheritMDKey = "x-litevirt-recreate-inherit-bin"

// recreateInherit is a recreate decision's outcome for one create.
type recreateInherit struct {
	Name        string `json:"name"`
	Host        string `json:"host"`
	Image       string `json:"image"`
	Template    string `json:"template"`
	Privileged  bool   `json:"privileged"`
	Confinement string `json:"confinement"`
	// Inherited: the privileged/confinement above are the member's own,
	// kept by the judgment (securityInherited).
	Inherited bool `json:"inherited"`
	// GrantTemplate: the rootfs path the member already uses, granted to
	// the create (recreateTemplateGranted).
	GrantTemplate string `json:"grant_template,omitempty"`
}

type recreateInheritKey struct{}

// withRecreateInherit records, for the create of one recreate, what its
// decision granted, bound to that create (dec.apply).
func withRecreateInherit(ctx context.Context, dec *recreateDecision, req *pb.CreateContainerRequest, inherited bool) context.Context {
	return context.WithValue(ctx, recreateInheritKey{}, &recreateInherit{
		Name: dec.name, Host: dec.host, Image: req.Image, Template: req.Template,
		Privileged: req.Privileged, Confinement: req.Confinement,
		Inherited: inherited, GrantTemplate: dec.template,
	})
}

// recreateInheritOutgoing adds the decision's outcome to a forwarded create
// of exactly the create it was bound to; any other forward goes as it was.
func recreateInheritOutgoing(ctx, octx context.Context, req *pb.CreateContainerRequest) context.Context {
	ri, _ := ctx.Value(recreateInheritKey{}).(*recreateInherit)
	if ri == nil || !ri.binds(req, req.HostName) {
		return octx
	}
	b, err := json.Marshal(ri)
	if err != nil {
		return octx
	}
	return metadata.AppendToOutgoingContext(octx, recreateInheritMDKey, string(b))
}

// binds reports whether ri was judged for req, a create on host, and asks
// for no broader security mode than the one judged.
func (ri *recreateInherit) binds(req *pb.CreateContainerRequest, host string) bool {
	if ri.Name == "" || ri.Name != req.Name || ri.Host == "" || ri.Host != host ||
		ri.Image != req.Image || ri.Template != req.Template {
		return false
	}
	if req.Privileged && !ri.Privileged {
		return false
	}
	if req.Confinement == lxc.ConfinementLegacy && ri.Confinement != lxc.ConfinementLegacy {
		return false
	}
	return true
}

// acceptRecreateInherit applies, on the member's host, the decision a
// forwarding peer judged for this create: the kept mode and the granted
// rootfs path, exactly as the entry's in-process decision does. Only from an
// authenticated peer, only for the create it is bound to (name, this host,
// image, template), and only up to the mode recorded in it.
func (s *Server) acceptRecreateInherit(ctx context.Context, req *pb.CreateContainerRequest) context.Context {
	if !s.isRemotePeer(ctx) {
		return ctx
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ctx
	}
	v := md.Get(recreateInheritMDKey)
	if len(v) == 0 {
		return ctx
	}
	var ri recreateInherit
	if json.Unmarshal([]byte(v[0]), &ri) != nil {
		return ctx
	}
	if (req.HostName != "" && req.HostName != s.hostName) || !ri.binds(req, s.hostName) {
		return ctx
	}
	if ri.GrantTemplate != "" && ri.GrantTemplate == req.Template {
		ctx = context.WithValue(ctx, recreateTemplateKey{}, ri.GrantTemplate)
	}
	if ri.Inherited {
		ctx = withInheritedSecurity(ctx)
	}
	return ctx
}
