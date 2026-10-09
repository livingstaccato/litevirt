package grpcapi

import (
	"context"

	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/lxc"
)

// A compose recreate deletes its member and then creates it again. The
// create's host-side checks — the protected-place check of its template
// (checkContainerTemplate) and the OCI image-owner check
// (refuseForeignOCIItem) — read the disk of the host the member lives on.
// When the deploy entered on that host the recreate judgment runs them
// before the delete (judgeContainerRecreate). When it entered on another
// host, the delete forwarded to the member's host carries the recreate's
// template and project, and that host runs the same checks on its own disk
// before it deletes anything (recreateDeleteCheck): a recreate whose create
// would be refused is refused at its delete, and the member is kept.
//
// The metadata is honoured only from an authenticated cluster peer
// (isRemotePeer, as for the owner-strict marker): a client cannot set it,
// and a delete without it is the plain delete it always was. A target that
// predates it ignores it, and behaves as before (the checks at the create).
const (
	recreateTemplateMDKey = "x-litevirt-recreate-template-bin"
	recreateProjectMDKey  = "x-litevirt-recreate-project-bin"
)

// recreatePreflight is the create a recreate's delete is followed by, as far
// as the member's host needs it to judge that create before the delete.
type recreatePreflight struct {
	template, project string
}

type recreatePreflightKey struct{}

// withRecreatePreflight hands pf to the delete of the recreate it belongs to.
// In-process only; DeleteContainer's forward turns it into peer metadata.
func withRecreatePreflight(ctx context.Context, pf *recreatePreflight) context.Context {
	if pf == nil {
		return ctx
	}
	return context.WithValue(ctx, recreatePreflightKey{}, pf)
}

// recreatePreflightOutgoing is the context a forwarded container delete is
// sent with: for a recreate's delete, its preflight and the owner-strict
// marker the create's owner check needs on the target; otherwise ctx as is.
func (s *Server) recreatePreflightOutgoing(ctx context.Context) context.Context {
	pf, _ := ctx.Value(recreatePreflightKey{}).(*recreatePreflight)
	if pf == nil {
		return ctx
	}
	ctx = s.ownerStrictOutgoing(ctx)
	return metadata.AppendToOutgoingContext(ctx, recreateTemplateMDKey, pf.template, recreateProjectMDKey, pf.project)
}

// recreatePreflightIncoming is the preflight a forwarded recreate delete
// carries, from an authenticated peer only.
func (s *Server) recreatePreflightIncoming(ctx context.Context) *recreatePreflight {
	if !s.isRemotePeer(ctx) {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil
	}
	t := md.Get(recreateTemplateMDKey)
	if len(t) == 0 {
		return nil
	}
	pf := &recreatePreflight{template: t[0]}
	if p := md.Get(recreateProjectMDKey); len(p) > 0 {
		pf.project = p[0]
	}
	return pf
}

// recreateDeleteCheck runs, on the member's host and before its delete, the
// host-side checks the recreate's create will run: a delete whose create
// would be refused is refused, and the member is left as it is.
func (s *Server) recreateDeleteCheck(ctx context.Context, name string) error {
	pf := s.recreatePreflightIncoming(ctx)
	if pf == nil {
		return nil
	}
	if err := s.recreateHostChecks(ctx, pf.template, pf.project, name); err != nil {
		s.audit(ctx, "ct.delete", name, "recreate of template="+pf.template, "denied")
		return err
	}
	return nil
}

// recreateHostChecks is the create's host-side template checks for a
// recreate of member name, run on the host that holds the member, through
// the create's own functions on the create's own arguments: the protected-
// place check, and the image-owner check (an ownerless item, or one the
// create's project owns, passes as on main; another project's is refused).
// No grant skips the owner check: library items and their owner records are
// per host, so the template string a member recorded does not make the item
// under it the member's.
func (s *Server) recreateHostChecks(ctx context.Context, template, project, name string) error {
	if err := s.checkContainerTemplate(template, name); err != nil {
		return status.Errorf(status.Code(err), "recreating container %q: %s; the member was left as it is", name, status.Convert(err).Message())
	}
	p, isPath, _ := lxc.TemplatePath(template)
	if !isPath {
		return nil
	}
	item := ociLibraryName(p, s.dataDir)
	if err := s.refuseForeignOCIItem(ctx, item, project, "be created from"); err != nil {
		if _, rerr := s.readOCIOwner(item); rerr != nil {
			return status.Errorf(status.Code(err),
				"recreating container %q on %s: %s, so the item cannot be shown to be this member's project's or no project's; the member was left as it is",
				name, s.hostName, status.Convert(err).Message())
		}
		return status.Errorf(status.Code(err),
			"recreating container %q: %s; the item belongs to that project (an Admin claimed it for the project, or the project pulled it on %s), so a redeploy by a caller outside it needs the Admin role; the member was left as it is",
			name, status.Convert(err).Message(), s.hostName)
	}
	return nil
}
