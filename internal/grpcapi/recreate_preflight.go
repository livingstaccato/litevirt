package grpcapi

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/lxc"
	"github.com/litevirt/litevirt/internal/safename"
)

// A compose recreate deletes its member and then creates it again. The
// create's host-side checks — the protected-place check of its template
// (checkContainerTemplate), the OCI image-owner check (refuseForeignOCIItem),
// and the fetch of the image it is built from (FetchContainerImage) — read
// the disk, or reach the image server, of the host the member lives on.
// When the deploy entered on that host the recreate judgment runs them
// before the delete (judgeContainerRecreate). When it entered on another
// host, the delete forwarded to the member's host carries the recreate's
// template, project and download image, and that host runs the same checks,
// and the fetch, before it deletes anything (recreateDeleteCheck): a
// recreate whose create would be refused, or whose image it cannot fetch, is
// refused at its delete, and the member is kept.
//
// The metadata is honoured only from an authenticated cluster peer
// (isRemotePeer, as for the owner-strict marker): a client cannot set it,
// and a delete without it is the plain delete it always was. A target that
// predates it ignores it, and behaves as before (the checks at the create).
const (
	recreateTemplateMDKey = "x-litevirt-recreate-template-bin"
	recreateProjectMDKey  = "x-litevirt-recreate-project-bin"
	recreateDistroMDKey   = "x-litevirt-recreate-distro-bin"
	recreateReleaseMDKey  = "x-litevirt-recreate-release-bin"
	recreateArchMDKey     = "x-litevirt-recreate-arch-bin"
	// recreatePinnedMDKey carries the item generation a privileged or
	// legacy member was built from, for a deployer who may not change its
	// image: "1:<gen>" (gen may be empty).
	recreatePinnedMDKey = "x-litevirt-recreate-pinned-gen-bin"
)

// recreatePreflight is the create a recreate's delete is followed by, as far
// as the member's host needs it to judge that create before the delete.
type recreatePreflight struct {
	template, project string
	// distro, release and arch are the download template's image.
	distro, release, arch string
	// pinned says the deployer may not change the member's image (a
	// privileged or legacy member, and neither Admin nor ContainerRoot), so
	// the rootfs path's content must still be generation pinGen.
	pinned bool
	pinGen string
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
	ctx = metadata.AppendToOutgoingContext(ctx, recreateTemplateMDKey, pf.template, recreateProjectMDKey, pf.project,
		recreateDistroMDKey, pf.distro, recreateReleaseMDKey, pf.release, recreateArchMDKey, pf.arch)
	if pf.pinned {
		ctx = metadata.AppendToOutgoingContext(ctx, recreatePinnedMDKey, "1:"+pf.pinGen)
	}
	return ctx
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
	first := func(k string) string {
		if v := md.Get(k); len(v) > 0 {
			return v[0]
		}
		return ""
	}
	pf := &recreatePreflight{
		template: t[0], project: first(recreateProjectMDKey),
		distro: first(recreateDistroMDKey), release: first(recreateReleaseMDKey), arch: first(recreateArchMDKey),
	}
	if g, ok := strings.CutPrefix(first(recreatePinnedMDKey), "1:"); ok {
		pf.pinned, pf.pinGen = true, g
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
	if err := s.recreateHostChecks(ctx, *pf, name); err != nil {
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
// under it the member's. Then the image the create is built from is fetched
// and verified here (recreateFetchImage).
func (s *Server) recreateHostChecks(ctx context.Context, pf recreatePreflight, name string) error {
	if err := s.recreateTemplateChecks(ctx, pf.template, pf.project, name); err != nil {
		return err
	}
	if err := s.recreatePinnedImage(ctx, pf, name); err != nil {
		return err
	}
	return s.recreateFetchImage(ctx, pf, name)
}

// recreatePinnedImage refuses a pinned recreate (recreatePreflight.pinned)
// whose rootfs path no longer holds the generation the member was built
// from: an Admin's pull replaced the item since, so the recreate would run
// a new image as root, which the deployer may not choose.
func (s *Server) recreatePinnedImage(ctx context.Context, pf recreatePreflight, name string) error {
	if !pf.pinned {
		return nil
	}
	p, isPath, _ := lxc.TemplatePath(pf.template)
	if !isPath {
		return nil
	}
	if cur := lxc.ReadImageGen(lxc.BundleDir(p)); cur != pf.pinGen {
		s.audit(ctx, "ct.recreate-security", name, "image under "+pf.template+" replaced since the member was built", "denied")
		return status.Errorf(codes.PermissionDenied,
			"recreating container %q: it is privileged or legacy-confined, and the image under %q on %s is not the pull it was built from "+
				"(the item was replaced since by a pull over it, or the member was built on another host, whose items are its own), "+
				"so this recreate would run another image as root on the host; that needs the Admin role "+
				"or the ContainerRoot role on it (lv role grant ContainerRoot <principal> --path %s). The member was left as it is",
			name, pf.template, s.hostName, ctRBACPathFor(pf.project, name))
	}
	return nil
}

// recreateFetchImage fetches and verifies, on the member's host and before
// its delete, the image the recreate's create is built from: an image this
// host cannot fetch (a release the image server does not have, a server it
// cannot reach, a rootfs path that is not one here) refuses the recreate,
// and the member is left as it is. A download preflight without its image
// (from an entry host that predates sending it) cannot be fetched here, and
// is left to the create, as before.
func (s *Server) recreateFetchImage(ctx context.Context, pf recreatePreflight, name string) error {
	if pf.template == "" || (pf.template == "download" && pf.distro == "") {
		return nil
	}
	if s.containerRuntime == nil {
		return status.Errorf(codes.Unavailable,
			"recreating container %q: no container runtime on %s to fetch its image; the member was left as it is", name, s.hostName)
	}
	opts := CreateContainerOpts{Name: name, Template: pf.template, Distro: pf.distro, Release: pf.release, Arch: pf.arch}
	if err := s.containerRuntime.FetchContainerImage(ctx, opts); err != nil {
		image := pf.template
		if pf.template == "download" {
			image = pf.distro + ":" + pf.release
		}
		s.audit(ctx, "ct.create", name, "recreate cannot fetch image="+image, "error")
		return status.Errorf(codes.FailedPrecondition,
			"recreating container %q: %s cannot fetch its new image %q: %v; the member was left as it is",
			name, s.hostName, image, err)
	}
	return nil
}

// recreateTemplateChecks is the protected-place and image-owner half of
// recreateHostChecks.
func (s *Server) recreateTemplateChecks(ctx context.Context, template, project, name string) error {
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

// A recreate whose member is on another host runs that host's checks, and
// the fetch of the new image, twice: first as a probe in the judgment, on
// the caller's context, so a caller who gives up during a slow fetch, or a
// refusal, leaves the member as it is before anything is detached; then
// again at the delete, where the fetch finds the image it kept
// (lxc.LxcRunner.FetchImage). The probe rides InspectContainer for the
// member, with the real name and recreateProbeMDKey: a host that knows the
// probe answers it and says so in the recreateProbeMDKey response header;
// a host that predates it serves the plain read InspectContainer always
// was, and its checks run at the delete only, as before. Whatever the
// build, the worst a probe can do is a read.
const recreateProbeMDKey = "x-litevirt-recreate-probe-bin"

// probeRecreateOnMember runs the member host's recreate checks for name
// (pf), before the delete, on ctx.
func (s *Server) probeRecreateOnMember(ctx context.Context, host, name string, pf *recreatePreflight) error {
	c, closer, err := s.dialPeer(ctx, host)
	if err != nil {
		// The delete forwards to the same host, and refuses when it cannot
		// reach it either; its own checks run there.
		return nil
	}
	defer closer()
	out := metadata.AppendToOutgoingContext(s.recreatePreflightOutgoing(withRecreatePreflight(ctx, pf)), recreateProbeMDKey, "1")
	var hdr metadata.MD
	_, err = c.InspectContainer(out, &pb.InspectContainerRequest{Name: name, HostName: host}, grpc.Header(&hdr))
	if len(hdr.Get(recreateProbeMDKey)) == 0 {
		if ctx.Err() != nil {
			return status.Errorf(codes.Canceled, "recreating container %q: %v; the member was left as it is", name, ctx.Err())
		}
		return nil // a host that predates the probe: it checks at the delete
	}
	return err
}

// answerRecreateProbe answers a recreate probe (probeRecreateOnMember) from
// a peer: handled reports whether req was one.
func (s *Server) answerRecreateProbe(ctx context.Context, req *pb.InspectContainerRequest) (handled bool, err error) {
	if !s.isRemotePeer(ctx) {
		return false, nil
	}
	md, _ := metadata.FromIncomingContext(ctx)
	if len(md.Get(recreateProbeMDKey)) == 0 {
		return false, nil
	}
	_ = grpc.SetHeader(ctx, metadata.Pairs(recreateProbeMDKey, "1"))
	if err := safename.ValidateContainerName(req.Name); err != nil {
		return true, status.Errorf(codes.InvalidArgument, "%v", err)
	}
	return true, s.recreateDeleteCheck(ctx, req.Name)
}
