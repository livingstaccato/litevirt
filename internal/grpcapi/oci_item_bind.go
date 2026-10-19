package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/lxc"
)

// recreatePinKey carries, to a recreate's create, the library item
// generation its judgment pinned (recreatePinnedImage): the create copies
// that generation or nothing.
type recreatePinKey struct{}

type recreatePin struct{ template, gen string }

func withRecreatePin(ctx context.Context, template, gen string) context.Context {
	return context.WithValue(ctx, recreatePinKey{}, &recreatePin{template: template, gen: gen})
}

// createItemCheck is the create's judgment of a library item's rootfs
// path, made where the runtime copies it, under the item's lock
// (lxc.CreateOpts.CheckItem): the item's owner record, which a claim
// writes with the content under the same lock, and, for a recreate whose
// judgment pinned the generation, that generation. unpin drops that
// recreate's pin once the create is over.
func (s *Server) createItemCheck(ctx context.Context, req *pb.CreateContainerRequest) (check func(gen string) error, unpin func()) {
	p, isPath, _ := lxc.TemplatePath(req.Template)
	if !isPath {
		return nil, func() {}
	}
	item := ociLibraryName(p, s.dataDir)
	pin, _ := ctx.Value(recreatePinKey{}).(*recreatePin)
	if pin != nil && pin.template != req.Template {
		pin = nil
	}
	unpin = func() {}
	if pin != nil {
		unpin = func() { lxc.UnpinOCIItem(lxc.BundleDir(p), req.Name) }
	}
	return func(gen string) error {
		if err := s.refuseForeignOCIItem(ctx, item, req.Project, "be created from"); err != nil {
			return err
		}
		if pin != nil && gen != pin.gen {
			s.audit(ctx, "ct.recreate-security", req.Name, "image under "+req.Template+" replaced before the copy", "denied")
			return status.Errorf(codes.PermissionDenied,
				"recreating container %q: it is privileged or legacy-confined, and the image under %q was replaced after the recreate was judged, "+
					"so the create would run another image as root on the host; that needs the Admin role or the ContainerRoot role on it "+
					"(lv role grant ContainerRoot <principal> --path %s)",
				req.Name, req.Template, ctRBACPathFor(req.Project, req.Name))
		}
		return nil
	}, unpin
}

// ociOwnerWriteHook is a test seam: it runs just before a pull records the
// owner of library item, under the item's locks.
var ociOwnerWriteHook = func(item, project string) {}
