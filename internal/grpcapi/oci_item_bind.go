package grpcapi

import (
	"context"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/lxc"
)

// recreatePinKey carries, to a recreate's create, the library item
// generation its judgment bound it to (recreatePinnedImage): the create is
// built from the copy of that generation the member's host took before
// the delete, or from the item while it is still that generation.
type recreatePinKey struct{}

type recreatePin struct {
	template, gen string
	any           bool // bound to the generation the fetch found
}

func withRecreatePin(ctx context.Context, template, gen string, any bool) context.Context {
	return context.WithValue(ctx, recreatePinKey{}, &recreatePin{template: template, gen: gen, any: any})
}

// recreateBound reports whether this create is a recreate built from the
// copy of template its member's host took, and judged, before the delete.
func recreateBound(ctx context.Context, template string) bool {
	pin, _ := ctx.Value(recreatePinKey{}).(*recreatePin)
	return pin != nil && pin.template == template
}

// createItemCheck is the create's judgment of a library item's rootfs
// path, made where the runtime copies it, under the item's lock
// (lxc.CreateOpts.CheckItem): the item's owner record, which a claim
// writes with the content. For a recreate bound to a generation it also
// returns that binding (lxc.CreateOpts.Pinned).
func (s *Server) createItemCheck(ctx context.Context, req *pb.CreateContainerRequest) (check func(gen string) error, pinned bool, pinnedGen string, anyGen bool) {
	p, isPath, _ := lxc.TemplatePath(req.Template)
	if !isPath {
		return nil, false, "", false
	}
	item := ociLibraryName(p, s.dataDir)
	if pin, _ := ctx.Value(recreatePinKey{}).(*recreatePin); pin != nil && pin.template == req.Template {
		pinned, pinnedGen, anyGen = true, pin.gen, pin.any
	}
	return func(string) error {
		return s.refuseForeignOCIItem(ctx, item, req.Project, "be created from")
	}, pinned, pinnedGen, anyGen
}

// ociOwnerWriteHook is a test seam: it runs just before a pull records the
// owner of library item, under the item's locks.
var ociOwnerWriteHook = func(item, project string) {}
