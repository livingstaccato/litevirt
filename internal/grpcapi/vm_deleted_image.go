package grpcapi

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// refuseDeletedImage refuses a create of VM vmName from image img when img's
// catalog row is deleted (lv image rm). A host keeps a deleted image's file
// a while — within the delete's margin, and while a VM records the image —
// and a create that found it built on it with no pull, so a deleted image
// was usable by name (lab 2). A name the catalog has never recorded is not a
// deleted one, and an import or pull of the name revives it.
//
// A re-create of vmName (a rebuild, a rolling recreate, a deploy update: the
// create carries the VM it replaces) is not refused: it held the image from
// before its teardown (holdImage), so an lv image rm that landed since is
// one it began before, and refusing it now would lose the VM it tore down.
//
// The caller holds the image (holdImage): a delete that lands after this
// check finds the create in flight and keeps the file for it.
func (s *Server) refuseDeletedImage(ctx context.Context, vmName, img string) error {
	if _, recreate := replacedRowFor(ctx, vmName); recreate {
		return nil
	}
	deletedAt, err := corrosion.ImageDeletedAt(ctx, s.db, img)
	if err != nil {
		return status.Errorf(codes.Internal, "image %q: read the image catalog: %v", img, err)
	}
	if deletedAt == "" {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"image %q was deleted (lv image rm, at %s) and cannot be used; to use it again, re-import it (lv image import) or pull it (lv image pull)",
		img, deletedAt)
}
