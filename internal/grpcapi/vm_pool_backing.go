package grpcapi

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/qcow2"
	"github.com/litevirt/litevirt/internal/safename"
)

// poolRootDiskBacking returns what a root disk created in a storage pool is
// cloned from. A file-based driver writes it as the overlay's backing file,
// and a bare name there is resolved next to the overlay — inside the pool
// directory, where whoever can upload to the pool can place a file of that
// name (a crafted qcow2 that chains to a host file). So for those drivers it
// is the image store's own file, by absolute path, and that file must be
// standalone. Ceph clones from a named RBD snapshot and keeps its name.
func (s *Server) poolRootDiskBacking(img, driver string) (string, error) {
	if img == "" {
		return "", nil
	}
	if driver == "ceph" {
		return img, nil
	}
	if err := safename.ValidateImageName(img); err != nil {
		return "", status.Errorf(codes.InvalidArgument, "image %q: %v", img, err)
	}
	if s.images == nil {
		return "", status.Errorf(codes.FailedPrecondition, "image %q: no image store on %s", img, s.hostName)
	}
	p := s.images.ImagePath(img)
	if err := qcow2.AssertStandalone(p); err != nil {
		return "", status.Errorf(codes.FailedPrecondition, "image %q cannot back a disk: %v", img, err)
	}
	return p, nil
}
