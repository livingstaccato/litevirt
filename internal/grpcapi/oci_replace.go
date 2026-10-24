package grpcapi

import (
	"context"
	"path/filepath"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/lxc"
)

// A pull into an OCI library item that already holds an unpacked image
// replaces the image every later create and recreate from that item runs,
// in every project the item serves. It is therefore an Admin's claim only:
// an Admin's lv ct pull --project over an existing item. Any other pull over
// an existing item is refused, as umoci refused it before. A replace is also
// refused while a container uses the item's rootfs in place (one an earlier
// release created from it), and a member built from the item's earlier
// content sees the replaced content as a new image (TemplateGen).

// ociReplaceMDKey marks a forwarded pull as an Admin's claim, judged on the
// entry host where the caller is real. Honoured from an authenticated peer
// only; a pull without it over an existing item is refused.
const ociReplaceMDKey = "x-litevirt-oci-replace-bin"

// ociAdminClaim reports whether req is an Admin's claim: the Admin role and
// an explicit --project, judged where the caller is real.
func ociAdminClaim(ctx context.Context, req *pb.PullOCIImageRequest) bool {
	return req.Project != "" && RequireRole(ctx, "admin") == nil
}

// ociReplaceOutgoing is the context a pull is forwarded with: the
// owner-strict marker, and the claim marker for an Admin's claim.
func (s *Server) ociReplaceOutgoing(ctx context.Context, req *pb.PullOCIImageRequest) context.Context {
	out := s.ownerStrictOutgoing(ctx)
	if !s.isRemotePeer(ctx) && ociAdminClaim(ctx, req) {
		out = metadata.AppendToOutgoingContext(out, ociReplaceMDKey, "1")
	}
	return out
}

// ociReplaceAllowed reports whether this pull may replace an existing item.
func (s *Server) ociReplaceAllowed(ctx context.Context, req *pb.PullOCIImageRequest) bool {
	if s.isRemotePeer(ctx) {
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok {
			return false
		}
		v := md.Get(ociReplaceMDKey)
		return len(v) > 0 && v[0] == "1" && req.Project != ""
	}
	return ociAdminClaim(ctx, req)
}

// judgeOCIReplace decides, on the host that unpacks, whether the pull
// replaces an existing item: false when Dest holds no unpacked image. Over
// an existing one it is refused unless it is an Admin's claim and no
// container on this host uses the item's rootfs in place.
func (s *Server) judgeOCIReplace(ctx context.Context, req *pb.PullOCIImageRequest) (bool, error) {
	exists, err := lxc.IsBundle(req.Dest)
	if err != nil {
		return false, status.Errorf(codes.Internal, "pull oci: %v", err)
	}
	if !exists {
		return false, nil
	}
	if !s.ociReplaceAllowed(ctx, req) {
		s.audit(ctx, "image.pull", filepath.Base(req.Dest), "replace refused: not an admin claim", "denied")
		return false, ociItemExistsErr(req.Dest, s.hostName)
	}
	refs, err := s.containerRuntime.RootfsReferences(ctx, req.Dest)
	if err != nil {
		return false, status.Errorf(codes.FailedPrecondition,
			"OCI image %q on %s: cannot tell whether a container uses it in place (%v), so it was not replaced", filepath.Base(req.Dest), s.hostName, err)
	}
	if len(refs) > 0 {
		s.audit(ctx, "image.pull", filepath.Base(req.Dest), "replace refused: in use by "+strings.Join(refs, ","), "denied")
		return false, status.Errorf(codes.FailedPrecondition,
			"OCI image %q on %s is the root filesystem of container(s) %s, created from it in place by an earlier release; "+
				"it was not replaced, since that would remove their files. Pull into another name",
			filepath.Base(req.Dest), s.hostName, strings.Join(refs, ", "))
	}
	return true, nil
}

func ociItemExistsErr(dest, host string) error {
	return status.Errorf(codes.FailedPrecondition,
		"OCI image %q already exists on %s; pull into another name. Replacing it changes the image every container "+
			"built from it is recreated from, so only an Admin may, by claiming it for a project (lv ct pull --project)",
		filepath.Base(dest), host)
}
