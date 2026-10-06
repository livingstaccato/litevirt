package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/safename"
)

// SetImageLimits records the daemon's image pull/import bounds (disk-fill +
// SSRF guards). Zero values fall back to the image package defaults;
// blockedCIDRs nil → no URL-pull network deny policy.
func (s *Server) SetImageLimits(maxBytes int64, timeout time.Duration, blockedCIDRs []netip.Prefix) {
	s.imageMaxBytes = maxBytes
	s.imagePullTimeout = timeout
	s.imageBlockedCIDRs = blockedCIDRs
}

// imagePullOptions builds the configured PullOptions (defaults applied inside
// image.Pull when a field is zero). BlockedCIDRs is the opt-in URL-pull network
// deny policy; it does NOT apply to streamed Import/Push (byte-ceiling only).
func (s *Server) imagePullOptions() image.PullOptions {
	return image.PullOptions{Timeout: s.imagePullTimeout, MaxBytes: s.imageMaxBytes, BlockedCIDRs: s.imageBlockedCIDRs}
}

// maxImageBytes returns the effective image byte ceiling for streamed
// import/upload (source-side + target-side guards).
func (s *Server) maxImageBytes() int64 {
	if s.imageMaxBytes > 0 {
		return s.imageMaxBytes
	}
	return image.DefaultMaxImageBytes
}

func (s *Server) PullImage(req *pb.PullImageRequest, stream pb.LiteVirt_PullImageServer) error {
	// Images are a cluster-global library (matching PullOCIImage), so the check
	// is rooted; a project-scoped token can't pull into the shared store.
	if err := s.RequirePerm(stream.Context(), "/", "image.pull", "operator"); err != nil {
		return err
	}
	if err := safename.ValidateImageName(req.Name); err != nil {
		return status.Errorf(codes.InvalidArgument, "%v", err)
	}
	// A re-pull of a name disks are built on is a refresh: the new content is
	// published as a new version for new disks, and the file existing disks
	// are built on is never written over (image.Store.Publish).
	slog.Info("pulling image", "name", req.Name, "url", req.SourceUrl)

	// Insert image + image_host records with "pulling" status so the image
	// is visible in ListImages immediately.
	bgCtx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	// Create the catalog + per-host rows up front (visible in ListImages during the
	// pull). These are not cosmetic: a lost write leaves an image on disk that
	// placement/failover cannot see, so fail closed rather than pull invisibly.
	if err := corrosion.InsertImage(bgCtx, s.db, corrosion.ImageRecord{
		Name:      req.Name,
		Format:    req.Format,
		SourceURL: req.SourceUrl,
	}); err != nil {
		s.noteStateWriteFail(corrosion.OpImage, err)
		return status.Errorf(codes.Internal, "record image: %v", err)
	}
	if err := corrosion.InsertImageHost(bgCtx, s.db, corrosion.ImageHostRecord{
		ImageName: req.Name,
		HostName:  s.hostName,
		Path:      s.images.ImagePath(req.Name),
		Status:    "pulling",
		PulledAt:  now,
	}); err != nil {
		s.noteStateWriteFail(corrosion.OpImageHost, err)
		return status.Errorf(codes.Internal, "record image host: %v", err)
	}

	// Create a progress channel
	progressCh := make(chan image.PullProgress, 10)

	// Start the download in a goroutine. Use a detached context so the
	// pull completes even if the client disconnects (#17).
	errCh := make(chan error, 1)
	go func() {
		pub, pullErr := image.PullPublished(s.images, req.Name, req.SourceUrl, req.Checksum, s.imagePullOptions(), progressCh)
		errCh <- pullErr
		if pullErr != nil {
			slog.Error("image pull failed", "name", req.Name, "error", pullErr)
			if err := corrosion.UpdateImageHostStatus(bgCtx, s.db, req.Name, s.hostName, "error"); err != nil {
				s.noteStateWriteFail(corrosion.OpImageHost, err)
			}
			return
		}
		// Persist final result with a background context — stream ctx may be cancelled.
		s.imagePublished(bgCtx, req.Name, pub)
		if err := s.persistImageRecord(req, pub); err != nil {
			slog.Error("image record persist failed after pull", "name", req.Name, "error", err)
			if uerr := corrosion.UpdateImageHostStatus(bgCtx, s.db, req.Name, s.hostName, "error"); uerr != nil {
				s.noteStateWriteFail(corrosion.OpImageHost, uerr)
			}
		}
	}()

	// Stream progress to client and persist to DB for UI polling.
	// On client disconnect, keep draining the channel so the download
	// goroutine doesn't block on channel writes.
	var lastPersisted float32
	clientGone := false
	for p := range progressCh {
		// Persist progress every ~5% to avoid flooding the DB.
		if p.ProgressPct-lastPersisted >= 5 || p.Status == "complete" {
			corrosion.UpdateImageHostProgress(bgCtx, s.db, req.Name, s.hostName, p.ProgressPct)
			lastPersisted = p.ProgressPct
		}

		if !clientGone {
			if err := stream.Send(&pb.PullProgress{
				HostName:    s.hostName,
				ProgressPct: p.ProgressPct,
				Status:      p.Status,
				Error:       p.Error,
			}); err != nil {
				slog.Info("image pull: client disconnected, pull continues in background", "name", req.Name)
				clientGone = true
			}
		}
	}

	// Check for download error
	if err := <-errCh; err != nil {
		if clientGone {
			return nil // already logged, client won't see the error
		}
		return status.Errorf(codes.Internal, "pull image: %v", err)
	}

	slog.Info("image pulled successfully", "name", req.Name)
	return nil
}

// persistImageRecord writes the image and image_host records after a successful pull.
// The recorded checksum is the published content's own sha256 — what disks
// built on it now are built on — whether or not the request named one.
func (s *Server) persistImageRecord(req *pb.PullImageRequest, pub image.Published) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	path := pub.Path
	if path == "" {
		path = s.images.ImagePath(req.Name)
	}
	var sizeBytes int64
	if _, sz, err := s.images.DiskInfo(path); err == nil {
		sizeBytes = sz
	}

	now := time.Now().UTC().Format(time.RFC3339)
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{
		Name:      req.Name,
		Format:    req.Format,
		SourceURL: req.SourceUrl,
		Checksum:  recordedChecksum(req.Checksum, pub.Digest),
		SizeBytes: sizeBytes,
	}); err != nil {
		s.noteStateWriteFail(corrosion.OpImage, err)
		return fmt.Errorf("persist image record: %w", err)
	}

	if err := corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{
		ImageName: req.Name,
		HostName:  s.hostName,
		Path:      path,
		Status:    "ready",
		PulledAt:  now,
	}); err != nil {
		s.noteStateWriteFail(corrosion.OpImageHost, err)
		return fmt.Errorf("persist image_host record: %w", err)
	}

	slog.Info("image record persisted", "name", req.Name)
	return nil
}

func (s *Server) ListImages(ctx context.Context, _ *emptypb.Empty) (*pb.ListImagesResponse, error) {
	if err := RequireRole(ctx, "viewer"); err != nil {
		return nil, err
	}
	images, err := corrosion.ListImages(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list images: %v", err)
	}

	resp := &pb.ListImagesResponse{}
	for _, img := range images {
		// Get hosts that have this image
		hosts, _ := corrosion.GetImageHosts(ctx, s.db, img.Name)
		var hostNames []string
		imgStatus := "ready"
		var progressPct float32
		for _, h := range hosts {
			hostNames = append(hostNames, h.HostName)
			if h.Status == "pulling" {
				imgStatus = "pulling"
				progressPct = h.ProgressPct
			} else if h.Status == "error" && imgStatus != "pulling" {
				imgStatus = "error"
			}
		}
		if len(hosts) == 0 {
			imgStatus = "ready"
		}

		resp.Images = append(resp.Images, &pb.Image{
			Name:        img.Name,
			Format:      img.Format,
			SourceUrl:   img.SourceURL,
			Checksum:    img.Checksum,
			SizeBytes:   img.SizeBytes,
			Hosts:       hostNames,
			Status:      imgStatus,
			ProgressPct: progressPct,
		})
	}

	return resp, nil
}

func (s *Server) DeleteImage(ctx context.Context, req *pb.DeleteImageRequest) (*emptypb.Empty, error) {
	if err := RequireRole(ctx, "operator"); err != nil {
		return nil, err
	}
	if err := corrosion.DeleteImage(ctx, s.db, req.Name); err != nil {
		return nil, status.Errorf(codes.Internal, "delete image: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// recordedChecksum is the checksum an image record carries: the published
// content's own sha256 when there is one, else what the request declared.
func recordedChecksum(declared, digest string) string {
	if digest != "" {
		return "sha256:" + digest
	}
	return declared
}

// imagePublished follows a publish of image name: a heal is logged, and a
// refresh sweeps the image's older versions nothing is built on.
func (s *Server) imagePublished(ctx context.Context, name string, pub image.Published) {
	for _, f := range pub.Healed {
		slog.Warn("image: a local copy no longer matched its recorded identity and was healed in place with byte-identical content",
			"image", name, "path", f, "sha256", pub.Digest)
	}
	if pub.Superseded == "" {
		return
	}
	slog.Info("image refreshed: new disks use the new version; disks built on the old one keep it",
		"image", name, "current", pub.Path, "superseded", pub.Superseded)
	s.sweepImageVersions(ctx, name, pub.Path, pub.Superseded)
}

// sweepImageVersions removes image name's files that are neither kept (the
// current file, and the one this refresh just superseded — a VM created on
// it a moment ago may not have its disk row yet) nor referenced: no disk row
// on any host names the file, and no disk row is built on the image by name
// (its overlay names one of the image's files, and which one is not
// recorded, so every file is kept). A file a disk is built on is never
// removed.
func (s *Server) sweepImageVersions(ctx context.Context, name string, keep ...string) {
	if s.images == nil {
		return
	}
	byName, err := corrosion.DisksReferencingPath(ctx, s.db, name)
	if err != nil || len(byName) > 0 {
		return
	}
	for _, f := range s.images.ImageFiles(name) {
		if slices.Contains(keep, f) {
			continue
		}
		rows, err := s.diskReferencesAnyHost(ctx, f)
		if err != nil || len(rows) > 0 {
			continue
		}
		if err := s.images.RemoveImageFile(name, f); err != nil {
			slog.Warn("image: sweep of an old version failed", "image", name, "file", f, "error", err)
			continue
		}
		slog.Info("image: removed an old version nothing is built on", "image", name, "file", f)
	}
}
