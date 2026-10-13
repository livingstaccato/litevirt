package grpcapi

import (
	"context"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// imageOp names an operation that leaves a copy of an image on this host and
// records it in the catalog (images) and in this host's image_hosts row.
type imageOp string

const (
	// imageOpImport is lv image import by an operator: the one operation that
	// may bring a deleted image's name back (lab 2 F-1).
	imageOpImport imageOp = "import"
	// imageOpCopy is a peer's push into this host: lv image push, an
	// auto-pull for a VM create, the reconciler's heal (both autoPullImage).
	imageOpCopy imageOp = "copy from a peer"
	// imageOpPull is lv image pull.
	imageOpPull imageOp = "pull"
	// imageOpBuild is lv image build.
	imageOpBuild imageOp = "build"
	// imageOpCompose is a compose deploy's download of an image it names.
	imageOpCompose imageOp = "compose download"
)

// revives reports whether op may revive a deleted image's catalog row. Only
// an operator's import does (review round 1, I-1): a copy, pull or build that
// finishes after lv image rm must never undo the delete — an image is removed
// for a reason, a vulnerable base among them.
func (o imageOp) revives() bool { return o == imageOpImport }

// imageCopyMDKey marks an ImportImage stream as a peer's copy (PushImage):
// lv image push, an auto-pull, a heal. Its absence does not make a bare peer
// an operator (isImageCopy), so a push from an earlier build is a copy too.
const imageCopyMDKey = "x-litevirt-image-copy"

// isImageCopy reports whether the ImportImage on ctx is a copy, not an
// operator's import: PushImage marks its stream, and a peer's own identity
// (its host certificate, no forwarded user) is a system continuation —
// an earlier build's push carries no mark. An operator's import relayed by a
// peer authenticates as that operator and stays an import.
func isImageCopy(ctx context.Context) bool {
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get(imageCopyMDKey)) > 0 {
		return true
	}
	return callerPrincipalKind(ctx) == principalKindPeer && callerAuthMethod(ctx) == authMethodMTLS
}

// imageOpStart reads, as op begins, image name's catalog row: its deleted_at
// ("" when live or absent), which recordImage compares against at the end. An
// op that may not revive refuses a name that already reads deleted here, so
// nothing is downloaded or built for it.
func (s *Server) imageOpStart(ctx context.Context, name string, op imageOp) (string, error) {
	d, err := corrosion.ImageDeletedAt(ctx, s.db, name)
	if err != nil {
		return "", status.Errorf(codes.Internal, "read image %q's catalog record: %v", name, err)
	}
	if d != "" && !op.revives() {
		return d, status.Errorf(codes.FailedPrecondition,
			"image %q was deleted (lv image rm, at %s): a %s does not bring it back; lv image import <file> --name %s does",
			name, d, op, name)
	}
	return d, nil
}

// recordImage writes, for op, image name's catalog row and this host's
// image_hosts row, once op has published its copy here. startDeleted is the
// row's deleted_at as op began (imageOpStart).
//
//   - A row deleted since op began (lv image rm while it ran, here or applied
//     from a peer) records nothing: Aborted. The copy is left for lv image
//     prune.
//   - A row that reads deleted refuses every op but an operator's import:
//     FailedPrecondition.
//   - An operator's import writes the reviving catalog row
//     (corrosion.ReviveImage); every other op the plain one, so a delete this
//     host has not applied yet still wins everywhere through LWW and
//     anti-entropy.
func (s *Server) recordImage(ctx context.Context, op imageOp, startDeleted string, img corrosion.ImageRecord, ih corrosion.ImageHostRecord) error {
	if hook := s.imagePrune.recordHook.Load(); hook != nil {
		(*hook)(img.Name)
	}
	now, err := corrosion.ImageDeletedAt(ctx, s.db, img.Name)
	if err != nil {
		return status.Errorf(codes.Internal, "read image %q's catalog record: %v", img.Name, err)
	}
	switch {
	case now != "" && now != startDeleted:
		return status.Errorf(codes.Aborted,
			"image %q was deleted (lv image rm, at %s) while this %s ran: nothing is recorded, and the copy here is left for lv image prune",
			img.Name, now, op)
	case now != "" && !op.revives():
		return status.Errorf(codes.FailedPrecondition,
			"image %q was deleted (lv image rm, at %s): a %s does not bring it back; lv image import <file> --name %s does",
			img.Name, now, op, img.Name)
	}
	write := corrosion.InsertImage
	if op.revives() {
		write = corrosion.ReviveImage
	}
	if err := write(ctx, s.db, img); err != nil {
		s.noteStateWriteFail(corrosion.OpImage, err)
		return status.Errorf(codes.Internal, "record image: %v", err)
	}
	if err := s.recordImageHost(ctx, ih, now != ""); err != nil {
		s.noteStateWriteFail(corrosion.OpImageHost, err)
		return status.Errorf(codes.Internal, "record image host: %v", err)
	}
	return nil
}

// recordImageHost writes this host's image_hosts row for a copy it holds.
//
// Once the release token has durably latched here it is always the reviving
// form (corrosion.ReviveImageHost), whatever the row reads here (review round
// 1, I-2): lv image rm on another host may not have reached this one yet, and
// the plain insert would leave every peer's tombstone in place, after which
// anti-entropy deletes this host's row too (lab 2 F-1) — no peer pulls the
// copy and placement does not see it. After the latch the shape is known to
// every recipient, and it is plain LWW: a later delete still wins.
//
// Before the latch it is the plain insert. Over a deleted row (reviving: the
// catalog row read deleted, so this is an import under a deleted name) the
// gap is logged: the image lists, but the copy's record reads deleted on every
// host until it is imported again after the upgrade.
//
// One race is left to the catalog row: a copy recorded while the image's
// delete has not reached this host leaves this row live under a deleted
// catalog row. Nothing lists the image; its file stays until lv image rm runs
// again (the prune keeps a file published after the delete).
func (s *Server) recordImageHost(ctx context.Context, ih corrosion.ImageHostRecord, reviving bool) error {
	if s.ReleaseTokenLatched() {
		return corrosion.ReviveImageHost(ctx, s.db, ih)
	}
	if reviving {
		slog.Warn("image: this host's copy of an image imported again under a deleted image's name is recorded, "+
			"but the record reads deleted on the other hosts, and on this one once anti-entropy runs, until the cluster "+
			"upgrade finishes (lv cluster upgrade-status): no peer pulls the copy and placement does not see it; "+
			"import it again after the upgrade",
			"image", ih.ImageName, "host", ih.HostName)
	}
	return corrosion.InsertImageHost(ctx, s.db, ih)
}
