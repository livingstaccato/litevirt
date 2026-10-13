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
	// imageOpImport is lv image import.
	imageOpImport imageOp = "import"
	// imageOpCopy is a peer's push into this host: lv image push, an
	// auto-pull for a VM create, the reconciler's heal (both autoPullImage).
	imageOpCopy imageOp = "copy from a peer"
	// imageOpPull is lv image pull.
	imageOpPull imageOp = "pull"
	// imageOpBuild is lv image build (forwarded to the VM's host as the
	// operator's own request).
	imageOpBuild imageOp = "build"
	// imageOpCompose is a compose deploy's download of an image it names.
	imageOpCompose imageOp = "compose download"
)

// revives reports whether op may revive a deleted image's catalog row: lv
// image import, pull, build and a compose deploy's download do, as each did
// on main (review round 2, which corrects round 1's I-1); a build forwarded to
// the VM's host does too. lv gitops calls DeployStack in a background loop,
// so a compose file it deploys that still declares a deleted image downloads
// it and makes it live again. A copy from a peer never revives (review round
// 1, I-1): lv image push, a VM create's auto-pull and the reconciler's heal.
func (o imageOp) revives() bool { return o != imageOpCopy }

// imageCopyMDKey marks an ImportImage stream as a peer's copy (PushImage):
// lv image push, an auto-pull, a heal. Its absence does not make a peer's
// call an import (isImageCopy), so a push from an earlier build is a copy too.
const imageCopyMDKey = "x-litevirt-image-copy"

// isImageCopy reports whether the ImportImage on ctx is a copy, not an
// operator's import: PushImage marks its stream, and any call that arrives
// over a peer's transport is one, whether it runs as the peer or as an
// operator the peer relays (forwarded identity) — PushImage is the only
// thing that relays ImportImage, and an earlier build's carries no mark
// (review re-review 1, R-m2). An operator's own import reaches the host
// directly.
func isImageCopy(ctx context.Context) bool {
	if md, ok := metadata.FromIncomingContext(ctx); ok && len(md.Get(imageCopyMDKey)) > 0 {
		return true
	}
	return callerPrincipalKind(ctx) == principalKindPeer
}

// imageTicket is what an image operation takes as it begins (imageOpStart)
// and records with: the catalog row's deleted_at then ("" when live or
// absent), and the clocks its records are written at, reserved then.
type imageTicket struct {
	deleted string
	clocks  []corrosion.ImageClocks // one pair per record; a pull records twice
}

// next is the next record's reserved clocks.
func (t *imageTicket) next() (corrosion.ImageClocks, bool) {
	if len(t.clocks) == 0 {
		return corrosion.ImageClocks{}, false
	}
	c := t.clocks[0]
	t.clocks = t.clocks[1:]
	return c, true
}

// imageTicketRecords is how many records one operation writes at most: a pull
// writes its "pulling" row as it begins and its copy's row at the end.
const imageTicketRecords = 2

// imageOpStart reads, as op begins, image name's catalog row, and reserves
// the clocks op's records are written at (review re-review 1, R-m1): a delete
// stamped after this, on any host, is newer than every record op writes, so it
// wins on every replica even if it reaches this host only after op records.
// A copy from a peer refuses a name that already reads deleted here, so
// nothing is streamed for it.
func (s *Server) imageOpStart(ctx context.Context, name string, op imageOp) (*imageTicket, error) {
	d, err := corrosion.ImageDeletedAt(ctx, s.db, name)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "read image %q's catalog record: %v", name, err)
	}
	if d != "" && !op.revives() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"image %q was deleted (lv image rm, at %s): a %s does not bring it back; lv image import, pull or build of %s does",
			name, d, op, name)
	}
	t := &imageTicket{deleted: d}
	for range imageTicketRecords {
		t.clocks = append(t.clocks, corrosion.ReserveImageClocks(s.db))
	}
	return t, nil
}

// imageRecordRetries bounds how often an operator's record is written again
// at fresh clocks when a newer record of the image keeps landing first.
const imageRecordRetries = 3

// recordImage writes, for op, image name's catalog row and this host's
// image_hosts row, once op has published its copy here. t is what op took as
// it began (imageOpStart).
//
//   - A copy from a peer refuses a row that reads deleted:
//     FailedPrecondition.
//   - An operator's operation (import, pull, build, compose download) writes
//     the reviving catalog row; a copy the plain one.
//   - The catalog row is written at the clocks reserved as op began, and only
//     if, in the same transaction, it still reads as it did then
//     (corrosion.RecordImage). A delete applied here since op began wins:
//     nothing is recorded (Aborted), and the copy is left for lv image prune.
//     A delete stamped after op began that reaches this host only later still
//     wins everywhere, through LWW and anti-entropy. A delete stamped before
//     op began that has not reached this host when op records does not: the
//     record is newer (corrosion.RecordImage).
//   - A newer live record of the image here (another copy, pull or import of
//     it, begun after op) is not a delete (re-review 2, I-1). A copy then
//     leaves the catalog row to it and records only this host's row. An
//     operator's operation writes its row again at fresh clocks, so the newest
//     operator content is the one recorded; in that case alone a delete stamped
//     after op began that has not reached this host by then loses to it.
//   - This host's row is written at the clock reserved with the catalog row's,
//     unless a write to it here is newer (corrosion.RecordImageHost).
func (s *Server) recordImage(ctx context.Context, op imageOp, t *imageTicket, img corrosion.ImageRecord, ih corrosion.ImageHostRecord) error {
	if t == nil {
		var err error
		if t, err = s.imageOpStart(ctx, img.Name, op); err != nil {
			return err
		}
	}
	if hook := s.imagePrune.recordHook.Load(); hook != nil {
		clock := ""
		if len(t.clocks) > 0 {
			clock = t.clocks[0].Insert
		}
		(*hook)(img.Name, clock)
	}
	if t.deleted != "" && !op.revives() {
		return status.Errorf(codes.FailedPrecondition,
			"image %q was deleted (lv image rm, at %s): a %s does not bring it back; lv image import, pull or build of %s does",
			img.Name, t.deleted, op, img.Name)
	}
	clk, ok := t.next()
	if !ok {
		return status.Errorf(codes.Internal, "image %q: this %s has no reserved record clocks left", img.Name, op)
	}
	outcome := corrosion.ImageRecordWritten
	for attempt := 0; ; attempt++ {
		var err error
		outcome, err = corrosion.RecordImage(ctx, s.db, img, op.revives(), t.deleted, clk)
		if err != nil {
			s.noteStateWriteFail(corrosion.OpImage, err)
			return status.Errorf(codes.Internal, "record image: %v", err)
		}
		if outcome != corrosion.ImageRecordSuperseded || !op.revives() || attempt >= imageRecordRetries {
			break
		}
		clk = corrosion.ReserveImageClocks(s.db) // an operator's content is the newest: record it again, now
	}
	switch outcome {
	case corrosion.ImageRecordDeleted:
		now, _ := corrosion.ImageDeletedAt(ctx, s.db, img.Name)
		return status.Errorf(codes.Aborted,
			"image %q was deleted (lv image rm, at %s) while this %s ran: nothing is recorded, and the copy here is left for lv image prune",
			img.Name, now, op)
	case corrosion.ImageRecordSuperseded:
		if op.revives() {
			return status.Errorf(codes.Aborted,
				"image %q's catalog record kept changing while this %s ran: nothing is recorded, and the copy here is left for lv image prune",
				img.Name, op)
		}
		// A copy: the newer record describes the image; this host holds a copy.
	}
	reviving := t.deleted != ""
	if op.revives() {
		t.deleted = "" // this record made the row live: the operation's next record begins from it
	}
	if err := s.recordImageHost(ctx, ih, reviving, clk.Host); err != nil {
		s.noteStateWriteFail(corrosion.OpImageHost, err)
		return status.Errorf(codes.Internal, "record image host: %v", err)
	}
	return nil
}

// recordImageHost writes this host's image_hosts row for a copy it holds.
//
// It is written at, the clock the operation reserved as it began, unless a
// write to the row here is newer (corrosion.RecordImageHost).
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
// delete has not reached this host, where the delete is older than this row's
// clock, leaves this row live under a deleted catalog row. That is a delete
// stamped before the operation began, or, when the row was written here after
// that (a pull's progress, or a record written again at fresh clocks), before
// that write. lv image ls does not list the image, and GetImageHosts names
// no host of a deleted image, so no auto-pull, compose deploy or placement
// counts this one. The row and its file stay until lv image rm runs again
// (the prune keeps a file published within its margin of the delete).
func (s *Server) recordImageHost(ctx context.Context, ih corrosion.ImageHostRecord, reviving bool, at string) error {
	if s.ReleaseTokenLatched() {
		return corrosion.RecordImageHost(ctx, s.db, ih, true, at)
	}
	if reviving {
		slog.Warn("image: this host's copy of an image imported, pulled or built again under a deleted image's name is recorded, "+
			"but the record reads deleted on the other hosts, and on this one once anti-entropy runs, until the cluster "+
			"upgrade finishes (lv cluster upgrade-status): no peer pulls the copy and placement does not see it; "+
			"import it again after the upgrade",
			"image", ih.ImageName, "host", ih.HostName)
	}
	return corrosion.RecordImageHost(ctx, s.db, ih, false, at)
}
