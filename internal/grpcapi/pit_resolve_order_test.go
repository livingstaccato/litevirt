package grpcapi

import (
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pitoverlay"
)

// I-2 of the pit-restore review: an admin's discard or forced commit points
// the definition at the disk BEFORE the overlay goes. A repoint that fails
// leaves the overlay where it is (and the VM held), never a definition
// naming a file that no longer exists; a crash between the two leaves the
// overlay beside the disk, assessed by the next heal.

// resolveWebOn resolves web's root overlay as an admin, confirmed.
func (s *Server) resolveWebOn(action string, force bool) (*pb.ResolvePITOverlayResponse, error) {
	return s.ResolvePITOverlay(adminCtx(), &pb.ResolvePITOverlayRequest{
		VmName: "web", DiskName: "root", Action: action, Confirm: true, ForceCommit: force,
	})
}

// Mutation "discard removes, then repoints" — red.
func TestResolvePITOverlay_ADiscardWhoseRepointFailsKeepsTheOverlay(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{commitErr: errors.New("redefine refused")})
	if _, err := s.resolveWebOn("discard", false); err == nil {
		t.Fatal("the discard reported success with the definition not repointed")
	}
	if !pitoverlay.Present(live) || !holdsTheWindowsWrite(t, pitoverlay.Path(live)) {
		t.Fatal("the overlay was removed although the definition could not be pointed at the disk")
	}
}

// Mutation "force-commit commits and removes, then repoints" — red.
func TestResolvePITOverlay_AForcedCommitWhoseRepointFailsKeepsTheOverlay(t *testing.T) {
	s, live := stoppedWithStaleOverlay(t)
	s.SetPointInTimeSnapshotter(&fakePITSnapshotter{commitErr: errors.New("redefine refused")})
	if _, err := s.resolveWebOn("commit", true); err == nil {
		t.Fatal("the forced commit reported success with the definition not repointed")
	}
	if !pitoverlay.Present(live) {
		t.Fatal("the overlay was removed although the definition could not be pointed at the disk")
	}
	if holdsTheWindowsWrite(t, live) {
		t.Fatal("the overlay was committed into the disk although the definition could not be pointed at it")
	}
}

// A crash after the discard's repoint and before the removal: the definition
// is on the disk, the overlay still beside it and assessed — the VM stays
// held — and the discard run again finishes; the VM then starts.
//
// Mutation "discard removes, then repoints" — red.
func TestResolvePITOverlay_ACrashBetweenRepointAndRemovalRecovers(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	type crash struct{}
	prev := resolvePITStep
	resolvePITStep = func(step string) {
		if step == "repointed" {
			panic(crash{})
		}
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(crash); !ok {
					panic(r)
				}
			}
		}()
		_, _ = s.resolveWebOn("discard", false)
	}()
	resolvePITStep = prev

	if on, _ := fake.DomainUsesFile("web", overlay); on {
		t.Fatal("the definition still names the overlay after the repoint")
	}
	if !pitoverlay.Present(live) || !holdsTheWindowsWrite(t, overlay) {
		t.Fatal("the overlay went before the crash point")
	}
	if err := startWeb(t, s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start after a crash mid-discard = %v; want refused, held on the overlay", err)
	}
	if _, err := s.resolveWebOn("discard", false); err != nil {
		t.Fatalf("discard run again: %v", err)
	}
	if pitoverlay.Present(live) {
		t.Fatal("the overlay is still there after the discard")
	}
	if err := startWeb(t, s); err != nil {
		t.Fatalf("start after the discard: %v", err)
	}
}

// Re-review 1, m5: a crash after a forced commit's repoint and before the
// commit leaves the overlay uncommitted beside the disk; the VM stays held,
// and the forced commit run again finishes.
//
// Mutation "force-commit commits, then repoints" — red.
func TestResolvePITOverlay_ACrashBetweenRepointAndForcedCommitRecovers(t *testing.T) {
	s, fake, live := heldOnItsOverlay(t)
	overlay := pitoverlay.Path(live)
	type crash struct{}
	prev := resolvePITStep
	resolvePITStep = func(step string) {
		if step == "repointed" {
			panic(crash{})
		}
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				if _, ok := r.(crash); !ok {
					panic(r)
				}
			}
		}()
		_, _ = s.resolveWebOn("commit", true)
	}()
	resolvePITStep = prev

	if on, _ := fake.DomainUsesFile("web", overlay); on {
		t.Fatal("the definition still names the overlay after the repoint")
	}
	if !pitoverlay.Present(live) || holdsTheWindowsWrite(t, live) {
		t.Fatal("the overlay was committed or removed before the crash point")
	}
	if err := startWeb(t, s); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start after a crash mid-forced-commit = %v; want refused, held", err)
	}
	if _, err := s.resolveWebOn("commit", true); err != nil {
		t.Fatalf("forced commit run again: %v", err)
	}
	if pitoverlay.Present(live) || !holdsTheWindowsWrite(t, live) {
		t.Fatal("after the forced commit the overlay is still there, or its write is not in the disk")
	}
	if err := startWeb(t, s); err != nil {
		t.Fatalf("start after the forced commit: %v", err)
	}
}
