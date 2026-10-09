package grpcapi

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// A cold move copies the disks of a VM whose domain is shut off, and removes
// the source's copies once the handoff commits. Its in-memory VM lock holds
// off this host's RPCs, but not the restart policy (vmcheck) or the
// reconciler: those start a VM under the replicated per-VM start lease
// (health.TryVMStartLease) instead. A `restart: always` VM whose policy window
// elapsed mid-copy was started on the source, the copy read a disk the guest
// was writing, the torn copy was handed off, and the source's disk was then
// unlinked under the running guest.
//
// So a cold move holds the start lease for its whole duration, under its own
// holder name, and re-checks that the domain is shut off right before the
// handoff and again before it touches the source.

// coldMoveLockHolder is a cold move's identity on the per-VM start lease.
// Distinct from the reconciler's and the restart policy's, so neither can
// re-take a lease the move holds.
func coldMoveLockHolder(hostName string) string { return hostName + "/cold-migrate" }

// holdColdMoveStartLease takes the VM's start lease for a cold move and keeps
// it taken until the returned release is called. A lease another start path
// holds refuses the move, as does a lease whose state cannot be read.
func (s *Server) holdColdMoveStartLease(ctx context.Context, vmName string) (release func(), err error) {
	return s.holdStartLease(ctx, coldMoveLockHolder(s.hostName), vmName, "so it is not migrated cold", "migrate it", false)
}

// holdStartLease takes the VM's start lease for holder and keeps it taken,
// renewed, until the returned release is called. A lease another start path
// holds refuses ("<retry> once that is done"), as does a lease whose state
// cannot be read ("..., <notDone>: <err>"). With takeOverStale, a lease
// whose holder is not live (staleStartLease) is taken over instead.
func (s *Server) holdStartLease(ctx context.Context, holder, vmName, notDone, retry string, takeOverStale bool) (release func(), err error) {
	heldBy, err := health.TryVMStartLease(ctx, s.db, holder, vmName, time.Now())
	if err == nil && heldBy != holder && takeOverStale {
		if why := s.staleStartLease(ctx, vmName, heldBy); why != "" {
			slog.Warn("taking over a stale start lease", "vm", vmName, "held_by", heldBy, "why", why, "holder", holder)
			health.ReleaseVMStartLease(ctx, s.db, heldBy, vmName)
			heldBy, err = health.TryVMStartLease(ctx, s.db, holder, vmName, time.Now())
		}
	}
	if err != nil {
		return nil, status.Errorf(codes.Unavailable,
			"cannot take the start lease of VM %q, %s: %v", vmName, notDone, err)
	}
	if heldBy != holder {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is being started on this cluster (its start lease is held by %s); %s once that is done", vmName, heldBy, retry)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(health.VMStartLeaseTTL / 4)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				// Re-taken by its own holder, the lease's expiry moves on. A
				// lease lost to another holder is caught by the re-checks of
				// the domain, which is what the lease protects.
				rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
				if h, rerr := health.TryVMStartLease(rctx, s.db, holder, vmName, time.Now()); rerr != nil || h != holder {
					slog.Warn("could not renew the VM's start lease", "vm", vmName, "holder", holder, "held_by", h, "error", rerr)
				}
				cancel()
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		health.ReleaseVMStartLease(rctx, s.db, holder, vmName)
	}, nil
}

// staleStartLease says why the VM's start lease held by heldBy has no live
// holder behind it, or "" when it may: a lease this host took before this
// daemon started (a run that crashed holding it), or one whose holder's host
// is known to be down: its row says offline or fenced, or it was removed. A
// holder on a host in any other state (active, draining, maintenance, ...),
// a host this replica has no row for yet, a component of this daemon, or
// anything that cannot be read counts as live.
func (s *Server) staleStartLease(ctx context.Context, vmName, heldBy string) string {
	host, _, _ := strings.Cut(heldBy, "/")
	if host == s.hostName {
		if s.startedAt.IsZero() {
			return ""
		}
		h, takenAt, ok, err := health.ReadVMStartLease(ctx, s.db, vmName)
		if err != nil || !ok || h != heldBy || takenAt.IsZero() {
			return ""
		}
		// updated_at has whole seconds: compared with the start's second,
		// a lease taken in this daemon's first second still counts as live.
		if takenAt.Before(s.startedAt.Truncate(time.Second)) {
			return "taken at " + takenAt.Format(time.RFC3339) + ", before this daemon started"
		}
		return ""
	}
	rec, err := corrosion.GetHost(ctx, s.db, host)
	if err != nil {
		return ""
	}
	if rec == nil {
		// No live row: removed (its row tombstoned), or a host whose row has
		// not reached this replica yet. Only the first is known to be gone.
		if removed, rerr := corrosion.HostRemoved(ctx, s.db, host); rerr == nil && removed {
			return "its host " + host + " was removed from the cluster"
		}
		return ""
	}
	// Only a host known to be down: offline or fenced. A draining, upgrading,
	// maintenance, joining or suspect host still runs its daemon, which may
	// hold the lease and run the VM (a draining source's cold move holds it
	// until its handoff is cleaned up), and its lease expires by itself if no
	// one renews it.
	if rec.State == "offline" || rec.State == "fenced" {
		return "its host " + host + " is " + rec.State
	}
	return ""
}

// coldSourceShutOff reports whether the VM's domain here is confirmed shut
// off, as a cold move needs before it copies, hands off, or cleans up. Paused
// counts as active.
func (s *Server) coldSourceShutOff(vmName string) error {
	active, err := s.virt.DomainIsActive(vmName)
	if err != nil {
		return status.Errorf(codes.FailedPrecondition,
			"cannot confirm the domain of VM %q is shut off on %s, so it is not migrated cold: %v", vmName, s.hostName, err)
	}
	if active {
		return status.Errorf(codes.FailedPrecondition,
			"VM %q is recorded stopped, but its domain on %s is active; stop it before migrating it cold", vmName, s.hostName)
	}
	return nil
}

// SetColdMoveAfterHandoffForTest installs the coldMoveAfterHandoff test seam.
func (s *Server) SetColdMoveAfterHandoffForTest(f func(vm string)) { s.coldMoveAfterHandoff = f }
