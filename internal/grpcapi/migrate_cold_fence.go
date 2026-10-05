package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	holder := coldMoveLockHolder(s.hostName)
	heldBy, err := health.TryVMStartLease(ctx, s.db, holder, vmName, time.Now())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable,
			"cannot take the start lease of VM %q, so it is not migrated cold: %v", vmName, err)
	}
	if heldBy != holder {
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q is being started on this cluster (its start lease is held by %s); migrate it once that is done", vmName, heldBy)
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
					slog.Warn("cold migration: could not renew the VM's start lease", "vm", vmName, "held_by", h, "error", rerr)
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
