package grpcapi

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A delete waits for the start lease rather than refusing at once.
//
// The holders it can meet with this host's VM lock already held are the
// paths that take the lease without that lock: the reconciler's starts, the
// restart policy, the define of a VM re-keyed here stopped, a claim release,
// and a peer. Each holds it for a start, about a second on the lab, and an
// image pull that outlives the walk budget gives it back. Refusing at once
// made `lv rm` of a crash-looping VM fail intermittently, and `compose down`,
// a rolling recreate and a blue-green cutover do not retry that refusal. Main
// deleted in all of these cases.
//
// So the delete polls for the lease, bounded well inside the two minutes an
// entry host gives a proxied delete, and only then refuses with Aborted,
// naming the holder: the stack teardown retries Aborted. The lock order is
// the VM lock, then the lease, as for a snapshot restore and a cold move, and
// no lease holder takes the VM lock, so the wait cannot deadlock.

// deleteLeaseWaitDefault bounds a delete's wait for the start lease.
const deleteLeaseWaitDefault = 60 * time.Second

// deleteLeasePoll is how often a waiting delete tries the lease again.
const deleteLeasePoll = 250 * time.Millisecond

// SetDeleteLeaseWaitForTest sets how long a delete waits for a start lease
// another holder has.
func (s *Server) SetDeleteLeaseWaitForTest(d time.Duration) { s.deleteLeaseWait = d }

// holdDeleteStartLease takes the VM's start lease for this host's delete and
// keeps it, renewed, until the returned release is called. A lease another
// holder has is waited for, up to the bound; a stale one is taken over. It
// refuses with Aborted (the holder named) when the bound passes, Unavailable
// when the lease cannot be read, and the context's own status when ctx ends
// first. A refusal has taken nothing.
func (s *Server) holdDeleteStartLease(ctx context.Context, vmName string) (func(), error) {
	holder := deleteLockHolder(s.hostName)
	bound := s.deleteLeaseWait
	if bound <= 0 {
		bound = deleteLeaseWaitDefault
	}
	deadline := time.Now().Add(bound)
	logged := ""
	for {
		heldBy, err := s.takeStartLease(ctx, holder, vmName, true)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, status.FromContextError(cerr).Err()
			}
			return nil, status.Errorf(codes.Unavailable,
				"cannot take the start lease of VM %q, so it is not deleted: %v", vmName, err)
		}
		if heldBy == holder {
			if logged != "" {
				slog.Info("delete: took the start lease after waiting for it", "vm", vmName, "was_held_by", logged)
			}
			return s.keepStartLease(ctx, holder, vmName), nil
		}
		if logged != heldBy {
			slog.Info("delete: waiting for the start lease another holder has", "vm", vmName, "held_by", heldBy,
				"bound", bound)
			logged = heldBy
		}
		if !time.Now().Before(deadline) {
			return nil, status.Errorf(codes.Aborted,
				"VM %q is being started: its start lease is still held by %s after waiting %s, so nothing was deleted; "+
					"retry once that start is done", vmName, heldBy, bound)
		}
		t := time.NewTimer(deleteLeasePoll)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, status.FromContextError(ctx.Err()).Err()
		case <-t.C:
		}
	}
}
