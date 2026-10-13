package daemon

import (
	"context"
	"log/slog"
	"time"

	"github.com/litevirt/litevirt/internal/storage"
)

// Nothing the daemon does before its gRPC server serves may wait on storage
// that a network server holds (lab 2 F-1). A stat, open or readdir on a hard
// NFS mount whose server does not answer blocks in the kernel until it
// answers, and a daemon that never serves is, to its peers, a host whose
// port refuses: they count a one-way partition, reach quorum and fence it,
// taking down every VM on it, local disks included. On lab 2 that was the
// startup sweep of staging temps, an os.ReadDir of an nfs pool's mount point.
//
// So each startup step that touches pool or shared storage either runs off
// the start path (startStorageSweeps; the cutover cleanup resume), is waited
// for only up to startupStepBound (awaitStartupStep), or makes its system
// calls under storage.Bounded (statfs, path resolution, the cold migration
// scratch sweep).

// startupStepBound is how long the start path waits for a step that may
// touch storage a network server holds; tests shorten it.
var startupStepBound = 5 * time.Second

// awaitStartupStep runs step and waits for it at most bound. A step still
// running then is left to finish in the background, and the start goes on.
// It reports whether the step finished in time.
func awaitStartupStep(name string, bound time.Duration, step func()) bool {
	done := make(chan struct{})
	go func() {
		defer close(done)
		step()
	}()
	t := time.NewTimer(bound)
	defer t.Stop()
	select {
	case <-done:
		return true
	case <-t.C:
		slog.Warn("startup: a step that touches storage did not finish in time; it goes on in the background and the daemon starts serving (does an NFS or other network server not answer?)",
			"step", name, "waited", bound)
		return false
	}
}

// vmReplaceCleanupRetry is how often a cutover cleanup deferred because its
// storage did not answer is tried again.
var vmReplaceCleanupRetry = 5 * time.Minute

// resumeVMReplaceCleanups resumes the cutover cleanups a previous process
// left, and tries again every retry while one was deferred because storage
// it frees did not answer (storage.IsFSNoAnswer). Any other failure is
// logged and left to the next start, as before.
func resumeVMReplaceCleanups(ctx context.Context, r interface {
	ResumeVMReplaceCleanups(context.Context) error
}, retry time.Duration) {
	for {
		err := r.ResumeVMReplaceCleanups(ctx)
		if err == nil {
			return
		}
		slog.Warn("cutover: resuming journaled cleanups", "error", err)
		if !storage.IsFSNoAnswer(err) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(retry):
		}
	}
}

// startupSweeper is the part of the gRPC server the startup storage sweeps
// need.
type startupSweeper interface {
	SweepStaleStaging(ctx context.Context)
	RunPoolRecordsMarker(ctx context.Context)
}

// startStorageSweeps starts, in the background and in this order, the sweep
// of staging temps a crash left in this host's pool, image and disk
// directories, and then the pool-file records marker. Neither has to finish
// before the daemon serves: the sweep removes only temps older than an hour,
// so it cannot race an operation this daemon starts, and the marker is
// retried periodically anyway. Both read every pool directory of this host,
// any of which may be on an NFS mount whose server does not answer.
func startStorageSweeps(ctx context.Context, s startupSweeper) {
	go func() {
		s.SweepStaleStaging(ctx)
		s.RunPoolRecordsMarker(ctx)
	}()
}
