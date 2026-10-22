package grpcapi

import (
	"log/slog"
	"time"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// MemorySnapshotTuning is this node's memory snapshot configuration
// (memory_snapshot.* in the daemon config). Zero values are the libvirt
// package defaults (DefaultCapturePauseBudget, DefaultCaptureDeadline).
type MemorySnapshotTuning struct {
	// PauseBudget is the longest predicted guest pause a live capture is
	// chosen for.
	PauseBudget time.Duration
	// LiveDeadline bounds a live capture before the guest is suspended to
	// finish it.
	LiveDeadline time.Duration
}

// SetMemorySnapshotTuning sets the memory snapshot tuning; called once at
// daemon start, before the server serves.
func (s *Server) SetMemorySnapshotTuning(t MemorySnapshotTuning) { s.memorySnapshot = t }

// SetCaptureRegistry sets the host's memory snapshot capture registry, which
// the daemon shares with its partition pauser and settle; called before the
// server serves. Without it the server keeps one of its own.
func (s *Server) SetCaptureRegistry(r *lv.CaptureRegistry) {
	s.captureRegOnce.Do(func() { s.captureReg = r })
	if s.captureReg != r {
		// Two registries split the host: the pauser would hold one while
		// captures run under the other, and the pause would not win.
		slog.Error("memory snapshot: the gRPC server already has a different capture registry; the partition pause will not see its captures")
	}
}

// CaptureRegistry is this host's memory snapshot capture registry, which the
// daemon shares with its partition pauser (lv.CaptureRegistry).
func (s *Server) CaptureRegistry() *lv.CaptureRegistry {
	s.captureRegOnce.Do(func() { s.captureReg = lv.NewCaptureRegistry() })
	return s.captureReg
}
