package grpcapi

import "time"

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
