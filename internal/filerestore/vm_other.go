//go:build !linux

package filerestore

import (
	"context"
	"fmt"
	"os"
)

// Launcher starts restore VMs; off Linux there are none.
type Launcher struct{}

// NewLauncher returns a launcher that is always unavailable off Linux.
func NewLauncher(Config) *Launcher { return &Launcher{} }

// Preflight always fails off Linux.
func (l *Launcher) Preflight() error {
	return fmt.Errorf("%w: a restore VM needs Linux with KVM", ErrUnavailable)
}

// Session is one running restore VM.
type Session struct{ *Client }

// Open always fails off Linux.
func (l *Launcher) Open(context.Context, BlockDevice, string, string) (*Session, error) {
	return nil, l.Preflight()
}

// Close does nothing off Linux.
func (s *Session) Close() {}

// SweepStale does nothing off Linux.
func SweepStale(string, uint32, [2]uint64) int { return 0 }

// RunTrampoline is never used off Linux.
func RunTrampoline([]string) { os.Exit(2) }

// EnsureRestoreUser does nothing off Linux.
func EnsureRestoreUser() error { return nil }
