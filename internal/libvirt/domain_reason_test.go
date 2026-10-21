package libvirt

import (
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

func TestCoarseDomainState(t *testing.T) {
	cases := []struct {
		state golibvirt.DomainState
		want  string
	}{
		{golibvirt.DomainRunning, "running"},
		{golibvirt.DomainBlocked, "running"},
		{golibvirt.DomainShutdown, "stopping"},
		{golibvirt.DomainPaused, "stopped"},
		{golibvirt.DomainShutoff, "stopped"},
		{golibvirt.DomainPmsuspended, "stopped"},
		{golibvirt.DomainCrashed, "error"},
		{golibvirt.DomainNostate, "unknown"},
	}
	for _, tc := range cases {
		if got := coarseDomainState(tc.state); got != tc.want {
			t.Errorf("coarseDomainState(%v) = %q; want %q", tc.state, got, tc.want)
		}
	}
}

func TestNormalizeDomainReason(t *testing.T) {
	cases := []struct {
		name   string
		state  golibvirt.DomainState
		reason int32
		want   string
	}{
		// Shutoff reasons — the crucial crash-vs-clean distinction.
		{"shutoff-shutdown", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffShutdown), "guest-shutdown"},
		{"shutoff-destroyed", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffDestroyed), "destroyed"},
		{"shutoff-crashed", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffCrashed), "crashed"},
		{"shutoff-migrated", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffMigrated), "migrated"},
		{"shutoff-saved", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffSaved), "saved"},
		{"shutoff-failed", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffFailed), "failed"},
		{"shutoff-from-snapshot", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffFromSnapshot), "from-snapshot"},
		{"shutoff-daemon", golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffDaemon), "daemon"},
		{"shutoff-unknown-reason", golibvirt.DomainShutoff, 999, "unknown"},

		// Non-shutoff states ignore the reason int.
		{"running", golibvirt.DomainRunning, 0, "running"},
		{"blocked", golibvirt.DomainBlocked, 0, "running"},
		{"paused", golibvirt.DomainPaused, 0, "paused"},
		{"pmsuspended", golibvirt.DomainPmsuspended, 0, "pmsuspended"},
		{"shutdown", golibvirt.DomainShutdown, 0, "shutting-down"},
		{"crashed", golibvirt.DomainCrashed, 0, "crashed"},
		{"nostate", golibvirt.DomainNostate, 0, "unknown"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeDomainReason(tc.state, tc.reason); got != tc.want {
				t.Errorf("normalizeDomainReason(%v, %d) = %q; want %q", tc.state, tc.reason, got, tc.want)
			}
		})
	}
}

// A guest QEMU paused because a disk write failed (ENOSPC on a full pool,
// EIO) is still reported with Reason "paused", which every caller reads as
// "active, not executing" — but carries why in PausedReason, so an I/O
// error pause can be told from an operator's. Other states carry none.
func TestNormalizePausedReason(t *testing.T) {
	cases := []struct {
		state  golibvirt.DomainState
		reason int32
		want   string
	}{
		{golibvirt.DomainPaused, int32(golibvirt.DomainPausedIoerror), PausedReasonIOError},
		{golibvirt.DomainPaused, int32(golibvirt.DomainPausedUser), "user"},
		{golibvirt.DomainPaused, int32(golibvirt.DomainPausedMigration), "migration"},
		{golibvirt.DomainPaused, int32(golibvirt.DomainPausedUnknown), "unknown"},
		{golibvirt.DomainPaused, 999, "unknown"},
		{golibvirt.DomainRunning, int32(golibvirt.DomainPausedIoerror), ""},
		{golibvirt.DomainShutoff, int32(golibvirt.DomainShutoffCrashed), ""},
	}
	for _, tc := range cases {
		if got := normalizePausedReason(tc.state, tc.reason); got != tc.want {
			t.Errorf("normalizePausedReason(%v, %d) = %q; want %q", tc.state, tc.reason, got, tc.want)
		}
		if tc.state == golibvirt.DomainPaused {
			if got := normalizeDomainReason(tc.state, tc.reason); got != "paused" {
				t.Errorf("normalizeDomainReason(paused, %d) = %q; want paused whatever the pause reason", tc.reason, got)
			}
		}
	}
}
