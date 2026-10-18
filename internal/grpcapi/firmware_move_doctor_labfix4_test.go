package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// cleanupAction is the action text of os1's open cleanup_failed condition.
func cleanupAction(t *testing.T, r *fwlRig) string {
	t.Helper()
	c, found, err := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigCleanupFailed, "vm", fwlVM)
	if err != nil || !found || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("cleanup_failed: %+v found=%v err=%v, want it open", c, found, err)
	}
	var ev struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal([]byte(c.Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	return ev.Action
}

// requireCleanupHeld: the retry left the source's domain defined, its state
// unwiped, the marker cleaning and cleanup_failed open.
func requireCleanupHeld(t *testing.T, r *fwlRig, why string) {
	t.Helper()
	if st, ok := r.srcFake.RawState(fwlVM); !ok || st == libvirtfake.StateRunning {
		t.Fatalf("%s: source domain %s (defined %v), want defined and shut off", why, st, ok)
	}
	r.requireSourceIntact(why)
	requireMarker(t, r, fwmig.PhaseCleaning, "")
	requireFwmigCondition(t, r.src, condFwmigCleanupFailed)
}

// targetOffline records dst-host offline (lost, not fenced) under strategy.
func targetOffline(t *testing.T, r *fwlRig, strategy string) {
	t.Helper()
	if _, err := r.src.ConfigureHost(adminCtx(), &pb.ConfigureHostRequest{Name: "dst-host", FenceStrategy: strategy}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateHostState(context.Background(), r.src.db, "dst-host", "offline"); err != nil {
		t.Fatal(err)
	}
}

// Re-review 3, I-1: a stopped cleanup whose target is offline (lost, not
// yet fenced) holds before the undefine, under either fence strategy that
// leaves a host offline; the exits stay open: --accept-target at once,
// --accept-source once the target is proved off, and the action text says
// which needs what (m-1).
//
// Mutations: hold only on fenced/removed/proved off (the round-3 rule) — the
// cleanup undefines and wipes, red; the action text without the
// fence-confirm step — red.
func TestFwmigCleanup_HoldsWhileTheTargetIsOffline(t *testing.T) {
	for _, strategy := range []string{"best-effort", "manual"} {
		t.Run(strategy+"/accept_source_after_fence_confirm", func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			run := r.crashAt(fwmig.PhaseReleased)
			cleaningMarker(t, r, run)
			targetOffline(t, r, strategy)
			r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
			requireCleanupHeld(t, r, "after the cleanup retry")
			action := cleanupAction(t, r)
			for _, want := range []string{"--accept-target", "lv host fence-confirm dst-host", "--accept-source --acknowledge-rollback"} {
				if !strings.Contains(action, want) {
					t.Errorf("action %q does not name %q", action, want)
				}
			}
			if i, j := strings.Index(action, "lv host fence-confirm dst-host"), strings.Index(action, "--accept-source"); i < 0 || j < i {
				t.Errorf("action %q: fence-confirm must come before --accept-source", action)
			}
			// A second pass holds as well (the startup and the minute retry).
			r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
			requireCleanupHeld(t, r, "after a second retry")
			before := r.snap()
			_, err := r.doctor(actAcceptSource, withAck)
			r.refused(err, "fence-confirm", before)
			r.fenceTarget()
			_, err = r.doctor(actAcceptSource, withAck)
			r.resolved(err, "src-host", "stopped")
			r.requireSourceIntact("after --accept-source")
		})
		t.Run(strategy+"/accept_target", func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			run := r.crashAt(fwmig.PhaseReleased)
			cleaningMarker(t, r, run)
			targetOffline(t, r, strategy)
			r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
			requireCleanupHeld(t, r, "after the cleanup retry")
			r.peerC.mu.Lock()
			r.peerC.dialErr = func() error { return status.Error(codes.Unavailable, "no route to host") }
			r.peerC.mu.Unlock()
			_, err := r.doctor(actAcceptTarget)
			r.resolved(err, "dst-host", "running")
			ents, _ := os.ReadDir(filepath.Join(r.src.dataDir, fwmig.QuarantineDir))
			if len(ents) != 1 {
				t.Errorf("source quarantine %v, want the source's state", ents)
			}
		})
	}
}

// Re-review 3, I-1: an active target that does not answer the records call
// holds the cleanup too; once it answers, the cleanup goes on by itself.
//
// Mutation: take `active` alone as alive — the cleanup undefines and wipes
// while the target does not answer, red.
func TestFwmigCleanup_HoldsWhileTheTargetDoesNotAnswer(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	cleaningMarker(t, r, run)
	r.peerC.mu.Lock()
	r.peerC.dialErr = func() error { return status.Error(codes.Unavailable, "connection refused") }
	r.peerC.mu.Unlock()
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	requireCleanupHeld(t, r, "while the target does not answer")
	if a := cleanupAction(t, r); !strings.Contains(a, "lv host fence-confirm dst-host") {
		t.Errorf("action %q does not name the fence-confirm", a)
	}

	r.peerC.mu.Lock()
	r.peerC.dialErr = nil
	r.peerC.mu.Unlock()
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	if m, ok := r.marker(); ok {
		t.Fatalf("marker left once the target answers: %s: %s", m.Phase, m.Detail)
	}
	if st, ok := r.srcFake.RawState(fwlVM); ok {
		t.Errorf("source domain %s still defined after the cleanup", st)
	}
	requireNoFwmigCondition(t, r.src, condFwmigCleanupFailed)
}

// Re-review 3, m-1: a target proved off holds the cleanup with both exits
// open at once, and the text says so without a fence-confirm step.
func TestFwmigCleanup_ProvedOffTargetActionText(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	cleaningMarker(t, r, run)
	r.fenceTarget()
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	requireCleanupHeld(t, r, "after the cleanup retry")
	a := cleanupAction(t, r)
	if strings.Contains(a, "fence-confirm") {
		t.Errorf("action %q asks for a fence-confirm of a target already proved off", a)
	}
	for _, want := range []string{"--accept-target", "--accept-source --acknowledge-rollback"} {
		if !strings.Contains(a, want) {
			t.Errorf("action %q does not name %q", a, want)
		}
	}
}
