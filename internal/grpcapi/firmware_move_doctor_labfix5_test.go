package grpcapi

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// cleanupCondition is os1's open cleanup_failed condition: its severity and
// action.
func cleanupCondition(t *testing.T, r *fwlRig) (severity, action string) {
	t.Helper()
	c, found, err := corrosion.GetHealthCondition(context.Background(), r.src.db, firmwareMigrationEvaluator, condFwmigCleanupFailed, "vm", fwlVM)
	if err != nil || !found || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("cleanup_failed: %+v found=%v err=%v, want it open", c, found, err)
	}
	return c.Severity, cleanupAction(t, r)
}

// Round-4 re-review n-1: the target answering is not enough; its answer must
// show the VM's copy there (a domain of the VM's uuid, and no read error).
// An answer with an error, no domain, or another VM's domain holds, the
// source's copy defined and whole.
//
// Mutation: count any answer as alive (the round-4 rule) — every case
// undefines and wipes, red.
func TestFwmigCleanup_HoldsUnlessTheTargetShowsTheCopy(t *testing.T) {
	cases := map[string]func(*fwlRig){
		"read_error": func(r *fwlRig) {
			r.peerC.readAnswer = func(resp *pb.FirmwareMoveDoctorResponse) *pb.FirmwareMoveDoctorResponse {
				resp = proto.Clone(resp).(*pb.FirmwareMoveDoctorResponse)
				resp.Hosts[0].Error = "domain: libvirt is not running"
				return resp
			}
		},
		"no_domain": func(r *fwlRig) {
			if err := r.dstFake.UndefineDomainPreservingState(fwlVM); err != nil {
				r.t.Fatal(err)
			}
		},
		"another_uuid": func(r *fwlRig) {
			r.peerC.readAnswer = func(resp *pb.FirmwareMoveDoctorResponse) *pb.FirmwareMoveDoctorResponse {
				resp = proto.Clone(resp).(*pb.FirmwareMoveDoctorResponse)
				resp.Hosts[0].Domain.Uuid = "00000000-0000-4000-8000-00000000beef"
				return resp
			}
		},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			run := r.crashAt(fwmig.PhaseReleased)
			cleaningMarker(t, r, run)
			if name == "no_domain" {
				r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
			}
			r.peerC.mu.Lock()
			set(r)
			r.peerC.mu.Unlock()
			r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
			requireCleanupHeld(t, r, "after the cleanup retry")
			if _, a := cleanupCondition(t, r); !strings.Contains(a, "--accept-target") {
				t.Errorf("action %q does not name --accept-target", a)
			}
		})
	}
	// The copy shut off on the target is still its copy: the cleanup goes on.
	t.Run("shut_off_copy_goes_on", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		cleaningMarker(t, r, run)
		r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
		r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
		if m, ok := r.marker(); ok {
			t.Fatalf("marker left: %s: %s", m.Phase, m.Detail)
		}
	})
}

// Round-4 re-review m-2: a target in a planned state (draining,
// maintenance) or removed without a proof holds the cleanup at warning, not
// critical, with text naming the state and --accept-target; a lost one
// (offline) stays critical.
//
// Mutation: raise every hold at the code's default (critical) — red.
func TestFwmigCleanup_HoldSeverityByTargetState(t *testing.T) {
	for _, tc := range []struct {
		state, want, says string
	}{
		{"draining", corrosion.SeverityWarning, "draining"},
		{"maintenance", corrosion.SeverityWarning, "maintenance"},
		{"removed", corrosion.SeverityWarning, "removed"},
		{"offline", corrosion.SeverityCritical, "offline"},
	} {
		t.Run(tc.state, func(t *testing.T) {
			r := newFwdRig(t, fwlOpts{})
			run := r.crashAt(fwmig.PhaseReleased)
			cleaningMarker(t, r, run)
			if err := corrosion.UpdateHostState(context.Background(), r.src.db, "dst-host", tc.state); err != nil {
				t.Fatal(err)
			}
			r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
			requireCleanupHeld(t, r, "after the cleanup retry")
			sev, a := cleanupCondition(t, r)
			if sev != tc.want {
				t.Errorf("severity %s, want %s", sev, tc.want)
			}
			for _, w := range []string{tc.says, "--accept-target"} {
				if !strings.Contains(a, w) {
					t.Errorf("action %q does not name %q", a, w)
				}
			}
		})
	}
}

// Round-4 re-review m-1: an orphaned stage's seed is kept while a hold of
// the VM is on this host at removal time: an incoming copy may reuse it
// without rewriting it.
//
// Mutation: drop the hold re-check — the seed goes, red.
func TestReconciler_OrphanedStageKeepsASeedUnderAHold(t *testing.T) {
	ctx := context.Background()
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
	r.fenceTarget()
	if _, err := r.doctor(actAcceptSource, withAck); err != nil {
		t.Fatalf("accept-source: %v", err)
	}
	r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
	h, held := r.hold()
	_ = r.dst.fwRecords().RemoveHold(fwlVM)
	_ = r.dst.fwRecords().RemoveLeftover(fwlVM)
	iso := lv.CloudInitISOPath(r.dst.dataDir, fwlVM)
	r.write(iso, []byte("seed"))
	if err := cloudinit.StampSeed(iso, fwLiveUUID); err != nil {
		t.Fatal(err)
	}
	stage := stageLeftoverAndCrash(t, r)
	// The VM comes back: a new move's hold, reusing the old seed.
	if !held {
		h = fwmig.Hold{VM: fwlVM, Binding: run.marker.Binding, Source: "src-host", State: fwmig.HoldPrepared, Since: time.Now(), TPM: true, UEFI: true, NvramMaterialised: fwmig.NvramPending}
	}
	h.Attempt = "6f1c2d3e-4b5a-4c6d-8e7f-001122334455"
	if err := r.dst.fwRecords().PutHold(h); err != nil {
		t.Fatal(err)
	}
	rc := health.NewReconciler(r.dst.hostName, r.dst.dataDir, r.dst.db, r.dstFake)
	rc.SetFirmwareStore(r.dstStore)
	rc.ReconcileOnce(ctx)
	if _, err := os.Stat(stage); !os.IsNotExist(err) {
		t.Fatalf("fixture: the orphaned stage was not finished (%v)", err)
	}
	if _, err := os.Stat(iso); err != nil {
		t.Errorf("the seed an incoming copy holds was removed (%v)", err)
	}
}

// Round-5 re-review m-1: the VM moved on to a third host (its row names
// neither the source nor the target): the cleanup holds at warning, the
// text names the host it moved to and --accept-target as the exit, and
// never asks to power off or fence-confirm the healthy target. The exit
// works.
//
// Mutation: no moved-on kind (the round-5 lost hold) — critical, with the
// power-off text, red.
func TestFwmigCleanup_MovedOnToAThirdHostHoldsAtWarning(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	cleaningMarker(t, r, run)
	// B → C: the target's copy left with the VM.
	r.dstFake.SetState(fwlVM, libvirtfake.StateShutdown)
	if err := r.dstFake.UndefineDomainPreservingState(fwlVM); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "third-host", "running"); err != nil {
		t.Fatal(err)
	}
	r.src.RetryLiveFirmwareCleanupsOnce(context.Background())
	requireCleanupHeld(t, r, "after the cleanup retry")
	sev, a := cleanupCondition(t, r)
	if sev != corrosion.SeverityWarning {
		t.Errorf("severity %s, want warning", sev)
	}
	for _, w := range []string{"third-host", "--accept-target"} {
		if !strings.Contains(a, w) {
			t.Errorf("action %q does not name %q", a, w)
		}
	}
	for _, bad := range []string{"power", "fence-confirm", "--accept-source"} {
		if strings.Contains(a, bad) {
			t.Errorf("action %q names %q", a, bad)
		}
	}
	_, err := r.doctor(actAcceptTarget)
	r.resolved(err, "third-host", "running")
}
