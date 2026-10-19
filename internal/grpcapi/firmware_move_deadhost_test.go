package grpcapi

import (
	"context"
	"os"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
)

// deadHostDetail is what `lv host rm --dead dst-host` says about os1, read
// on the move's source.
func deadHostDetail(t *testing.T, r *fwlRig) string {
	t.Helper()
	out, err := r.src.strandedOn(context.Background(), "dst-host")
	if err != nil {
		t.Fatal(err)
	}
	for _, st := range out {
		if st.GetName() == fwlVM {
			return st.GetDetail()
		}
	}
	t.Fatalf("os1 is not listed on dst-host: %+v", out)
	return ""
}

// raiseOn raises code for os1's attempt from the source, naming the target.
func raiseOn(t *testing.T, r *fwlRig, code, attempt, source, target string) {
	t.Helper()
	o := r.src.hostName
	r.src.hostName = source
	defer func() { r.src.hostName = o }()
	if err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{
		Code: code, VM: fwlVM, Attempt: attempt, Source: source, Target: target, Detail: "test",
	}); err != nil {
		t.Fatal(err)
	}
}

func requireText(t *testing.T, text string, want, notWant []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("%q\nlacks %q", text, w)
		}
	}
	for _, w := range notWant {
		if strings.Contains(text, w) {
			t.Errorf("%q\nnames %q", text, w)
		}
	}
}

// never in a text that cannot rule out a surviving copy.
var notLost = []string{"is lost", "`lv rm"}

// Re-review of 2e970654d, I-2: per condition, the advice of `lv host rm
// --dead` is what doctorAcceptSource does with that move, and the named
// command is run against it: the return works where it is offered, and is
// refused where the text says it is.
func TestStrandedOn_FirmwareMoveAdvicePerCondition(t *testing.T) {
	returnable := []string{"lv doctor firmware-move os1 --accept-source --acknowledge-rollback", "src-host",
		"discards dst-host's copy", "`lv host add`"}

	t.Run("cleanup_failed", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		m := cleaningMarker(t, r, run)
		raiseOn(t, r, condFwmigCleanupFailed, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r), append(returnable, condFwmigCleanupFailed), notLost)
		removeTarget(t, r)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
	})
	t.Run("target_unreachable_after_commit", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		m := r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		raiseOn(t, r, condFwmigTargetUnreachable, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r), returnable, notLost)
		removeTarget(t, r)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
	})
	t.Run("target_ran_after_commit", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		m := r.park(run, fwmig.PhaseTargetRan, "the target's guest ran")
		raiseOn(t, r, condFwmigTargetRan, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r), returnable, notLost)
		removeTarget(t, r)
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
	})
	// The guest ran on the target after the release: --accept-source is
	// refused; the way out needs the target back.
	t.Run("nvram_unconfirmed", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		m := r.park(run, fwmig.PhaseNvramUnconfirmed, "NVRAM unconfirmed")
		raiseOn(t, r, condFwmigNvramUnconfirmed, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r),
			[]string{"--confirm-target-nvram", "--push-source-nvram", "`lv host add`", "refused"},
			append([]string{"--accept-source --acknowledge-rollback` returns"}, notLost...))
		removeTarget(t, r)
		before := r.snap()
		_, err := r.doctor(actAcceptSource, withAck)
		r.refused(err, "--confirm-target-nvram", before)
	})
	// Its exit needs the target to answer, which a removed host cannot.
	t.Run("source_paused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		m := r.park(run, fwmig.PhaseSourcePaused, "both guests paused")
		if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "dst-host", "running"); err != nil {
			t.Fatal(err)
		}
		raiseOn(t, r, condFwmigSourcePaused, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r),
			[]string{"needs dst-host to answer", "`lv host add`", "lv doctor firmware-move os1 --accept-source"},
			append([]string{"--acknowledge-rollback` returns"}, notLost...))
		removeTarget(t, r)
		r.peerC.mu.Lock()
		r.peerC.dialErr = func() error { return errUnreachableForTest }
		r.peerC.mu.Unlock()
		_, err := r.doctor(actAcceptSource)
		if err == nil || !strings.Contains(err.Error(), "needs dst-host to answer") {
			t.Fatalf("--accept-source with the target gone = %v, want refused: it needs dst-host to answer", err)
		}
	})
}

// Re-review of 2e970654d, I-1 and M-2/M-3: whenever a surviving copy cannot be
// ruled out — the conditions cannot be read or parsed, a condition the
// advice does not cover is open, or an open condition does not match this
// move (another target, raised by a host other than its source, another
// attempt) — the text says so and names `lv doctor firmware-move <vm>`,
// never "lost" or `lv rm`. A resolved condition counts for nothing.
//
// Mutations: drop the target check, accept a resolved condition, drop the
// raiser == source check, drop the attempt check — each red; fall back to the
// lost text on a read error — red.
func TestStrandedOn_FirmwareMoveUncheckedNeverSaysLost(t *testing.T) {
	check := []string{"could not be confirmed", "lv doctor firmware-move os1`"}
	setup := func(t *testing.T) (*fwlRig, fwmig.Marker) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		return r, cleaningMarker(t, r, run)
	}
	for name, tc := range map[string]func(t *testing.T, r *fwlRig, m fwmig.Marker){
		"read_error": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			if _, err := r.src.db.DB().Exec(`DROP TABLE health_conditions`); err != nil {
				t.Fatal(err)
			}
		},
		"bad_evidence": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			raiseOn(t, r, condFwmigCleanupFailed, m.Attempt, "src-host", "dst-host")
			if _, err := r.src.db.DB().Exec(`UPDATE health_conditions SET evidence = 'not json' WHERE code = ?`, condFwmigCleanupFailed); err != nil {
				t.Fatal(err)
			}
		},
		"uncovered_code": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			raiseOn(t, r, condFwmigSourceStateSuspect, m.Attempt, "src-host", "dst-host")
		},
		"another_target": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			raiseOn(t, r, condFwmigCleanupFailed, m.Attempt, "src-host", "other-host")
		},
		"raised_by_another_host": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			o := r.src.hostName
			r.src.hostName = "third-host"
			err := r.src.raiseFirmwareMigrationCondition(context.Background(), fwmigCondition{
				Code: condFwmigCleanupFailed, VM: fwlVM, Attempt: m.Attempt, Source: "src-host", Target: "dst-host", Detail: "test"})
			r.src.hostName = o
			if err != nil {
				t.Fatal(err)
			}
		},
		"another_attempt": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			raiseOn(t, r, condFwmigCleanupFailed, "6f1c2d3e-4b5a-4c6d-8e7f-001122334477", "src-host", "dst-host")
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, m := setup(t)
			tc(t, r, m)
			requireText(t, deadHostDetail(t, r), check, append([]string{"--accept-source"}, notLost...))
		})
	}
	t.Run("resolved_condition", func(t *testing.T) {
		r, m := setup(t)
		raiseOn(t, r, condFwmigCleanupFailed, m.Attempt, "src-host", "dst-host")
		if err := r.src.resolveFirmwareMigrationCondition(context.Background(), condFwmigCleanupFailed, fwlVM); err != nil {
			t.Fatal(err)
		}
		requireText(t, deadHostDetail(t, r), []string{"is lost"}, []string{"--accept-source"})
	})
	t.Run("no_condition", func(t *testing.T) {
		r, _ := setup(t)
		requireText(t, deadHostDetail(t, r), []string{"is lost"}, []string{"--accept-source", "could not be confirmed"})
	})
}

var errUnreachableForTest = status.Error(codes.Unavailable, "no route to host")

// Re-review of 2e970654d, M-2: when the source's hashes cannot be read, the
// record says so, never "as the cutover left it".
//
// Mutation: answer "as the cutover left it" on a read error — red.
func TestSourceStateSinceCutover_UnreadableHashes(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	m := cleaningMarker(t, r, run)
	if err := os.Remove(r.srcStore.NvramPath(fwlVM)); err != nil {
		t.Fatal(err)
	}
	got := r.src.sourceStateSinceCutover(m)
	if !strings.Contains(got, "cannot be read") || strings.Contains(got, "as the cutover left it") {
		t.Errorf("sourceStateSinceCutover = %q", got)
	}
}
