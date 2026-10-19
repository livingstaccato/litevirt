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

// never in a text for a target that may still matter: a removed host
// cannot be re-added while the VM's row is on it (re-review of 78580365c,
// I-3).
var noReadd = []string{"`lv host add`"}

// Re-review of 2e970654d, I-2, and of 78580365c, I-3/M-4/M-5: per open move,
// the advice of `lv host rm --dead` is what doctorAcceptSource does with it,
// settled before the removal, and the named command is run against the real
// doctor with the target fenced (proved off) but not removed.
func TestStrandedOn_FirmwareMoveAdvicePerCondition(t *testing.T) {
	returnable := []string{"lv doctor firmware-move os1 --accept-source --acknowledge-rollback", "src-host",
		"Settle it before removing dst-host", "It discards dst-host's copy, which may be newer", "bring dst-host back up"}
	settle := func(t *testing.T, r *fwlRig) {
		t.Helper()
		r.fenceTarget()
		_, err := r.doctor(actAcceptSource, withAck)
		r.resolved(err, "src-host", "stopped")
	}
	t.Run("cleanup_failed", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		m := cleaningMarker(t, r, run)
		raiseOn(t, r, condFwmigCleanupFailed, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r), append(returnable, condFwmigCleanupFailed), append(notLost, noReadd...))
		settle(t, r)
	})
	// M-5: a committed move whose cleanup has not stopped raises no
	// condition; the source's marker shows it.
	t.Run("committed_no_condition", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		cleaningMarker(t, r, run)
		requireText(t, deadHostDetail(t, r), append(returnable, "its marker on src-host"), append(notLost, noReadd...))
		settle(t, r)
	})
	t.Run("target_unreachable_after_commit", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		m := r.park(run, fwmig.PhaseTargetUnreachable, "Release was not answered")
		raiseOn(t, r, condFwmigTargetUnreachable, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r), returnable, append(notLost, noReadd...))
		settle(t, r)
	})
	t.Run("target_ran_after_commit", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		m := r.park(run, fwmig.PhaseTargetRan, "the target's guest ran")
		raiseOn(t, r, condFwmigTargetRan, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r), returnable, append(notLost, noReadd...))
		settle(t, r)
	})
	// M-4: the full commands; with the target proved off the source's older
	// state is returned.
	t.Run("nvram_unconfirmed", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseCommitted)
		m := r.park(run, fwmig.PhaseNvramUnconfirmed, "NVRAM unconfirmed")
		raiseOn(t, r, condFwmigNvramUnconfirmed, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r),
			[]string{"lv doctor firmware-move os1 --confirm-target-nvram --accept-nvram-hash=<sha256>",
				"lv doctor firmware-move os1 --push-source-nvram --acknowledge-rollback",
				"lv doctor firmware-move os1 --accept-source --acknowledge-rollback", "bring it back up"},
			append(notLost, noReadd...))
		settle(t, r)
	})
	// Its exit needs the target to answer: the text says to bring it back
	// up, never to remove it, and the doctor refuses without it.
	t.Run("source_paused", func(t *testing.T) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseMigrating)
		m := r.park(run, fwmig.PhaseSourcePaused, "both guests paused")
		if err := corrosion.UpdateVMHost(context.Background(), r.src.db, fwlVM, "dst-host", "running"); err != nil {
			t.Fatal(err)
		}
		raiseOn(t, r, condFwmigSourcePaused, m.Attempt, "src-host", "dst-host")
		requireText(t, deadHostDetail(t, r),
			[]string{"needs dst-host to answer", "bring dst-host back up rather than removing it", "lv doctor firmware-move os1 --accept-source"},
			append([]string{"--acknowledge-rollback"}, append(notLost, noReadd...)...))
		r.fenceTarget()
		r.peerC.mu.Lock()
		r.peerC.dialErr = func() error { return errUnreachableForTest }
		r.peerC.mu.Unlock()
		_, err := r.doctor(actAcceptSource)
		if err == nil || !strings.Contains(err.Error(), "needs dst-host to answer") {
			t.Fatalf("--accept-source with the target gone = %v, want refused: it needs dst-host to answer", err)
		}
	})
}

// Re-review of 2e970654d, I-1 and M-2/M-3, and of 78580365c, M-6: whenever a
// surviving copy cannot be ruled out, the text says so and names
// `lv doctor firmware-move <vm>`, never "lost" or `lv rm`. A resolved
// condition counts for nothing, and no marker anywhere is "lost".
//
// Mutations: drop the target check, accept a resolved condition, drop the
// raiser == source check, drop the attempt check, fall back to "none" on a
// read error, take an unreadable remote source as returnable, ignore a host
// that did not answer the marker sweep — each red.
func TestStrandedOn_FirmwareMoveUncheckedNeverSaysLost(t *testing.T) {
	check := []string{"could not be confirmed", "lv doctor firmware-move os1`"}
	setup := func(t *testing.T) (*fwlRig, fwmig.Marker) {
		r := newFwdRig(t, fwlOpts{})
		run := r.crashAt(fwmig.PhaseReleased)
		return r, cleaningMarker(t, r, run)
	}
	unmark := func(t *testing.T, r *fwlRig) {
		if err := r.src.fwRecords().RemoveMarker(fwlVM); err != nil {
			t.Fatal(err)
		}
	}
	unreachable := func(r *fwlRig) {
		r.peerC.mu.Lock()
		r.peerC.dialErr = func() error { return errUnreachableForTest }
		r.peerC.mu.Unlock()
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
		// M-6: the source is another host, and it does not answer.
		"remote_source_unreadable": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			raiseOn(t, r, condFwmigCleanupFailed, m.Attempt, "peer-host", "dst-host")
			unreachable(r)
		},
		// No condition and no marker here, and a third host that does not
		// answer the sweep.
		"sweep_host_silent": func(t *testing.T, r *fwlRig, m fwmig.Marker) {
			unmark(t, r)
			if err := corrosion.InsertHost(context.Background(), r.src.db, corrosion.HostRecord{Name: "third-host", Address: "10.0.0.3", State: "active"}); err != nil {
				t.Fatal(err)
			}
			unreachable(r)
		},
	} {
		t.Run(name, func(t *testing.T) {
			r, m := setup(t)
			tc(t, r, m)
			requireText(t, deadHostDetail(t, r), check, append([]string{"--accept-source"}, append(notLost, noReadd...)...))
		})
	}
	t.Run("resolved_condition_no_marker", func(t *testing.T) {
		r, m := setup(t)
		raiseOn(t, r, condFwmigCleanupFailed, m.Attempt, "src-host", "dst-host")
		if err := r.src.resolveFirmwareMigrationCondition(context.Background(), condFwmigCleanupFailed, fwlVM); err != nil {
			t.Fatal(err)
		}
		unmark(t, r)
		requireText(t, deadHostDetail(t, r), []string{"is lost"}, []string{"--accept-source"})
	})
	t.Run("no_move", func(t *testing.T) {
		r, _ := setup(t)
		unmark(t, r)
		requireText(t, deadHostDetail(t, r), []string{"is lost"}, []string{"--accept-source", "could not be confirmed"})
	})
}

// Re-review of 78580365c, I-3 (design a): `lv host rm --dead` refuses while a
// firmware VM recorded on the host has an open move to it, naming the
// settling step and --force; with no open move it does not.
//
// Mutation: return nil from deadRemovalFirmwareRefusal — red.
func TestDeadRemovalFirmwareRefusal(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseReleased)
	cleaningMarker(t, r, run)
	err := r.src.deadRemovalFirmwareRefusal(context.Background(), "dst-host")
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("refusal = %v, want FailedPrecondition", err)
	}
	requireText(t, err.Error(), []string{"lv doctor firmware-move os1 --accept-source --acknowledge-rollback",
		"lv host rm --dead --force dst-host"}, noReadd)
	r.fenceTarget()
	_, derr := r.doctor(actAcceptSource, withAck)
	r.resolved(derr, "src-host", "stopped")
	if err := r.src.deadRemovalFirmwareRefusal(context.Background(), "dst-host"); err != nil {
		t.Fatalf("after the doctor settled it: %v, want no refusal", err)
	}
}

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

// Re-review of 78580365c, I-3 (design a): a move parked nvram_unconfirmed
// whose target is proved off can be settled from the source: --accept-source
// --acknowledge-rollback returns the VM from the source's older state, so a
// dead target never strands it. While the target is not proved off it is
// refused, naming the full commands.
//
// Mutation: refuse nvram_unconfirmed whatever the target (the round-2
// doctor) — the proved-off case is refused, red.
func TestDoctorAcceptSource_NvramUnconfirmedTargetProvedOff(t *testing.T) {
	r := newFwdRig(t, fwlOpts{})
	run := r.crashAt(fwmig.PhaseCommitted)
	r.park(run, fwmig.PhaseNvramUnconfirmed, "NVRAM unconfirmed")
	r.dstFake.SetState(fwlVM, "running")
	before := r.snap()
	_, err := r.doctor(actAcceptSource, withAck)
	r.refused(err, "--confirm-target-nvram --accept-nvram-hash=<sha256>", before)
	if !strings.Contains(err.Error(), "--push-source-nvram --acknowledge-rollback") {
		t.Errorf("refusal %v does not name --push-source-nvram --acknowledge-rollback", err)
	}
	r.dstFake.SetState(fwlVM, "shutoff")
	r.fenceTarget()
	_, err = r.doctor(actAcceptSource)
	if err == nil || !strings.Contains(err.Error(), "--acknowledge-rollback") {
		t.Fatalf("without the acknowledgement = %v, want it asked for", err)
	}
	_, err = r.doctor(actAcceptSource, withAck)
	r.resolved(err, "src-host", "stopped")
	r.requireSourceIntact("after the return")
}

var errUnreachableForTest = status.Error(codes.Unavailable, "no route to host")
